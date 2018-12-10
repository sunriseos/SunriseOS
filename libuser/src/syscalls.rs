//! Syscall Wrappers

use core::slice;
use types::*;
use alloc::prelude::*;
use core::fmt::Write;
use kfs_libkern::nr;
pub use kfs_libkern::{MemoryInfo, MemoryPermissions};
use error::KernelError;

#[cfg(target_arch = "x86")]
global_asm!("
.intel_syntax noprefix
.global syscall_inner
syscall_inner:
    push ebp
    mov  ebp, esp

    push ebx
    push esi
    push edi

    // Eax contains Register struct
    mov eax, [esp + 0x14]

    mov ebx, [eax + 0x04]
    mov ecx, [eax + 0x08]
    mov edx, [eax + 0x0C]
    mov esi, [eax + 0x10]
    mov edi, [eax + 0x14]
    mov ebp, [eax + 0x18]
    mov eax, [eax + 0x00]

    int 0x80

    push eax
    mov eax, [esp + 0x18]

    mov [eax + 0x04], ebx
    mov [eax + 0x08], ecx
    mov [eax + 0x0C], edx
    mov [eax + 0x10], esi
    mov [eax + 0x14], edi
    mov [eax + 0x18], ebp
    pop ebx
    mov [eax + 0x00], ebx

    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
");

#[repr(C)]
struct Registers {
    eax: usize,
    ebx: usize,
    ecx: usize,
    edx: usize,
    esi: usize,
    edi: usize,
    ebp: usize,
}

extern {
    fn syscall_inner(registers: &mut Registers);
}

unsafe fn syscall(nr: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) -> Result<(usize, usize, usize, usize), KernelError> {
    let mut registers = Registers {
        eax: nr,
        ebx: arg1,
        ecx: arg2,
        edx: arg3,
        esi: arg4,
        edi: arg5,
        ebp: arg6
    };

    syscall_inner(&mut registers);

    if registers.eax == 0 {
        Ok((registers.ebx, registers.ecx, registers.edx, registers.esi))
    } else {
        Err(KernelError::from_syscall_ret(registers.eax as u32))
    }
}

pub fn query_memory(addr: usize) -> Result<(MemoryInfo, usize), KernelError> {
    let mut meminfo = MemoryInfo::default();
    let (pageinfo, ..) = unsafe {
        syscall(nr::QueryMemory, &mut meminfo as *mut _ as usize, 0, addr, 0, 0, 0)?
    };
    Ok((meminfo, pageinfo))
}

pub fn exit_process() -> ! {
    unsafe {
        match syscall(nr::ExitProcess, 0, 0, 0, 0, 0, 0) {
            Ok(_) => (),
            Err(err) => { let _ = output_debug_string(&format!("Failed to exit: {}", err)); },
        }
        loop {}
    }
}

/// Creates a thread in the current process.
pub fn create_thread(ip: fn() -> !, _context: usize, sp: *const u8, _priority: u32, _processor_id: u32) -> Result<Thread, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::CreateThread, ip as usize, _context, sp as _, _priority as _, _processor_id as _, 0)?;
        Ok(Thread(Handle::new(out_handle as _)))
    }
}

/// Starts the thread for the provided handle.
pub fn start_thread(thread_handle: &Thread) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::StartThread, (thread_handle.0).0.get() as usize, 0, 0, 0, 0, 0)?;
        Ok(())
    }
}

/// Exits the current thread.
#[allow(unused_must_use)]
pub fn exit_thread() -> ! {
    unsafe {
        syscall(nr::ExitThread, 0, 0, 0, 0, 0, 0);
    }
    unreachable!("svcExitThread returned, WTF ???")
}

/// Sleeps for a specified amount of time, or yield thread.
pub fn sleep_thread(nanos: usize) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::SleepThread, nanos, 0, 0, 0, 0, 0)?;
        Ok(())
    }
}

pub fn create_shared_memory(size: usize, myperm: MemoryPermissions, otherperm: MemoryPermissions) -> Result<SharedMemory, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::CreateSharedMemory, size, myperm.bits() as _, otherperm.bits() as _, 0, 0, 0)?;
        Ok(SharedMemory(Handle::new(out_handle as _)))
    }
}

pub fn map_shared_memory(handle: &SharedMemory, addr: usize, size: usize, perm: MemoryPermissions) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::MapSharedMemory, (handle.0).0.get() as _, addr, size, perm.bits() as _, 0, 0)?;
        Ok(())
    }
}

pub fn unmap_shared_memory(handle: &SharedMemory, addr: usize, size: usize) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::UnmapSharedMemory, (handle.0).0.get() as _, addr, size, 0, 0, 0)?;
        Ok(())
    }
}

// Not totally public because it's not safe to use directly
pub(crate) fn close_handle(handle: u32) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::CloseHandle, handle as _, 0, 0, 0, 0, 0)?;
        Ok(())
    }
}

pub fn wait_synchronization(handles: &[HandleRef], timeout_ns: Option<usize>) -> Result<usize, KernelError> {
    unsafe {
        let (handleidx, ..) = syscall(nr::WaitSynchronization, handles.as_ptr() as _, handles.len(), timeout_ns.unwrap_or(usize::max_value()), 0, 0, 0)?;
        Ok(handleidx)
    }
}

pub fn connect_to_named_port(s: &str) -> Result<ClientSession, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::ConnectToNamedPort, s.as_ptr() as _, 0, 0, 0, 0, 0)?;
        Ok(ClientSession(Handle::new(out_handle as _)))
    }
}

pub fn send_sync_request_with_user_buffer(buf: &mut [u8], handle: &ClientSession) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::SendSyncRequestWithUserBuffer, buf.as_ptr() as _, buf.len(), (handle.0).0.get() as _, 0, 0, 0)?;
        Ok(())
    }
}

pub fn output_debug_string(s: &str) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::OutputDebugString, s.as_ptr() as _, s.len(), 0, 0, 0, 0)?;
        Ok(())
    }
}

pub fn create_session(is_light: bool, unk: usize) -> Result<(ServerSession, ClientSession), KernelError> {
    unsafe {
        let (serverhandle, clienthandle, ..) = syscall(nr::CreateSession, is_light as _, unk, 0, 0, 0, 0)?;
        Ok((ServerSession(Handle::new(serverhandle as _)), ClientSession(Handle::new(clienthandle as _))))
    }
}

pub fn accept_session(port: &ServerPort) -> Result<ServerSession, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::AcceptSession, (port.0).0.get() as _, 0, 0, 0, 0, 0)?;
        Ok(ServerSession(Handle::new(out_handle as _)))
    }
}

pub fn reply_and_receive_with_user_buffer(buf: &mut [u8], handles: &[HandleRef], replytarget: Option<HandleRef>, timeout: Option<usize>) -> Result<usize, KernelError> {
    unsafe {
        let (idx, ..) = syscall(nr::ReplyAndReceiveWithUserBuffer, buf.as_ptr() as _, buf.len(), handles.as_ptr() as _, handles.len(), match replytarget {
            Some(s) => s.inner.get() as _,
            None => 0
        }, timeout.unwrap_or(usize::max_value()))?;
        Ok(idx)
    }
}

pub fn create_interrupt_event(irqnum: usize, flag: u32) -> Result<ReadableEvent, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::CreateInterruptEvent, irqnum, flag as usize, 0, 0, 0, 0)?;
        Ok(ReadableEvent(Handle::new(out_handle as _)))
    }
}

pub fn create_port(max_sessions: u32, is_light: bool, name_ptr: &str) -> Result<(ClientPort, ServerPort), KernelError> {
    unsafe {
        let (out_client_handle, out_server_handle, ..) = syscall(nr::CreatePort, max_sessions as _, is_light as _, name_ptr.as_ptr() as _, 0, 0, 0)?;
        Ok((ClientPort(Handle::new(out_client_handle as _)), ServerPort(Handle::new(out_server_handle as _))))
    }
}

pub fn manage_named_port(name: &str, max_handles: u32) -> Result<ServerPort, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::ManageNamedPort, name.as_ptr() as _, max_handles as _, 0, 0, 0, 0)?;
        Ok(ServerPort(Handle::new(out_handle as _)))
    }
}

pub fn connect_to_port(port: &ClientPort) -> Result<ClientSession, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::ConnectToPort, (port.0).0.get() as _, 0, 0, 0, 0, 0)?;
        Ok(ClientSession(Handle::new(out_handle as _)))
    }
}

pub fn map_framebuffer() -> Result<(&'static mut [u8], usize, usize, usize), KernelError> {
    unsafe {
        let (addr, width, height, bpp) = syscall(nr::MapFramebuffer, 0, 0, 0, 0, 0, 0)?;
        output_debug_string(&format!("{} {} {} {}", addr, width, height, bpp));
        let framebuffer_size = bpp * width * height / 8;
        Ok((slice::from_raw_parts_mut(addr as *mut u8, framebuffer_size), width, height, bpp))
    }
}
