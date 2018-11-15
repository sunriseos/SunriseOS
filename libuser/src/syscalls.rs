//! Syscall Wrappers

use core::slice;
use types::*;

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

unsafe fn syscall(nr: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) -> Result<(usize, usize, usize, usize), usize> {
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
        Err(registers.eax)
    }
}

pub fn exit_process() -> ! {
    unsafe {
        match syscall(0x7, 0, 0, 0, 0, 0, 0) {
            Ok(_) => (),
            Err(err) => { let _ = output_debug_string(&format!("Failed to exit: {}", err)); },
        }
        loop {}
    }
}

pub fn wait_synchronization(handles: &[HandleRef], timeout_ns: Option<usize>) -> Result<usize, usize> {
    unsafe {
        let (handleidx, ..) = syscall(0x18, handles.as_ptr() as _, handles.len(), timeout_ns.unwrap_or(usize::max_value()), 0, 0, 0)?;
        Ok(handleidx)
    }
}

pub fn connect_to_named_port(s: &str) -> Result<ClientSession, usize> {
    unsafe {
        let (out_handle, ..) = syscall(0x1F, s.as_ptr() as _, 0, 0, 0, 0, 0)?;
        Ok(ClientSession(Handle::new(out_handle as _)))
    }
}

pub fn send_sync_request_with_user_buffer(buf: &mut [u8], handle: &ClientSession) -> Result<(), usize> {
    unsafe {
        syscall(0x22, buf.as_ptr() as _, buf.len(), (handle.0).0.get() as _, 0, 0, 0)?;
        Ok(())
    }
}

pub fn output_debug_string(s: &str) -> Result<(), usize> {
    unsafe {
        syscall(0x27, s.as_ptr() as _, s.len(), 0, 0, 0, 0)?;
        Ok(())
    }
}

pub fn accept_session(port: &ServerPort) -> Result<ServerSession, usize> {
    unsafe {
        let (out_handle, ..) = syscall(0x41, (port.0).0.get() as _, 0, 0, 0, 0, 0)?;
        Ok(ServerSession(Handle::new(out_handle as _)))
    }
}

pub fn create_interrupt_event(irqnum: usize, flag: u32) -> Result<ReadableEvent, usize> {
    unsafe {
        let (out_handle, ..) = syscall(0x53, irqnum, flag as usize, 0, 0, 0, 0)?;
        Ok(ReadableEvent(Handle::new(out_handle as _)))
    }
}

pub fn create_port(max_sessions: u32, is_light: bool, name_ptr: &str) -> Result<(ClientPort, ServerPort), usize> {
    unsafe {
        let (out_client_handle, out_server_handle, ..) = syscall(0x70, max_sessions as _, is_light as _, name_ptr.as_ptr() as _, 0, 0, 0)?;
        Ok((ClientPort(Handle::new(out_client_handle as _)), ServerPort(Handle::new(out_server_handle as _))))
    }
}

pub fn manage_named_port(name: &str, max_handles: u32) -> Result<ServerPort, usize> {
    unsafe {
        let (out_handle, ..) = syscall(0x71, name.as_ptr() as _, max_handles as _, 0, 0, 0, 0)?;
        Ok(ServerPort(Handle::new(out_handle as _)))
    }
}

pub fn connect_to_port(port: &ClientPort) -> Result<ClientSession, usize> {
    unsafe {
        let (out_handle, ..) = syscall(0x72, (port.0).0.get() as _, 0, 0, 0, 0, 0)?;
        Ok(ClientSession(Handle::new(out_handle as _)))
    }
}

pub fn map_framebuffer() -> Result<(&'static mut [u8], usize, usize, usize), usize> {
    unsafe {
        let (addr, width, height, bpp) = syscall(0x80, 0, 0, 0, 0, 0, 0)?;
        output_debug_string(&format!("{} {} {} {}", addr, width, height, bpp));
        let framebuffer_size = bpp * width * height / 8;
        Ok((slice::from_raw_parts_mut(addr as *mut u8, framebuffer_size), width, height, bpp))
    }
}

pub fn reply_and_receive_with_user_buffer(buf: &mut [u8], handles: &[HandleRef], replytarget: Option<HandleRef>) -> Result<usize, usize>{
    unsafe {
        let (idx, ..) = syscall(0x44, buf.as_ptr() as _, buf.len(), handles.as_ptr() as _, handles.len(), match replytarget {
            Some(s) => s.inner.get() as _,
            None => 0
        }, 0)?;
        Ok(idx)
    }
}
