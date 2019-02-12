//! Syscall Wrappers

use core::slice;
use crate::types::*;
pub use kfs_libkern::nr;
pub use kfs_libkern::{MemoryInfo, MemoryPermissions};
use crate::error::KernelError;

// Assembly blob can't get documented, but clippy requires it.
#[allow(clippy::missing_docs_in_private_items)]
mod syscall_inner {
    #[cfg(all(target_arch = "x86", not(test)))]
    global_asm!("
.intel_syntax noprefix
.global syscall_inner
// Call the syscall using arch-specific syscall ABI.
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
}

/// Register backup structure. The syscall_inner will pop the registers from this
/// structure before jumping into the kernel, and then update the structure with
/// the registers set by the syscall.
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
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

/// Generic syscall function.
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

/// Resize the heap of a process, just like a brk.
/// It can both expand, and shrink the heap.
///
/// If `new_size` == 0, the heap space is entirely de-allocated.
///
/// # Return
///
/// The address of the start of the heap.
///
/// # Error
///
/// * `new_size` must be PAGE_SIZE aligned.
///
/// # Unsafety
///
/// This function can free memory, potentially invalidating references to structs that were in it.
pub unsafe fn set_heap_size(new_size: usize) -> Result<usize, KernelError> {
    let (heap_address_base, ..) = unsafe {
        syscall(nr::SetHeapSize, new_size, 0, 0, 0, 0, 0)?
    };
    Ok(heap_address_base)
}

/// Query information about an address. Will fetch the page-aligned mapping `addr` falls in.
/// mapping that contains the provided address.
///
/// # Return
///
/// Information about the mapping the address fell into, and an unknown usize.
pub fn query_memory(addr: usize) -> Result<(MemoryInfo, usize), KernelError> {
    let mut meminfo = MemoryInfo::default();
    let (pageinfo, ..) = unsafe {
        syscall(nr::QueryMemory, &mut meminfo as *mut _ as usize, 0, addr, 0, 0, 0)?
    };
    Ok((meminfo, pageinfo))
}

/// Exits the process, killing all threads.
pub fn exit_process() -> ! {
    unsafe {
        match syscall(nr::ExitProcess, 0, 0, 0, 0, 0, 0) {
            Ok(_) => (),
            Err(err) => { let _ = output_debug_string(&format!("Failed to exit: {}", err)); },
        }
        #[allow(clippy::empty_loop)]
        loop {} // unreachable, but we can't panic, as panic! calls exit_process
    }
}

/// Creates a thread in the current process.
pub fn create_thread(ip: extern fn() -> !, arg: usize, sp: *const u8, priority: u32, processor_id: u32) -> Result<Thread, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::CreateThread, ip as usize, arg, sp as _, priority as _, processor_id as _, 0)?;
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

/// Creates a shared memory handle.
///
/// Allocates the given size bytes of physical memory to back the SharedMemory.
/// myperm dictates the memory permissions this handle can be mapped as in the
/// current process, while otherperm dictates the permissions for other
/// processes.
///
/// # Errors
///
/// - Errors if size is not page-aligned.
pub fn create_shared_memory(size: usize, myperm: MemoryPermissions, otherperm: MemoryPermissions) -> Result<SharedMemory, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::CreateSharedMemory, size, myperm.bits() as _, otherperm.bits() as _, 0, 0, 0)?;
        Ok(SharedMemory(Handle::new(out_handle as _)))
    }
}

/// Maps a shared memory.
///
/// Maps a SharedMemory handle at the given address, with the given permission.
///
/// # Errors
///
/// - addr must be page-aligned.
/// - size must be equal to the size of the backing shared memory handle.
/// - perm must be allowed.
pub fn map_shared_memory(handle: &SharedMemory, addr: usize, size: usize, perm: MemoryPermissions) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::MapSharedMemory, (handle.0).0.get() as _, addr, size, perm.bits() as _, 0, 0)?;
        Ok(())
    }
}

/// Unmaps a shared memory.
///
/// Unmaps a shared memory mapping at the given address.
///
/// # Errors:
///
/// - addr must point to a mapping backed by the given handle
/// - Size must be equal to the size of the backing shared memory handle.
pub fn unmap_shared_memory(handle: &SharedMemory, addr: usize, size: usize) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::UnmapSharedMemory, (handle.0).0.get() as _, addr, size, 0, 0, 0)?;
        Ok(())
    }
}

// Not totally public because it's not safe to use directly
/// Close the given handle.
pub(crate) fn close_handle(handle: u32) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::CloseHandle, handle as _, 0, 0, 0, 0, 0)?;
        Ok(())
    }
}

/// Wait for an event on the given handles.
///
/// When zero handles are passed, this will wait forever until either timeout or
/// cancellation occurs.
///
/// Does not accept 0xFFFF8001 or 0xFFFF8000 meta-handles.
///
/// # Object types
/// 
/// - KDebug: signals when there is a new DebugEvent (retrievable via
///   GetDebugEvent).
/// - KClientPort: signals when the number of sessions is less than the maximum
///   allowed.
/// - KProcess: signals when the process undergoes a state change (retrievable
///   via #svcGetProcessInfo).
/// - KReadableEvent: signals when the event's corresponding KWritableEvent has
///   been signaled via svcSignalEvent.
/// - KServerPort: signals when there is an incoming connection waiting to be
///   accepted.
/// - KServerSession: signals when there is an incoming message waiting to be
///   received or the pipe is closed.
/// - KThread: signals when the thread has exited.
///
/// # Result codes
/// 
/// - 0x0000: Success. One of the objects was signaled before the timeout
///   expired, or one of the objects is a Session with a closed remote. Handle
///   index is updated to indicate which object signaled.
/// - 0x7601: Thread termination requested. Handle index is not updated.
/// - 0xe401: Invalid handle. Returned when one of the handles passed is invalid.
///   Handle index is not updated.
/// - 0xe601: Invalid address. Returned when the handles pointer is not a
///   readable address. Handle index is not updated.
/// - 0xea01: Timeout. Returned when no objects have been signaled within the
///   timeout. Handle index is not updated.
/// - 0xec01: Interrupted. Returned when another thread uses
///   svcCancelSynchronization to cancel this thread. Handle index is not
///   updated.
/// - 0xee01: Too many handles. Returned when the number of handles passed is
///   >0x40. Note: KFS currently does not return this error. It is perfectly able
///   to wait on more than 0x40 handles.
pub fn wait_synchronization(handles: &[HandleRef<'_>], timeout_ns: Option<usize>) -> Result<usize, KernelError> {
    unsafe {
        let (handleidx, ..) = syscall(nr::WaitSynchronization, handles.as_ptr() as _, handles.len(), timeout_ns.unwrap_or_else(usize::max_value), 0, 0, 0)?;
        Ok(handleidx)
    }
}

/// Creates a session to the given named port.
pub fn connect_to_named_port(s: &str) -> Result<ClientSession, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::ConnectToNamedPort, s.as_ptr() as _, 0, 0, 0, 0, 0)?;
        Ok(ClientSession(Handle::new(out_handle as _)))
    }
}

/// Send an IPC request through the given pipe.
///
/// Please see the IPC module for more information on IPC.
pub fn send_sync_request_with_user_buffer(buf: &mut [u8], handle: &ClientSession) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::SendSyncRequestWithUserBuffer, buf.as_ptr() as _, buf.len(), (handle.0).0.get() as _, 0, 0, 0)?;
        Ok(())
    }
}

/// Print the given string to the kernel's debug output.
///
/// Currently, this prints the string to the serial port.
pub fn output_debug_string(s: &str) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::OutputDebugString, s.as_ptr() as _, s.len(), 0, 0, 0, 0)?;
        Ok(())
    }
}

/// Create an anonymous session.
pub fn create_session(is_light: bool, unk: usize) -> Result<(ServerSession, ClientSession), KernelError> {
    unsafe {
        let (serverhandle, clienthandle, ..) = syscall(nr::CreateSession, is_light as _, unk, 0, 0, 0, 0)?;
        Ok((ServerSession(Handle::new(serverhandle as _)), ClientSession(Handle::new(clienthandle as _))))
    }
}

/// Accept a connection on the given port.
pub fn accept_session(port: &ServerPort) -> Result<ServerSession, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::AcceptSession, (port.0).0.get() as _, 0, 0, 0, 0, 0)?;
        Ok(ServerSession(Handle::new(out_handle as _)))
    }
}

/// Reply and Receive IPC requests on the given handles.
///
/// If ReplyTarget is not None, a reply from the cmdbuf will be sent to that
/// session. Then it will wait until either of the passed sessions has an
/// incoming message, is closed, a passed port has an incoming connection, or
/// the timeout expires. If there is an incoming message, it is copied to the
/// cmdbuf.
///
/// If ReplyTarget is None, the cmdbuf should contain a blank message. If this
/// message has a C descriptor, the buffer it points to will be used as the
/// pointer buffer. See [switchbrew's IPC marshalling page]. Note that a pointer
/// buffer cannot be specified if ReplyTarget is not zero.
///
/// After being validated, passed handles will be enumerated in order; even if a
/// session has been closed, if one that appears earlier in the list has an
/// incoming message, it will take priority and a result code of 0x0 will be
/// returned.
///
/// [switchbrew's IPC marshalling page]: https://http://switchbrew.org/index.php?title=IPC_Marshalling
pub fn reply_and_receive_with_user_buffer(buf: &mut [u8], handles: &[HandleRef<'_>], replytarget: Option<HandleRef<'_>>, timeout: Option<usize>) -> Result<usize, KernelError> {
    unsafe {
        let (idx, ..) = syscall(nr::ReplyAndReceiveWithUserBuffer, buf.as_ptr() as _, buf.len(), handles.as_ptr() as _, handles.len(), match replytarget {
            Some(s) => s.inner.get() as _,
            None => 0
        }, timeout.unwrap_or_else(usize::max_value))?;
        Ok(idx)
    }
}

/// Create a waitable object for the given IRQ number.
///
/// Note that the process needs to be authorized to listen for the given IRQ.
pub fn create_interrupt_event(irqnum: usize, flag: u32) -> Result<ReadableEvent, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::CreateInterruptEvent, irqnum, flag as usize, 0, 0, 0, 0)?;
        Ok(ReadableEvent(Handle::new(out_handle as _)))
    }
}

/// Gets the physical region a given virtual address maps.
///
/// This syscall is mostly used for DMAs, where the physical address of a buffer needs to be known
/// by userspace.
///
/// # Return
///
/// 0. The start address of the physical region.
/// 1. 0x00000000 (On Horizon it contains the KernelSpace virtual address of this mapping,
///    but I don't see any use for it).
/// 2. The length of the physical region.
///
/// # Error
///
/// - InvalidAddress: This address does not map physical memory.
pub fn query_physical_address(virtual_address: usize) -> Result<(usize, usize, usize), KernelError> {
    unsafe {
        let (phys_addr, kernel_addr, phys_len, ..) = syscall(nr::QueryPhysicalAddress, virtual_address, 0, 0, 0, 0, 0)?;
        Ok((phys_addr, kernel_addr, phys_len))
    }
}

/// Creates an anonymous port.
pub fn create_port(max_sessions: u32, is_light: bool, name_ptr: &str) -> Result<(ClientPort, ServerPort), KernelError> {
    unsafe {
        let (out_client_handle, out_server_handle, ..) = syscall(nr::CreatePort, max_sessions as _, is_light as _, name_ptr.as_ptr() as _, 0, 0, 0)?;
        Ok((ClientPort(Handle::new(out_client_handle as _)), ServerPort(Handle::new(out_server_handle as _))))
    }
}

/// Creates a named port.
pub fn manage_named_port(name: &str, max_handles: u32) -> Result<ServerPort, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::ManageNamedPort, name.as_ptr() as _, max_handles as _, 0, 0, 0, 0)?;
        Ok(ServerPort(Handle::new(out_handle as _)))
    }
}

/// Connects to the given named port.
pub fn connect_to_port(port: &ClientPort) -> Result<ClientSession, KernelError> {
    unsafe {
        let (out_handle, ..) = syscall(nr::ConnectToPort, (port.0).0.get() as _, 0, 0, 0, 0, 0)?;
        Ok(ClientSession(Handle::new(out_handle as _)))
    }
}

/// Maps the framebuffer to a kernel-chosen address.
pub fn map_framebuffer() -> Result<(&'static mut [u8], usize, usize, usize), KernelError> {
    unsafe {
        let (addr, width, height, bpp) = syscall(nr::MapFramebuffer, 0, 0, 0, 0, 0, 0)?;
        let framebuffer_size = bpp * width * height / 8;
        Ok((slice::from_raw_parts_mut(addr as *mut u8, framebuffer_size), width, height, bpp))
    }
}

/// Maps a physical region in the address space of the process.
///
/// # Errors
///
/// * InvalidAddress:
///     * `virtual_address` is already occupied.
///     * `virtual_address` is not PAGE_SIZE aligned.
///     * `physical_address` points to a physical region in DRAM (it's not MMIO).
/// * InvalidLength:
///     * `length` is not PAGE_SIZE aligned.
///     * `length` is zero.
pub fn map_mmio_region(physical_address: usize, size: usize, virtual_address: usize, writable: bool) -> Result<(), KernelError> {
    unsafe {
        syscall(nr::MapMmioRegion, physical_address, size, virtual_address, writable as usize, 0, 0)?;
        Ok(())
    }
}
