//! Syscall Wrappers

use core::slice;
use core::marker::PhantomData;

macro_rules! syscall {
    ($nr:expr) => {{
        let out: usize;
        asm!("int 0x80" : "={eax}"(out) : "{eax}"($nr)
             : "memory" : "intel", "volatile");
        out
    }};
    ($nr:expr, $arg1:expr) => {{
        let out: usize;
        asm!("int 0x80" : "={eax}"(out) : "{eax}"($nr), "{ebx}"($arg1)
             : "memory" : "intel", "volatile");
        out
    }};
    ($nr:expr, $arg1:expr, $arg2:expr) => {{
        let out: usize;
        asm!("int 0x80" : "={eax}"(out) : "{eax}"($nr), "{ebx}"($arg1),
             "{ecx}"($arg2)
             : "memory" : "intel", "volatile");
        out
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {{
        let out: usize;
        asm!("int 0x80" : "={eax}"(out) : "{eax}"($nr), "{ebx}"($arg1),
             "{ecx}"($arg2), "{edx}"($arg3)
             : "memory" : "intel", "volatile");
        out
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr) => {{
        let out: usize;
        asm!("int 0x80" : "={eax}"(out) : "{eax}"($nr), "{ebx}"($arg1),
             "{ecx}"($arg2), "{edx}"($arg3), "{esi}"($arg4)
             : "memory" : "intel", "volatile");
        out
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr) => {{
        let out: usize;
        asm!("int 0x80" : "={eax}"(out) : "{eax}"($nr), "{ebx}"($arg1),
             "{ecx}"($arg2), "{edx}"($arg3), "{esi}"($arg4),
             "{edi}"($arg5)
             : "memory" : "intel", "volatile");
        out
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr, $arg6:expr) => {{
        let out: usize;
        asm!("int 0x80" : "={eax}"(out) : "{eax}"($nr), "{ebx}"($arg1),
             "{ecx}"($arg2), "{edx}"($arg3), "{esi}"($arg4),
             "{edi}"($arg5), "{ebp}"($arg6)
             : "memory" : "intel", "volatile");
        out
    }}
}

#[repr(transparent)]
#[derive(Debug)]
pub struct Handle(u32);

impl Handle {
    pub fn as_ref(&self) -> HandleRef {
        HandleRef {
            inner: self.0,
            lifetime: PhantomData
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // TODO: Drop.
    }
}

#[repr(transparent)]
pub struct HandleRef<'a> {
    inner: u32,
    lifetime: PhantomData<&'a Handle>
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ReadableEvent(pub Handle);

#[repr(transparent)]
#[derive(Debug)]
pub struct ClientSession(pub Handle);

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerSession(pub Handle);

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerPort(pub Handle);

impl ServerPort {
    pub fn accept(&self) -> Result<ServerSession, usize> {
        accept_session(self)
    }
}

pub fn exit_process() -> ! {
    unsafe {
        let ret = syscall!(0x7);
        let _ = output_debug_string(&format!("Failed to exit: {}", ret));
        loop {}
    }
}


pub fn wait_synchronization(handles: &[HandleRef], timeout_ns: Option<usize>) -> Result<usize, usize> {
    unsafe {
        let mut handleidx = 0usize;
        let ret = syscall!(0x18, &mut handleidx, handles.as_ptr(), handles.len(), timeout_ns.unwrap_or(usize::max_value()));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(handleidx)
        }
    }
}

pub fn connect_to_named_port(s: &str) -> Result<ClientSession, usize> {
    unsafe {
        let mut out_handle = 0u32;
        let ret = syscall!(0x1F, &mut out_handle, s as *const str as *const u8 as usize);
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ClientSession(Handle(out_handle)))
        }
    }
}

pub fn output_debug_string(s: &str) -> Result<(), usize> {
    unsafe {
        let ret = syscall!(0x27, s as *const str as *const u8 as usize, s.len());
        if ret != 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }
}

pub fn accept_session(port: &ServerPort) -> Result<ServerSession, usize> {
    unsafe {
        let mut out_handle = 0u32;
        let ret = syscall!(0x41, &mut out_handle, (port.0).0);
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ServerSession(Handle(out_handle)))
        }
    }
}

pub fn create_interrupt_event(irqnum: usize, flag: u32) -> Result<ReadableEvent, usize> {
    unsafe {
        let mut out_handle = 0u32;
        let ret = syscall!(0x53, &mut out_handle, irqnum, flag as usize);
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ReadableEvent(Handle(out_handle)))
        }
    }
}

pub fn manage_named_port(name: &str, max_handles: u32) -> Result<ServerPort, usize> {
    unsafe {
        let mut out_handle = 0u32;
        let ret = syscall!(0x71, &mut out_handle, name as *const str as *const u8 as usize, max_handles);
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ServerPort(Handle(out_handle)))
        }
    }
}

pub fn map_framebuffer() -> Result<(&'static mut [u8], usize, usize, usize), usize> {
    unsafe {
        let mut addr = 0usize;
        let mut width = 0usize;
        let mut height = 0usize;
        let mut bpp = 0usize;
        let ret = syscall!(0x80, &mut addr, &mut width, &mut height, &mut bpp);
        if ret != 0 {
            Err(ret)
        } else {
            let framebuffer_size = bpp * width * height / 8;
            Ok((slice::from_raw_parts_mut(addr as *mut u8, framebuffer_size), width, height, bpp))
        }
    }
}
