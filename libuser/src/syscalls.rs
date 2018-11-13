//! Syscall Wrappers

use core::slice;
use types::*;

macro_rules! syscall {
    ($nr:expr, inputs=($($itt:tt)*), outputs=($($ott:tt)*)) => {
        syscall!(@inputstart $nr, inputs=($($itt)*), outputs=($($ott)*), "ebx" $($ott)*);
    };

    (@inputstart $nr:expr, inputs=($($itt:tt)*), outputs=($($ott:tt)*), $curval:tt $($tt:tt)*) => {
        syscall!(@geninputs $nr, inputstart=$curval, inputs=(), outputs=(), ($($itt)*), ($($ott)*));
    };
    /*(@inputstart $nr:expr, inputs=($($itt:tt)*), outputs=($($ott:tt)*), "ebx" $expr:expr $(, $tt:tt)*) => {
        syscall!(@inputstart $nr, inputs=($($itt)*), outputs=($($ott)*), "ecx" $($tt),*);
    };
    (@inputstart $nr:expr, inputs=($($itt:tt)*), outputs=($($ott:tt)*), "ecx" $expr:expr $(, $tt:tt)*) => {
        syscall!(@inputstart $nr, inputs=($($itt)*), outputs=($($ott)*), "edx" $($tt),*);
    };
    (@inputstart $nr:expr, inputs=($($itt:tt)*), outputs=($($ott:tt)*), "edx" $expr:expr $(, $tt:tt)*) => {
        syscall!(@inputstart $nr, inputs=($($itt)*), outputs=($($ott)*), "esi" $($tt),*);
    };*/
    // TODO: We currently never go beyond 3 return registers.

    // Remove register from clobberlist if present in either output or input
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=("ebx" $(, $postclobbers:tt)*), "{ebx}" $(, $tt:tt)*) => {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*), clobberlist=($($postclobbers),*), $($tt),*);
    };
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=("ecx" $(, $postclobbers:tt)*), "{ecx}" $(, $tt:tt)*) => {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*), clobberlist=($($postclobbers),*), $($tt),*);
    };
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=("edx" $(, $postclobbers:tt)*), "{edx}" $(, $tt:tt)*) => {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*), clobberlist=($($postclobbers),*), $($tt),*);
    };
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=("esi" $(, $postclobbers:tt)*), "{esi}" $(, $tt:tt)*) => {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*), clobberlist=($($postclobbers),*), $($tt),*);
    };
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=("edi" $(, $postclobbers:tt)*), "{edi}" $(, $tt:tt)*) => {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*), clobberlist=($($postclobbers),*), $($tt),*);
    };
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=("ebp" $(, $postclobbers:tt)*), "{ebp}" $(, $tt:tt)*) => {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*), clobberlist=($($postclobbers),*), $($tt),*);
    };
    // If output/input is not present in clobberlist, go to next output/input
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=($($clobbers:tt)*), $cur:tt $(, $tt:tt)*) => {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*), clobberlist=($($clobbers)*), $($tt),*);
    };
    // We're done!
    (@buildclobber $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=($($clobber:tt)*) $(,)* ) => {
        syscall!(@mapout $nr, inputs=($($iconstraint($ivar)),*), outputs=(), clobberlist=($($clobber)*), $($oconstraint($ovar)),*);
    };

    (@mapout $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=($($clobber:tt)*), "{eax}"($cvar:expr) $(, $noconstraint:tt($novar:expr))* ) => {
        syscall!(@mapout $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar),)* "={eax}"($cvar)),
            clobberlist=($($clobber)*), $($noconstraint($novar)),*);
    };
    (@mapout $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=($($clobber:tt)*), "{ebx}"($cvar:expr) $(, $noconstraint:tt($novar:expr))* ) => {
        syscall!(@mapout $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar),)* "={ebx}"($cvar)),
            clobberlist=($($clobber)*), $($noconstraint($novar)),*);
    };
    (@mapout $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=($($clobber:tt)*), "{ecx}"($cvar:expr) $(, $noconstraint:tt($novar:expr))* ) => {
        syscall!(@mapout $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar),)* "={ecx}"($cvar)),
            clobberlist=($($clobber)*), $($noconstraint($novar)),*);
    };
    (@mapout $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
     clobberlist=($($clobber:tt)*), "{edx}"($cvar:expr) $(, $noconstraint:tt($novar:expr))* ) => {
        syscall!(@mapout $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar),)* "={edx}"($cvar)),
                 clobberlist=($($clobber)*), $($noconstraint($novar)),*);
    };
    (@mapout $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
     clobberlist=($($clobber:tt)*), "{esi}"($cvar:expr) $(, $noconstraint:tt($novar:expr))* ) => {
        syscall!(@mapout $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar),)* "={esi}"($cvar)),
                 clobberlist=($($clobber)*), $($noconstraint($novar)),*);
    };
    (@mapout $nr:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*),
        clobberlist=($($clobber:tt),*), ) => {{
        let out: usize;
        asm!("int 0x80" :
             "={eax}"(out) $(, $oconstraint($ovar))* :
             "{eax}"($nr) $(, $iconstraint($ivar))* :
             "memory" $(, $clobber)* :
             "intel", "volatile");
        out
    }};

    (@geninputs $nr:expr, inputstart="ebx", inputs=($($iconstraint:tt($ivar:expr)),*), outputs=(), ($val:expr $(, $itt:expr)*), ($($ott:tt)*))=> {
        syscall!(@geninputs $nr, inputstart="ecx", inputs=($($iconstraint($ivar),)* "{ebx}"($val)), outputs=(), ($($itt),*), ($($ott)*))
    };
    (@geninputs $nr:expr, inputstart="ecx", inputs=($($iconstraint:tt($ivar:expr)),*), outputs=(), ($val:expr $(, $itt:expr)*), ($($ott:tt)*))=> {
        syscall!(@geninputs $nr, inputstart="edx", inputs=($($iconstraint($ivar),)* "{ecx}"($val)), outputs=(), ($($itt),*), ($($ott)*))
    };
    (@geninputs $nr:expr, inputstart="edx", inputs=($($iconstraint:tt($ivar:expr)),*), outputs=(), ($val:expr $(, $itt:expr)*), ($($ott:tt)*))=> {
        syscall!(@geninputs $nr, inputstart="esi", inputs=($($iconstraint($ivar),)* "{edx}"($val)), outputs=(), ($($itt),*), ($($ott)*))
    };
    (@geninputs $nr:expr, inputstart="esi", inputs=($($iconstraint:tt($ivar:expr)),*), outputs=(), ($val:expr $(, $itt:expr)*), ($($ott:tt)*))=> {
        syscall!(@geninputs $nr, inputstart="edi", inputs=($($iconstraint($ivar),)* "{esi}"($val)), outputs=(), ($($itt),*), ($($ott)*))
    };
    (@geninputs $nr:expr, inputstart="edi", inputs=($($iconstraint:tt($ivar:expr)),*), outputs=(), ($val:expr $(, $itt:expr)*), ($($ott:tt)*))=> {
        syscall!(@geninputs $nr, inputstart="ebp", inputs=($($iconstraint($ivar),)* "{edi}"($val)), outputs=(), ($($itt),*), ($($ott)*))
    };
    (@geninputs $nr:expr, inputstart="ebp", inputs=($($iconstraint:tt($ivar:expr)),*), outputs=(), ($val:expr $(, $itt:expr)*), ($($ott:tt)*))=> {
        syscall!(@geninputs $nr, inputstart="none", inputs=($($iconstraint($ivar),)* "{ebp}"($val)), outputs=(), ($($itt),*), ($($ott)*))
    };
    (@geninputs $nr:expr, inputstart=$pos:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=(), ($(,)*), ($($ott:tt)*))=> {
        syscall!(@genoutputs $nr, outputstart="ebx", inputs=($($iconstraint($ivar)),*), outputs=(), (), ($($ott)*))
    };

    (@genoutputs $nr:expr, outputstart="ebx", inputs=($($itt:tt)*), outputs=($($oconstraint:tt($ovar:expr)),*), (), ($val:expr $(, $ott:expr)*)) => {
        syscall!(@genoutputs $nr, outputstart="ecx", inputs=($($itt)*), outputs=($($oconstraint($ovar),)* "{ebx}"($val)), (), ($($ott),*))
    };
    (@genoutputs $nr:expr, outputstart="ecx", inputs=($($itt:tt)*), outputs=($($oconstraint:tt($ovar:expr)),*), (), ($val:expr $(, $ott:expr)*)) => {
        syscall!(@genoutputs $nr, outputstart="edx", inputs=($($itt)*), outputs=($($oconstraint($ovar),)* "{ecx}"($val)), (), ($($ott),*))
    };
    (@genoutputs $nr:expr, outputstart="edx", inputs=($($itt:tt)*), outputs=($($oconstraint:tt($ovar:expr)),*), (), ($val:expr $(, $ott:expr)*)) => {
        syscall!(@genoutputs $nr, outputstart="esi", inputs=($($itt)*), outputs=($($oconstraint($ovar),)* "{edx}"($val)), (), ($($ott),*))
    };
    (@genoutputs $nr:expr, outputstart="esi", inputs=($($itt:tt)*), outputs=($($oconstraint:tt($ovar:expr)),*), (), ($val:expr $(, $ott:expr)*)) => {
        syscall!(@genoutputs $nr, outputstart="edi", inputs=($($itt)*), outputs=($($oconstraint($ovar),)* "{esi}"($val)), (), ($($ott),*))
    };

    // TODO: I'm lazy
    (@genoutputs $nr:expr, outputstart=$pos:expr, inputs=($($iconstraint:tt($ivar:expr)),*), outputs=($($oconstraint:tt($ovar:expr)),*), (), ($(,)*))=> {
        syscall!(@buildclobber $nr, inputs=($($iconstraint($ivar)),*), outputs=($($oconstraint($ovar)),*),
            clobberlist=("ebx", "ecx", "edx", "esi", "edi", "ebp") $(, $oconstraint)* $(, $iconstraint)*)
    };
}

pub fn exit_process() -> ! {
    unsafe {
        let ret = syscall!(0x7, inputs=(), outputs=());
        let _ = output_debug_string(&format!("Failed to exit: {}", ret));
        loop {}
    }
}

pub fn wait_synchronization(handles: &[HandleRef], timeout_ns: Option<usize>) -> Result<usize, usize> {
    unsafe {
        let handleidx;
        let ret = syscall!(0x18, inputs=(handles.as_ptr(), handles.len(), timeout_ns.unwrap_or(usize::max_value())), outputs=(handleidx));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(handleidx)
        }
    }
}

pub fn connect_to_named_port(s: &str) -> Result<ClientSession, usize> {
    unsafe {
        let out_handle;
        let ret = syscall!(0x1F, inputs=(s.as_ptr()), outputs=(out_handle));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ClientSession(Handle::new(out_handle)))
        }
    }
}

pub fn send_sync_request_with_user_buffer(buf: &mut [u8], handle: &ClientSession) -> Result<(), usize> {
    unsafe {
        let ret = syscall!(0x22, inputs=(buf.as_ptr(), buf.len(), (handle.0).0.get()), outputs=());
        if ret != 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }
}

pub fn output_debug_string(s: &str) -> Result<(), usize> {
    unsafe {
        let ret = syscall!(0x27, inputs=(s.as_ptr(), s.len()), outputs=());
        if ret != 0 {
            Err(ret)
        } else {
            Ok(())
        }
    }
}

pub fn accept_session(port: &ServerPort) -> Result<ServerSession, usize> {
    unsafe {
        let out_handle;
        let ret = syscall!(0x41, inputs=((port.0).0), outputs=(out_handle));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ServerSession(Handle::new(out_handle)))
        }
    }
}

pub fn create_interrupt_event(irqnum: usize, flag: u32) -> Result<ReadableEvent, usize> {
    unsafe {
        let out_handle;
        let ret = syscall!(0x53, inputs=(irqnum, flag as usize), outputs=(out_handle));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ReadableEvent(Handle::new(out_handle)))
        }
    }
}

pub fn create_port(max_sessions: u32, is_light: bool, name_ptr: &str) -> Result<(ClientPort, ServerPort), usize> {
    unsafe {
        let out_client_handle;
        let out_server_handle;
        let ret = syscall!(0x70, inputs=(max_sessions, is_light, name_ptr.as_ptr()), outputs=(out_client_handle, out_server_handle));
        if ret != 0 {
            Err(ret)
        } else {
            Ok((ClientPort(Handle::new(out_client_handle)), ServerPort(Handle::new(out_server_handle))))
        }
    }
}

pub fn manage_named_port(name: &str, max_handles: u32) -> Result<ServerPort, usize> {
    unsafe {
        let out_handle;
        let ret = syscall!(0x71, inputs=(name.as_ptr(), max_handles), outputs=(out_handle));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ServerPort(Handle::new(out_handle)))
        }
    }
}

pub fn connect_to_port(port: &ClientPort) -> Result<ClientSession, usize> {
    unsafe {
        let out_handle;
        let ret = syscall!(0x72, inputs=((port.0).0), outputs=(out_handle));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(ClientSession(Handle::new(out_handle)))
        }
    }
}

pub fn map_framebuffer() -> Result<(&'static mut [u8], usize, usize, usize), usize> {
    unsafe {
        let addr;
        let width;
        let height;
        let bpp;
        let ret = syscall!(0x80, inputs=(), outputs=(addr, width, height, bpp));
        if ret != 0 {
            Err(ret)
        } else {
            let framebuffer_size = bpp * width * height / 8;
            Ok((slice::from_raw_parts_mut(addr, framebuffer_size), width, height, bpp))
        }
    }
}

pub fn reply_and_receive_with_user_buffer(buf: &mut [u8], handles: &[HandleRef], replytarget: Option<HandleRef>) -> Result<usize, usize>{
    unsafe {
        let idx;
        let ret = syscall!(0x44, inputs=(buf.as_ptr(), buf.len(), handles.as_ptr(), handles.len(), replytarget), outputs=(idx));
        if ret != 0 {
            Err(ret)
        } else {
            Ok(idx)
        }
    }
}
