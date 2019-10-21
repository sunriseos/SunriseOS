use crate::ffi::CStr;
use crate::io;
use crate::time::Duration;
use crate::usize;

use sunrise_libuser::syscalls;
use sunrise_libuser::threads::{Thread as LibUserThread};

pub struct Thread(LibUserThread);

pub const DEFAULT_MIN_STACK_SIZE: usize = sunrise_libuser::threads::DEFAULT_STACK_SIZE;

impl Thread {
    // Thread wrapper
    fn start_wrapper(argument: usize) {
        let p = unsafe { Box::from_raw(argument as *const Box<dyn FnOnce()> as *mut Box<dyn FnOnce()>) };

        p();
    }

    // unsafe: see thread::Builder::spawn_unchecked for safety requirements
    pub unsafe fn new(stack_size: usize, p: Box<dyn FnOnce()>)
        -> io::Result<Thread>
    {
        // TODO(Sunrise): remap errors
        let box_p = Box::new(p);
        let inner_thread = LibUserThread::create(Self::start_wrapper, Box::into_raw(box_p) as *const Box<dyn FnOnce()> as *const u8 as usize, stack_size).unwrap();
        inner_thread.start().unwrap();
        Ok(Thread(inner_thread))
    }

    pub fn yield_now() {
        let _ = syscalls::sleep_thread(0);
    }

    pub fn set_name(_name: &CStr) {
        // TODO(Sunrise): We don't have thread names yet
        //panic!("not supported on sunrise yet")
    }

    pub fn sleep(duration: Duration) {
        let mut nanos = duration.as_nanos();
        if nanos > usize::MAX as u128 {
            nanos = usize::MAX as u128;
        }

        // TODO(Sunrise): change this to u64 after changing the syscall.
        let _ = syscalls::sleep_thread(nanos as usize);
    }

    pub fn join(self) {
        self.0.join().unwrap();
    }
}

pub mod guard {
    pub type Guard = !;
    pub unsafe fn current() -> Option<Guard> { None }
    pub unsafe fn init() -> Option<Guard> { None }
}
