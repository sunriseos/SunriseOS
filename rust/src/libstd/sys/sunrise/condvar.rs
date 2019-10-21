use crate::sys::mutex::Mutex;
use crate::time::Duration;

pub struct Condvar { }

impl Condvar {
    pub const fn new() -> Condvar {
        Condvar { }
    }

    #[inline]
    pub unsafe fn init(&mut self) {
        //panic!("not supported on sunrise yet")
    }

    #[inline]
    pub unsafe fn notify_one(&self) {
        panic!("not supported on sunrise yet")
    }

    #[inline]
    pub unsafe fn notify_all(&self) {
        panic!("not supported on sunrise yet")
    }

    pub unsafe fn wait(&self, _mutex: &Mutex) {
        panic!("not supported on sunrise yet")
    }

    pub unsafe fn wait_timeout(&self, _mutex: &Mutex, _dur: Duration) -> bool {
        panic!("not supported on sunrise yet")
    }

    #[inline]
    pub unsafe fn destroy(&self) {
        panic!("not supported on sunrise yet")
    }
}
