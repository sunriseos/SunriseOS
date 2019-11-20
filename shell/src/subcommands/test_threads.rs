//! Test function ensuring threads are working properly.

use core::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::sync::Arc;

use spin::Mutex;

use sunrise_libuser::twili::IPipeProxy;
use sunrise_libuser::error::Error;
use sunrise_libuser::threads::{self, Thread};

/// Help string.
pub static HELP: &str = "test_threads: Run threads that concurrently print As and Bs";

/// Test function ensuring threads are working properly.
pub fn main(_stdin: IPipeProxy, stdout: IPipeProxy, _stderr: IPipeProxy, _args: Vec<String>) -> Result<(), Error> {
    #[doc(hidden)]
    fn thread_a(terminal: usize) {
        let terminal = unsafe {
            Arc::from_raw(terminal as *const Mutex<IPipeProxy>)
        };
        let mut i = 0;
        while i < 10 {
            if let Some(mut lock) = terminal.try_lock() {
                let _ = writeln!(lock, "A");
                i += 1;
            }
            let _ = libuser::syscalls::sleep_thread(0);
        }
    }

    #[doc(hidden)]
    fn thread_b(terminal: usize) {
        // Wrap in a block to forcibly call Arc destructor before exiting the thread.
        {
            let terminal = unsafe {
                Arc::from_raw(terminal as *const Mutex<IPipeProxy>)
            };
            let mut i = 0;
            while i < 10 {
                if let Some(mut lock) = terminal.try_lock() {
                    let _ = writeln!(lock, "B");
                    i += 1;
                }
                let _ = libuser::syscalls::sleep_thread(0);
            }
        }
    }

    let terminal = Arc::new(Mutex::new(stdout));

    let t = Thread::create(thread_b, Arc::into_raw(terminal.clone()) as usize, threads::DEFAULT_STACK_SIZE)
        .expect("Failed to create thread B");
    t.start()
        .expect("Failed to start thread B");


    // thread is running b, run a meanwhile
    thread_a(Arc::into_raw(terminal.clone()) as usize);

    // Wait for thread_b to terminate.
    t.join().expect("Cannot wait for thread B to finish");

    Ok(())
}
