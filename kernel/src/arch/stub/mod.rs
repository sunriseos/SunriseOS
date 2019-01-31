//! Stub implementation of the arch-independant API
//!
//! This is the stub implementation of the arch-independant API. Its aim is to
//! ease porting efforts by providing a copy-pastable module to start a new
//! implementation of the arch-specific component, and to provide the test builds
//! with a simple implementation.

use alloc::sync::Arc;
use crate::process::ThreadStruct;

/// Enable interruptions. After calling this function, hardware should call
/// [crate::event::dispatch_event] whenever it receives an interruption.
pub unsafe fn enable_interrupts() {
}

/// Disable interruptions. After calling this function, no hardware should call
/// [crate::event::dispatch_event]. Interruptions should be queued until either
/// [enable_interrupts] is called or a process switch is performed.
pub unsafe fn disable_interrupts() {
}

/// Get the kernel arguments. Based on those, various kernel feature may get
/// enabled/disabled.
///
/// In practice, this cmdline is mainly used to setup the logger implementation.
/// It follows a similar scheme to env_logger, but doesn't implement the regex
/// matching. Look at the [env_logger docs] for more information.
///
/// [env_logger docs]: https://docs.rs/env_logger/0.6.0/env_logger/
pub fn get_cmdline() -> &'static str {
    "debug"
}

/// Get the kernel logger sink. Usually, this will be the Serial/UART output.
/// All calls to `log!` and co. will be directed to this logger. Note that this
/// function is called very early in the boot process (it's called in
/// [log_impl::log]).
pub fn get_logger() -> impl core::fmt::Write {
    #[doc(hidden)]
    #[derive(Debug)]
    struct EmptyLogger;
    impl core::fmt::Write for EmptyLogger {
        fn write_str(&mut self, _s: &str) -> Result<(), core::fmt::Error> {
            Ok(())
        }
    }
    EmptyLogger
}

/// Force unlocks any mutex that might be locking the Write implementation
/// returned by [get_logger]. This is only used by the panic handling, to ensure
/// we don't deadlock if we panic'd in the logging implementation.
pub unsafe fn force_logger_unlock() {
}

/// The hardware context of a paused thread. It contains just enough registers to get the thread
/// running again.
///
/// All other registers are to be saved on the thread's kernel stack before scheduling,
/// and restored right after re-schedule.
///
/// Stored in the ThreadStruct of every thread.
#[derive(Debug, Default)]
pub struct ThreadHardwareContext;

pub unsafe extern "C" fn process_switch(thread_b: Arc<ThreadStruct>, thread_current: Arc<ThreadStruct>) -> Arc<ThreadStruct> {
    unimplemented!("Can't process switch on stub architecture")
}

/// Prepares the thread for its first schedule, prepopulating the hwcontext and
/// setting up the necessary environment for [process_switch] to work correctly.
/// This can involve pushing values on the stack, setting specific registers,
/// etc... See [process_switch] documentation for more details.
///
/// # Safety
///
/// UB if called on a thread after it was scheduled for the first time.
pub unsafe fn prepare_for_first_schedule(t: &ThreadStruct, entrypoint: usize, userspace_stack: usize) {
}
