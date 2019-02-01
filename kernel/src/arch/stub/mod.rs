//! Stub implementation of the arch-independant API
//!
//! This is the stub implementation of the arch-independant API. Its aim is to
//! ease porting efforts by providing a copy-pastable module to start a new
//! implementation of the arch-specific component, and to provide the test builds
//! with a simple implementation.

use alloc::sync::Arc;
use xmas_elf::ElfFile;
use xmas_elf::symbol_table::Entry32;

use crate::mem::PhysicalAddress;
use crate::process::ThreadStruct;
use crate::error::KernelError;

/// Enable interruptions. After calling this function, hardware should call
/// [crate::event::dispatch_event] whenever it receives an interruption.
pub unsafe fn enable_interrupts() {
}

/// Disable interruptions, returning true if they were previously enabled, or
/// false if they were already disabled. After calling this function, no hardware
/// should call [crate::event::dispatch_event]. Interruptions should be queued
/// until either [enable_interrupts] is called or a process switch is performed.
pub unsafe fn disable_interrupts() -> bool {
    false
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

pub unsafe extern "C" fn process_switch(_thread_b: Arc<ThreadStruct>, _thread_current: Arc<ThreadStruct>) -> Arc<ThreadStruct> {
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
pub unsafe fn prepare_for_first_schedule(_t: &ThreadStruct, _entrypoint: usize, _userspace_stack: usize) {
}

/// Get a list of Kernel Internal Processes to load. These are processes
/// typically bundled with the kernel that are the basic necessary processes to
/// load other processes from the filesystem. These are typically FS, Loader and
/// Boot.
pub fn get_modules() -> impl Iterator<Item = impl crate::elf_loader::Module> {
    #[doc(hidden)]
    #[derive(Debug)]
    struct EmptyModule;
    impl crate::elf_loader::Module for EmptyModule {
        fn start_address(&self) -> PhysicalAddress {
            unreachable!()
        }
        fn end_address(&self) -> PhysicalAddress {
            unreachable!()
        }
        fn name(&self) -> &str {
            "Empty Module"
        }
    }
    core::iter::empty::<EmptyModule>()
}

/// A structure representing a kernel stack. Allows abstracting away allocation
/// and dumping of the Kernel Stack.
///
/// A KernelStack is switched to when the kernel needs to handle an interrupt or
/// exception while userspace is executing. To avoid leaking kernel memory to
/// userspace, the stack is switched to the KernelStack.
#[derive(Debug)]
pub struct KernelStack;

impl KernelStack {
    /// Allocate a new KernelStack for a new [ThreadStruct]. This is used by
    /// [ThreadStruct::new] to create the new KernelStack associated with this
    /// thread.
    pub fn allocate_stack() -> Result<KernelStack, KernelError> {
        unimplemented!()
    }

    /// Get the current kernel stack. Used by [ThreadStruct::create_first_thread]
    /// to create the first thread's KernelStack.
    ///
    /// # Safety
    ///
    /// Unsafe because it creates duplicates of the stack structure,
    /// whose only owner should be the ProcessStruct it belongs to.
    /// This enables having several mut references pointing to the same underlying memory.
    /// Caller has to make sure no references to the stack exists when calling this function.
    ///
    /// The safe method of getting the stack is by getting current [`ProcessStruct`], *lock it*,
    /// and use its `pstack`.
    ///
    /// [ThreadStruct::create_first_thread]: crate::process::ThreadStruct::create_first_thread
    pub unsafe fn get_current_stack() -> KernelStack {
        unimplemented!()
    }

    /// Dumps the stack, displaying it in a frame-by-frame format.
    ///
    /// It can accepts an elf symbols which will be used to enhance the stack dump.
    pub fn dump_current_stack<'a>(_elf_symbols: Option<(&ElfFile<'a>, &'a [Entry32])>) {
    }
}

/// A structure representing the CPU stack state at a given execution point. From
/// this state, we can generate a meaningful stack trace.
pub struct StackDumpSource;

/// Dumps the stack from the given information, displaying it in a frame-by-frame
/// format.
///
/// # Safety
///
/// This function checks whether the stack is properly mapped before attempting to access it.
/// It then creates a &[u8] from what could be a shared resource.
///
/// The caller must make sure the mapping pointed to by `source` cannot be modified while this
/// function is at work. This will often mean checking that the thread whose stack we're dumping
/// is stopped and will remain unscheduled at least until this function returns.
pub unsafe fn dump_stack<'a>(_source: &StackDumpSource, _elf_symbols: Option<(&ElfFile<'a>, &'a [Entry32])>) {
}
