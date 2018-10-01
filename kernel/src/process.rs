///! Process

use stack::KernelStack;
use i386::process_switch::*;
use i386::mem::paging::InactivePageTables;
use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::{RwLock, RwLockWriteGuard};
use sync::SpinLock;

/// The struct representing a process. There's one for every process.
///
/// It contains many information about the process :
///
/// - Its type (regular userspace process, or kworker)
/// - Its state (Running, Scheduled, Stopped)
/// - Its memory pages
/// - Its kernel stack, for syscalls and interrupts
/// - Its hardware context, to be restored on rescheduling
#[derive(Debug)]
pub struct ProcessStruct {
    pub pstate:     ProcessState,
    pub pmemory:    ProcessMemory,
    pub pstack:     KernelStack,
    pub phwcontext: ProcessHardwareContext
}

/// Just a handy shortcut
pub type ProcessStructArc = Arc<RwLock<ProcessStruct>>;

/// The state of a process.
///
/// - Running: currently on the CPU
/// - Scheduled: scheduled to be running
/// - Stopped: not in the scheduled queue, waiting for an event
///
/// Since SMP is not supported, there is only one Running process.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Scheduled,
    Stopped
}

/// The memory pages of this process
///
/// - Inactive contains the process's pages.
/// - Active means the already currently active ones, accessible through ACTIVE_PAGE_TABLES.
///
/// A ProcessMemory should be the only owner of a process' pages
#[derive(Debug)]
pub enum ProcessMemory {
    Inactive(SpinLock<InactivePageTables>),
    Active
}

impl ProcessStruct {
    /// Creates a new process.
    pub fn new() -> Arc<RwLock<ProcessStruct>> {
        use ::core::mem::ManuallyDrop;

        // allocate its memory space
        let pmemory = ProcessMemory::Inactive(SpinLock::new(InactivePageTables::new()));

        // allocate its kernel stack
        let pstack = KernelStack::allocate_stack()
            .expect("Couldn't allocate a kernel stack");

        // hardware context will be computed later in this function, write a dummy value for now
        let empty_hwcontext = ProcessHardwareContext::new();

        // the state of the process, stopped (for now ...)
        let pstate = ProcessState::Stopped;

        let p = Arc::new(
           RwLock::new(
                ProcessStruct {
                    pstate,
                    pmemory,
                    pstack,
                    phwcontext : empty_hwcontext
                }
            )
        );

        // prepare the process's stack for its first schedule-in
        unsafe {
            // safe because stack is empty, p has never run
            prepare_for_first_schedule(&mut p.write());
        }

        p
    }

    /// Creates the very first process at boot.
    ///
    /// # Safety
    ///
    /// Use only for creating the very first process. Should never be used again after that.
    /// Must be using a valid KernelStack, a valid ActivePageTables.
    ///
    /// # Panics
    ///
    /// ThreadInfoInStack will be initialized, it must not already have been
    pub unsafe fn create_first_process() -> Arc<RwLock<ProcessStruct>> {

        // the state of the process, currently running
        let pstate = ProcessState::Running;

        // use the already allocated stack
        let pstack = KernelStack::get_current_stack();

        // the saved esp will be overwritten on schedule-out anyway
        let phwcontext = ProcessHardwareContext::new();

        // the already currently active pages
        let pmemory = ProcessMemory::Active;

        let p = Arc::new(
            RwLock::new(
                ProcessStruct {
                    pstate,
                    pmemory,
                    pstack,
                    phwcontext
                }
            )
        );

        p
    }
}

impl Drop for ProcessStruct {
    fn drop(&mut self) {
        // todo this should be a debug !
        info!("Dropped a process : {:?}", self)
    }
}