///! Process

use stack::KernelStack;
use i386::process_switch::*;
use i386::mem::paging::InactivePageTables;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use event::Waitable;
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
    pub phwcontext: ProcessHardwareContext,
    pub phandles:   HandleTable,
}

#[derive(Debug)]
pub enum Handle {
    ReadableEvent(Box<Waitable>),
}

#[derive(Debug)]
pub struct HandleTable {
    table: BTreeMap<u32, Arc<Handle>>,
    counter: u32
}

impl HandleTable {
    pub fn new() -> HandleTable {
        HandleTable {
            table: BTreeMap::new(),
            counter: 1
        }
    }

    pub fn add_handle(&mut self, handle: Arc<Handle>) -> u32 {
        loop {
            let handlenum = self.counter;
            self.counter += 1;
            if !self.table.contains_key(&handlenum) {
                self.table.insert(handlenum, handle);
                break handlenum;
            }
        }
    }

    pub fn get_handle(&self, handle: u32) -> Arc<Handle> {
        self.table[&handle].clone()
    }
}

/// Just a handy shortcut
pub type ProcessStructArc = Arc<RwLock<ProcessStruct>>;

/// The state of a process.
///
/// - Running: currently on the CPU
/// - Scheduled: scheduled to be running
/// - Stopped: not in the scheduled queue, waiting for an event
/// - NotReady: never added to the schedule queue yet. Should be started with `scheduler::start_process`
///
/// Since SMP is not supported, there is only one Running process.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Scheduled,
    Stopped,
    NotReady
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

        // the state of the process, NotReady
        let pstate = ProcessState::NotReady;

        let p = Arc::new(
           RwLock::new(
                ProcessStruct {
                    pstate,
                    pmemory,
                    pstack,
                    phwcontext : empty_hwcontext,
                    phandles: HandleTable::new(),
                }
            )
        );

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
                    phwcontext,
                    phandles: HandleTable::new(),
                }
            )
        );

        p
    }

    /// Sets the entrypoint. Puts the Process in Stopped state.
    ///
    /// # Safety
    ///
    /// The given entrypoint *must* point to a mapped address in that process's address space.
    /// The function makes no attempt at checking if it is kernel or userspace.
    ///
    /// # Panics
    ///
    /// Panics if state is not NotReady
    pub unsafe fn set_entrypoint(&mut self, ep: usize) {
        assert_eq!(self.pstate, ProcessState::NotReady);

        // prepare the process's stack for its first schedule-in
        unsafe {
            // safe because stack is empty, p has never run
            prepare_for_first_schedule(self, ep);
        }

        self.pstate = ProcessState::Stopped;
    }
}

impl Drop for ProcessStruct {
    fn drop(&mut self) {
        // todo this should be a debug !
        info!("Dropped a process : {:?}", self)
    }
}
