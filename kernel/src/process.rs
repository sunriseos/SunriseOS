//! The Completly Unfair Scheduler
// TODO: Write some more doc here

use stack::KernelStack;
use i386::mem::paging::InactivePageTables;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
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
///
/// The task_struct of the currently running process can be retrieved thanks to a pointer saved at
/// the bottom of every kernel stack, the ThreadInfoInStack structure.
#[derive(Debug)]
pub struct ProcessStruct {
//    ptype:      ProcessType,
    pstate:     ProcessState,
    pmemory:    ProcessMemory,
    pstack:     KernelStack,
    phwcontext: ProcessHardwareContext
}

// /// The type of the process, either a regular userspace process, or a kworker.
// ///
// /// In case of kworker, it contains a pointer to the function to be executed upon first scheduling.
// /// Otherwise the generic fisrt-scheduling function for user processes will be called.
// pub enum ProcessType {
//     Regular,
//     Kworker(fn() -> !)
// }

/// The state of a process.
///
/// - Running: currently on the CPU
/// - Scheduled: scheduled to be running
/// - Stopped: not in the scheduled queue, waiting for an event
///
/// Since SMP is not supported, there is only one Running process.
#[derive(Debug)]
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

/// The hardware context of a paused process. It contains just enough registers to get the process
/// running again.
///
/// All other registers are to be saved on the process's kernel stack before scheduling,
/// and restored right after re-schedule.
#[derive(Debug)]
pub struct ProcessHardwareContext {
    esp: usize, // the top of the stack, where all other registers are saved
}

impl ProcessHardwareContext {
    /// Creates a hardware context to be loaded for a newly born process.
    fn new(stack: &mut KernelStack) -> Self {
        Self {
            esp: stack.get_stack_start(),
        }
    }
}

impl ProcessStruct {
    /// Creates a new process.
    pub fn new() -> Arc<RwLock<ProcessStruct>> {
        use ::core::mem::ManuallyDrop;

        // allocate its memory space
        let pmemory = ProcessMemory::Inactive(SpinLock::new(InactivePageTables::new()));

        // allocate its kernel stack
        // we are creating a cyclic link, so
        // 1: create the ProcessStruct without a stack,
        // 2: create a stack with a weak link to the half-initialized process
        // 3: lately write this stack in the ProcessStruct
        // this is safe because this is entirely done internally in this function,
        // and until we return it, the half-initialized process is only known by us.
        //
        // we must wrap it in a ManuallyDrop in case function panics, unwinds and tries to drop it
        let mut fake_stack = unsafe {
            ManuallyDrop::new(::core::mem::uninitialized::<KernelStack>())
        };

        // same goes for phwcontext, that needs the stack for initialization
        let fake_phwcontext = unsafe {
            ManuallyDrop::new(::core::mem::uninitialized::<ProcessHardwareContext>())
        };

        // the state of the process, stopped (for now ...)
        let pstate = ProcessState::Stopped;

        // must wrap in a manually drop for the same reason as stack, because it contains it
        let p = ManuallyDrop::new(
           Arc::new(
               RwLock::new(
                    ProcessStruct {
                        pstate,
                        pmemory,
                        pstack: ManuallyDrop::into_inner(fake_stack),
                        phwcontext : ManuallyDrop::into_inner(fake_phwcontext)
                    }
                )
           )
        );

        // 2: lately create the stack with a link to the ProcessStruct
        let linked_stack = KernelStack::allocate_stack(Arc::downgrade(&p))
            .expect("Couldn't allocate a kernel stack");
        // 3: lately write the stack in the ProcessStruct
        unsafe {
            // safe because dst was uninitialized
            ::core::ptr::write(&mut p.write().pstack, linked_stack);
        }

        // create a hardware context that kickstarts the process
        let phwcontext = ProcessHardwareContext::new(&mut p.write().pstack);
        // lately write the phwcontext in the ProcessStruct
        unsafe {
            // safe because dst was uninitialized
            ::core::ptr::write(&mut p.write().phwcontext, phwcontext);
        }

        // the ProcessStruct is now safe
        let p = ManuallyDrop::into_inner(p);

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
        let mut pstack = KernelStack::get_current_stack();

        // the saved esp will be overwritten on schedule-out anyway
        let phwcontext = ProcessHardwareContext::new(&mut pstack);

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

        // create a link back to the ProcessStruct in its stack
        let link = Arc::downgrade(&p);
        p.write().pstack.link_boot_stack_to_process(link);

        p
    }
}

/// Gets the current ProcessStruct from the Weak link at the base of current stack
/// Must be called when using a valid KernelStack, where the ThreadInfoInStack has been initialized
///
/// # Panics
///
/// Panics if the Weak link in the stack is broken
///
/// # Unsafe
///
/// This function is unsafe when the stack is not a KernelStack, but this should never be the case
/// after boot setup has finished, and making it actually unsafe would be a real pain.
/// See todo in KernelStack::get_kernel_stack()
pub fn get_current_process() -> Arc<RwLock<ProcessStruct>> {
    unsafe {
        // todo this is actually not safe. See doc comment
        KernelStack::get_current_linked_process()
    }.expect("The weak link in current stack points to a dropped ProcessStruct")
}
