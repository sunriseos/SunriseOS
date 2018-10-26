//! The Completly Unfair Scheduler

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;

use process::{ProcessStruct, ProcessState, ProcessStructArc};
use i386::process_switch::process_switch;
use sync::{SpinLockIRQ, SpinLockIRQGuard};
use core::sync::atomic::Ordering;
use error::Error;

/// We always keep an Arc to the process currently running.
/// This enables finding the current process from anywhere,
/// and also prevents dropping the ProcessStruct of the process we're currently running
///
/// # Safety
///
/// Setting this value should be done through set_current_process, otherwise Bad Things:tm:
/// will happen.
// why isn't uninitialized() a const fn !? D:
static mut CURRENT_PROCESS: Option<ProcessStructArc> = None;

pub fn try_get_current_process() -> Option<ProcessStructArc> {
    unsafe {
        // Safe because modifications only happens in the schedule() function,
        // and outside of that function, seen from a process' perspective,
        // CURRENT_PROCESS will always have the same value
        CURRENT_PROCESS.clone()
    }
}

/// Gets the current ProcessStruct.
pub fn get_current_process() -> ProcessStructArc {
    try_get_current_process().unwrap()
}

/// Sets the current ProcessStruct.
///
/// Setting the current process should *always* go through this function, and never
/// by setting CURRENT_PROCESS directly. This function uses mem::replace to ensure
/// that the ProcessStruct's Drop is run with CURRENT_PROCESS set to the *new* value.
unsafe fn set_current_process(p: ProcessStructArc) {
    mem::replace(&mut CURRENT_PROCESS, Some(p.clone()));

    p.pstate.compare_and_swap(ProcessState::Scheduled, ProcessState::Running, Ordering::SeqCst);
}

/// The schedule queue
///
/// It's a simple vec, acting as a round-robin, first element is the running process.
/// When its time slice has ended, it is rotated to the end of the vec, and we go on to the next one.
///
/// The vec is protected by a SpinLockIRQ, so accessing/modifying it disables irqs.
/// Since there's no SMP, this should guarantee we cannot deadlock in the scheduler.
static SCHEDULE_QUEUE: SpinLockIRQ<Vec<ProcessStructArc>> = SpinLockIRQ::new(Vec::new());

/// Adds a process at the end of the schedule queue, and changes its state to 'scheduled'
/// Process must be ready to be scheduled.
///
/// Note that if the lock protecting process was not available, this function might schedule
///
/// If the process was already scheduled, this function is a Noop.
///
/// # Panics
///
/// Panics if the process' state was already "Scheduled"
pub fn add_to_schedule_queue(process: ProcessStructArc) {
    // todo maybe delete this assert, it adds a lot of overhead
    //assert!(!is_in_schedule_queue(&process),
    //        "Process was already in schedule queue : {:?}", process);

    if is_in_schedule_queue(&process) {
        return;
    }

    let mut queue_lock = {
        let queue_lock = SCHEDULE_QUEUE.lock();
        use process::ProcessState;
        let mut oldstate = process.pstate.compare_and_swap(ProcessState::Stopped, ProcessState::Scheduled, Ordering::SeqCst);
        assert_eq!(oldstate, ProcessState::Stopped,
                   "Process added to schedule queue was not stopped : {:?}", oldstate);
        // TODO: Check ProcessState is Scheduled (was Stopped) or Killed
        queue_lock
        // process' guard is dropped here
    };

    queue_lock.push(process)
}

/// Checks if a process is in the schedule queue
pub fn is_in_schedule_queue(process: &ProcessStructArc) -> bool {
    let queue = SCHEDULE_QUEUE.lock();
    unsafe { CURRENT_PROCESS.iter() }.filter(|v| {
        v.pstate.load(Ordering::SeqCst) != ProcessState::Stopped
    }).chain(queue.iter()).any(|elem| Arc::ptr_eq(process, elem))
}

/// Removes the current process from the schedule queue, and schedule.
///
/// The passed lock will be locked until the process is safely removed from the schedule queue.
/// This can be used to avoid race conditions between registering for an event, and unscheduling.
///
/// The current process will not be ran again unless it was registered for rescheduling.
pub fn unschedule<'a>(interrupt_manager: &'a SpinLockIRQ<()>, interrupt_lock: SpinLockIRQGuard<'a, ()>) -> Result<(), Error> {
    {
        let process = get_current_process();
        let old = process.pstate.compare_and_swap(ProcessState::Running, ProcessState::Stopped, Ordering::SeqCst);
        assert!(old == ProcessState::Killed || old == ProcessState::Running, "Old was in invalid state {:?} before unscheduling", old);
    }

    internal_schedule(&interrupt_manager, interrupt_lock, true);

    if get_current_process().pstate.load(Ordering::SeqCst) == ProcessState::Killed {
        Err(Error::Canceled)
    } else {
        Ok(())
    }
}

/// Creates the very first process at boot.
/// The created process is marked as the current process, and added to the schedule queue.
///
/// # Safety
///
/// Use only for creating the very first process. Should never be used again after that.
/// Must be using a valid KernelStack, a valid ActivePageTables.
///
/// # Panics
///
/// Panics if the schedule queue was not empty
pub unsafe fn create_first_process() {
    let mut queue = SCHEDULE_QUEUE.lock();
    assert!(queue.is_empty());
    let p0 = ProcessStruct::create_first_process();
    unsafe {
        // provided we only run this function once, it hasn't been initialized yet
        set_current_process(Arc::clone(&p0));
    }
}

/// Performs a process switch.
///
/// # Queue politics
///
///          checking if process is locked
///          and also not the current one
///          ===============================>
///     j--------j j--------j j--------j j--------j
///     | current| |    X   | |        | |        |
///     j--------j j--------j j--------j j--------j    A
///        | A       locked,       |                   |
///        | |       skipped       |                   |
///        | +---------------------+                   |
///        +-------------------------------------------+
///
/// 1. Tries to lock the next first process. If it fails to acquire its lock,
///    it is ignored for now, and we move on to the next one.
/// 2. When a candidate is found, it is moved to the start of the queue, and
///    current process is pushed back at the end.
/// 3. Rotates the current process at the end of the queue.
/// 4. Performs the process switch
///  * as new process *
/// 5. Drops the lock to the schedule queue, re-enabling interrupts
pub fn schedule() {
    // We use a special SpinLockIRQ to disable the interruptions,
    // We pass it to the internal_schedule, which will drop it if it needs to HLT.
    let interrupt_manager = SpinLockIRQ::new(());
    let interrupt_lock = interrupt_manager.lock();

    internal_schedule(&interrupt_manager, interrupt_lock, false)
}

/// Parses the queue to find the first unlocked process.
/// Returns the index of found process
fn find_next_process_to_run(queue: &Vec<ProcessStructArc>) -> Option<usize> {
    for (index, process) in queue.iter().enumerate() {
        if process.phwcontext.try_lock().is_some() {
            return Some(index)
        }
    }
    None
}

/// Internal impl of the process switch, used by schedule and unschedule.
///
/// See schedule function for documentation on how scheduling works.
fn internal_schedule<'a>(interrupt_manager: &'a SpinLockIRQ<()>, mut interrupt_lock: SpinLockIRQGuard<'a, ()>, remove_self: bool) {
    // TODO: Ensure the global counter is <= 1
    loop {
        let mut queue = SCHEDULE_QUEUE.lock();

        let candidate_index = find_next_process_to_run(&queue);
        match (candidate_index, remove_self) {
            (None, true) => {
                // There's nobody to schedule. Let's drop all the locks, HLT, and run internal_schedule again.
                // NOTE: There's nobody running at this point. :O
                drop(queue);
                // Temporarily revive interrupts for hlt.
                drop(interrupt_lock);
                unsafe {
                    ::i386::instructions::interrupts::hlt();
                }

                // Kill interrupts again.
                interrupt_lock = interrupt_manager.lock();

                // Rerun internal_schedule.
                continue;
            },
            (None, false) => {
                // There's nobody else to run. Let's keep running ourselves...
                drop(queue);
            }
            (Some(index_b), _) => {
                // 1. remove canditate from the queue, pushing remaining of the queue to the front
                let process_b = queue.remove(index_b);

                // 2. push current at the back of the queue, unless we want to unschedule it.
                let proc = get_current_process();
                if !remove_self {
                    queue.push(proc.clone());
                }

                // unlock the queue
                drop(queue);

                let whoami = if !Arc::ptr_eq(&process_b, &proc) {
                    unsafe {
                        // safety: interrupts are off
                        process_switch(process_b, proc)
                    }
                } else {
                    // Avoid process switching if we're just rescheduling ourselves.
                    proc
                };

                /* we were scheduled again */

                // replace CURRENT_PROCESS with ourself.
                // If previously running process had deleted all other references to itself, this
                // is where its drop actually happens
                unsafe { set_current_process(whoami.clone()) };
            }
        }
        break;
    }
}


/// The function called when a process was schedule for the first time,
/// right after the arch-specific process switch was performed.
pub fn scheduler_first_schedule(current_process: ProcessStructArc, entrypoint: usize, stack: usize) {
    // replace CURRENT_PROCESS with ourself.
    // If previously running process had deleted all other references to itself, this
    // is where its drop actually happens
    unsafe { set_current_process(current_process) };

    unsafe {
        // this is a new process, no SpinLockIRQ is held
        ::i386::instructions::interrupts::sti();
    }

    ::i386::process_switch::jump_to_entrypoint(entrypoint, stack)
}
