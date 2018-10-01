//! The Completly Unfair Scheduler

use spin::Mutex;
use alloc::sync::Arc;
use spin::RwLock;
use alloc::vec::Vec;

use process::{ProcessStruct, ProcessStructArc};
use i386::process_switch::process_switch;
use sync::SpinLock;

/// We always keep an Arc to the process currently running.
/// This enables finding the current process from anywhere,
/// and also prevents dropping the ProcessStruct of the process we're currently running
// why isn't uninitialized() a const fn !? D:
static mut CURRENT_PROCESS: Option<ProcessStructArc> = None;

/// Gets the current ProcessStruct.
pub fn get_current_process() -> ProcessStructArc {
    unsafe {
        // Safe because modifications only happens in the schedule() function,
        // and outside of that function, seen from a process' perspective,
        // CURRENT_PROCESS will always have the same value
        Arc::clone(CURRENT_PROCESS.as_ref().unwrap())
    }
}

/// The schedule queue
///
/// It's a simple vec, acting as a round-robin, first element is the running process.
/// When its time slice has ended, it is rotated to the end of the vec, and we go on to the next one.
///
/// The vec is protected by a SpinLock, so accessing/modifying it disables irqs.
/// Since there's no SMP, this should guarantee we cannot deadlock in the scheduler.
static SCHEDULE_QUEUE: SpinLock<Vec<ProcessStructArc>> = SpinLock::new(Vec::new());

/// Adds a process at the end of the schedule queue, and changes its state to 'scheduled'
/// Process must be ready to be scheduled.
///
/// Note that if the lock protecting process was not available, this function might schedule
///
/// # Panics
///
/// Panics if the process was already in the schedule queue
/// Panics if the process' state was already "Scheduled"
pub fn add_to_schedule_queue(process: ProcessStructArc) {
    let mut queue_lock = {
        // first lock the process, which might schedule if we can't, it's ok
        let mut process_lock = process.write();
        let queue_lock = SCHEDULE_QUEUE.lock();

        // todo maybe delete this assert, it adds a lot of overhead
        assert!(!is_in_schedule_queue(&process),
                    "Process was already in schedule queue : {:?}", process);

        use process::ProcessState;
        assert_eq!(process_lock.pstate, ProcessState::Stopped,
                   "Process added to schedule queue was not stopped : {:?}", process_lock.pstate);

        process_lock.pstate = ProcessState::Scheduled;
        queue_lock
        // process' guard is dropped here
    };

    queue_lock.push(process)
}

/// Checks if a process is in the schedule queue
pub fn is_in_schedule_queue(process: &ProcessStructArc) -> bool {
    let queue = SCHEDULE_QUEUE.lock();
    queue.iter().any(|elem| Arc::ptr_eq(process, elem))
}

/// Removes a process from the schedule queue.
// todo /// Changes its state to "Stopped", except if it was "Running",
//      /// in which case it stays "Running" until its next schedule().
//      ... but this requires locking the ProcessStruct, and i hate this.
//          Failing to lock means deadlocking since we hold the queue's lock
///
/// Returns the ProcessStructArc that was stored in the queue, or None if it was not found.
pub fn unschedule(process: &ProcessStructArc) -> Option<ProcessStructArc> {
    let mut queue = SCHEDULE_QUEUE.lock();
    queue.iter().position(|elem| Arc::ptr_eq(process, elem))
        .map(|index|
            queue.remove(index)
        )
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
        CURRENT_PROCESS = Some(Arc::clone(&p0));
    }
    queue.push(p0);
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

    /// Parses the queue to find the first unlocked process.
    /// Returns the index of found process
    fn find_next_process_to_run(queue: &Vec<ProcessStructArc>) -> Option<usize> {
        // every process except the first one (current)
        for (index, process) in queue.iter().enumerate().skip(1) {
            if process.try_write().is_some() {
                return Some(index)
            }
        }
        None
    }

    // We use a special SpinLock to disable the interruptions,
    // which we drop only at the end of the function.
    // We need it because we need to unlock the queue's spinlock before process switching
    let mut interrupt_manager = SpinLock::new(());
    let interrupt_lock = interrupt_manager.lock();

    let mut queue = SCHEDULE_QUEUE.lock();

    let candidate_index = find_next_process_to_run(&queue);
    match candidate_index {
        None => { /* just return, we didn't schedule */ }
        Some(index_b) => {
            // 1. remove canditate from the queue, pushing remaining of the queue to the front
            let process_b = queue.remove(index_b);

            // 2. place it at the front of the queue, and remove current at the same time
            let current = ::core::mem::replace(&mut queue[0], process_b);

            // 3. push current at the back of the queue
            queue.push(current);

            // get the process again
            let process_b = Arc::clone(queue.first().unwrap());

            // unlock the queue
            drop(queue);

            let whoami = unsafe {
                // safety: interrupts are off
                process_switch(process_b)
            };

            /* we were scheduled again */

            // replace CURRENT_PROCESS with ourself.
            // If previously running process had deleted all other references to itself, this
            // is where its drop actually happens
            unsafe { CURRENT_PROCESS = Some(whoami) };
        }
    }

    // might re-enable the interrupts here !
    drop(interrupt_lock);
}


/// The function called when a process was schedule for the first time,
/// right after the arch-specific process switch was performed.
pub fn scheduler_fisrt_schedule(current_process: ProcessStructArc) {
    // replace CURRENT_PROCESS with ourself.
    // If previously running process had deleted all other references to itself, this
    // is where its drop actually happens
    unsafe { CURRENT_PROCESS = Some(current_process) };

    unsafe {
        // this is a new process, no SpinLock is held
        ::i386::instructions::interrupts::sti();
    }

    info!("Process switched to a new process");
    loop {
        // just do something for a while
        for i in 0..20 {
            info!("i: {}", i);
        }
        // and re-schedule
        schedule();
    }
}
