//! The Completly Unfair Scheduler

use spin::Mutex;
use alloc::sync::Arc;
use spin::RwLock;
use alloc::vec::Vec;

use process::{ProcessStruct, ProcessStructArc, process_switch};
use sync::SpinLock;

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
/// Panics if the process' lock cannot be obtained for writing.
pub fn add_to_schedule_queue(process: ProcessStructArc) {
    let mut queue_lock = {
        // first lock the process, which might schedule if we can't, it's ok
        let mut process_lock = process.write();
        let queue_lock = SCHEDULE_QUEUE.lock();

        use process::ProcessState;
        assert_eq!(process_lock.pstate, ProcessState::Stopped,
                   "Process added to schedule queue was not stopped : {:?}", process_lock.pstate);
        process_lock.pstate = ProcessState::Scheduled;
        queue_lock
        // process' guard is dropped here
    };

    queue_lock.push(process)
}

/// Creates the very first process at boot.
/// The created process is added to the schedule queue.
///
/// # Safety
///
/// Use only for creating the very first process. Should never be used again after that.
/// Must be using a valid KernelStack, a valid ActivePageTables.
///
/// # Panics
///
/// Panics if the schedule queue was not empty
/// ThreadInfoInStack will be initialized, it must not already have been
pub unsafe fn create_first_process() {
    let mut queue = SCHEDULE_QUEUE.lock();
    assert!(queue.is_empty());
    let p0 = ProcessStruct::create_first_process();
    queue.push(p0);
}

/// Performs a process switch.
///
/// # Queue politics
///
///                checking if process is locked
///                =====================>
/// j--------j j--------j j--------j j--------j
/// | current| |    X   | |        | |        |
/// j--------j j--------j j--------j j--------j    A
///    | A       locked,       |                   |
///    | |       skipped       |                   |
///    | +---------------------+                   |
///    +-------------------------------------------+
///
/// 1. Tries to lock the next first process. If it fails to acquire its lock,
///    it is ignored for now, and we move on to the next one.
/// 2. When a candidate is found, it is moved to the start of the queue, and
///    current process is pushed back at the end.
/// 2. Rotates the current process at the end of the queue.
/// 3. Performs the process switch
///  * as new process *
/// 4. Drops the lock to the schedule queue, re-enabling interrupts
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

            // get the processes again
            let current = Arc::clone(queue.last().unwrap());
            let process_b = Arc::clone(queue.first().unwrap());

            // unlock the queue
            drop(queue);

            unsafe {
                // safety: interrupts are off
                // safety: todo we never checked first is actually the current :/
                process_switch(current, process_b);
            }

            /* we were scheduled again */
        }
    }

    // might re-enable the interrupts here !
    drop(interrupt_lock);
}
