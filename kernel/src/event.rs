//! The core event handling primitives of Sunrise.
//!
//! The Sunrise kernel supports a couple sources of events, such as IRQs, timers,
//! userspace-triggered events, and other. It must be possible to await for
//! one or multiple events at the same time.
//!
//! In order to do this, we have the Event trait. It works by (in theory)
//! registering an interest in an event, and putting the current process to
//! sleep (deregistering it from the scheduler). When the event is triggered,
//! the scheduler will wake the process up, allowing it work.

use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use core::fmt::Debug;
use alloc::sync::Arc;
use crate::sync::{SpinLock, SpinLockIRQ};
use alloc::vec::Vec;
use crate::error::{KernelError, UserspaceError};
use crate::process::ThreadStruct;
use crate::scheduler;

use failure::Backtrace;

/// A waitable item.
///
/// There are essentially two kinds of Waitables: user-signaled and IRQ-backed.
/// IRQ-backed waitables are implemented by [IRQEvent], while user-signaled
/// events are implemented by [ReadableEvent].
///
/// It is possible that a raw waitable is not flexible enough though. For
/// instance, if we want to wait for 1 second, it might be necessary to wait on
/// the timer event multiple times. To do this, it is possible to implement our
/// own Waitable, that defers register to the underlying IRQEvent, but adds
/// additional logic to is_signaled. For example:
///
/// ```
/// use sunrise_kernel::event::{IRQEvent, Waitable};
/// use core::sync::atomic::{AtomicUsize, Ordering};
/// struct WaitFor5Ticks(IRQEvent, AtomicUsize);
/// impl Waitable for WaitFor5Ticks {
///     fn is_signaled(&self) -> bool {
///         self.1.compare_and_swap(0, 5, Ordering::SeqCst);
///         if self.0.is_signaled() {
///             if self.1.fetch_sub(1) == 0 {
///                 return true;
///             } else {
///                 return false;
///             }
///         } else {
///             return false;
///         }
///     }
///     fn register(&self) {
///         self.0.register()
///     }
/// }
/// ```
pub trait Waitable: Debug + Send + Sync {
    /// Checks whether the Waitable was signalled.
    ///
    /// If it returns false, the register function will be called again, in order
    /// to get notified of the next wakeup.
    ///
    /// This will likely require to change state - and yet it takes self by value.
    /// the reason for this is that it's possible for multiple threads, and
    /// potentially multiple CPUs, to wait on the same Waitable. Think of servers:
    /// you might want to wait for multiple threads for the arrival of a new socket.
    /// When this happens, **only a single thread should return true**. Make extra
    /// sure your Atomic operations are written properly!
    ///
    /// You'll probably want to check out AtomicUsize::fetch_update to make sure your
    /// atomic update loops are correct.
    fn is_signaled(&self) -> bool;

    /// Register the waitable with the scheduler.
    ///
    /// This should ensure that when the event is (or is likely to be) triggered,
    /// the scheduler puts the Process back in the running Vec. Most implementors
    /// will want to defer this to an IRQEvent. For instance:
    ///
    /// ```
    /// #use sunrise_kernel::event::{IRQEvent, Waitable};
    /// #struct Wait(IRQEvent);
    /// #impl Waitable for WaitFor5Ticks {
    /// #fn is_signaled(&self) -> bool {
    /// #self.0.is_signaled()
    /// #}
    /// fn register(&self) {
    ///     self.0.register()
    /// }
    /// #}
    /// ```
    fn register(&self);
}

/// Waits for an event to occur on one of the given Waitable objects.
pub fn wait<'wait, INTOITER>(waitable_intoiter: INTOITER) -> Result<&'wait dyn Waitable, UserspaceError>
where
    INTOITER: IntoIterator<Item=&'wait dyn Waitable>,
    <INTOITER as IntoIterator>::IntoIter: Clone
{
    let _thread = scheduler::get_current_thread();

    let waitable = waitable_intoiter.into_iter();
    let interrupt_manager = SpinLockIRQ::new(());

    loop {
        // Early-check for events that have already been signaled.
        for item in waitable.clone() {
            if item.is_signaled() {
                return Ok(item);
            }
        }

        // Disable interrupts between registration and unschedule.
        let lock = interrupt_manager.lock();

        // Register the process for wakeup on all the possible events
        for item in waitable.clone() {
            item.register();
        }

        // TODO: check that the current process is registered for an event,
        // bug otherwise.

        // Schedule
        scheduler::unschedule(&interrupt_manager, lock)?;
    }
}

/// The underlying shared object of a [ReadableEvent]/[WritableEvent].
#[derive(Debug)]
struct Event {
    /// The state determines whether the event is signaled or not. When it is true,
    /// the event is signaled, and calls to WaitSynchronization with this event
    /// will immediately return.
    state: AtomicBool,
    /// List of processes waiting on this IRQ. When this IRQ is triggered, all
    /// those processes will be rescheduled.
    waiting_processes: SpinLock<Vec<Arc<ThreadStruct>>>
}

/// Create a new pair of [WritableEvent]/[ReadableEvent].
pub fn new_pair() -> (WritableEvent, ReadableEvent) {
    let event = Arc::new(Event {
        state: AtomicBool::new(false),
        waiting_processes: SpinLock::new(Vec::new())
    });

    (WritableEvent { parent: event.clone() }, ReadableEvent { parent: event })
}

/// The readable part of an event. The user shall use this end to verify if the
/// event is signaled, and wait for the signaling through wait_synchronization.
/// The user can also use this handle to clear the signaled state through
/// [ReadableEvent::clear_signal()].
#[derive(Debug, Clone)]
pub struct ReadableEvent {
    /// Pointer to the shared event representation.
    parent: Arc<Event>
}

impl ReadableEvent {
    /// Clears the signaled state.
    ///
    /// # Errors
    ///
    /// - `InvalidState`
    ///   - The event wasn't signaled.
    pub fn clear_signal(&self) -> Result<(), KernelError> {
        let oldstate = self.parent.state.swap(false, Ordering::SeqCst);
        if !oldstate {
            return Err(KernelError::InvalidState { backtrace: Backtrace::new() })
        }
        Ok(())
    }
}

impl Waitable for ReadableEvent {
    fn is_signaled(&self) -> bool {
        self.parent.state.load(Ordering::SeqCst)
    }
    fn register(&self) {
        self.parent.waiting_processes.lock().push(scheduler::get_current_thread());
    }
}

/// The writable part of an event. The user shall use this end to signal (and
/// wake up threads waiting on the event).
#[derive(Debug, Clone)]
pub struct WritableEvent {
    /// Pointer to the shared event representation.
    parent: Arc<Event>
}

impl WritableEvent {
    /// Signals the event, setting its state to signaled and waking up any
    /// thread waiting on its value.
    pub fn signal(&self) {
        self.parent.state.store(true, Ordering::SeqCst);
        let mut processes = self.parent.waiting_processes.lock();
        while let Some(process) = processes.pop() {
            scheduler::add_to_schedule_queue(process);
        }
    }
    /// Clears the signaled state.
    ///
    /// # Errors
    ///
    /// - `InvalidState`
    ///   - The event wasn't signaled.
    pub fn clear_signal(&self) -> Result<(), KernelError> {
        let oldstate = self.parent.state.swap(false, Ordering::SeqCst);
        if !oldstate {
            return Err(KernelError::InvalidState { backtrace: Backtrace::new() })
        }
        Ok(())
    }
}

/// An event waiting for an IRQ.
///
/// When created, is_signaled is called and the IRQ was triggered, it will
/// increment the ACK count by 1. This means that if multiple IRQs happened
/// between wait calls, it will immediately return true.
// TODO: Allow configuring edge vs level triggering.
#[derive(Debug)]
pub struct IRQEvent {
    /// The global state of the IRQ this event is listening on.
    /// Contains the IRQ trigger count.
    state: &'static IRQState,
    /// Acknowledgement counter for this IRQEvent instance. Each time we get
    /// signaled, this counter is incremented until it matches the counter in
    /// state.
    ack: AtomicUsize,
}

impl Waitable for IRQEvent {
    fn is_signaled(&self) -> bool {
        self.ack.fetch_update(|x| {
            if x < self.state.counter.load(Ordering::SeqCst) {
                // TODO: If level-triggered, set this to the counter.
                Some(x + 1)
            } else {
                None
            }
        }, Ordering::SeqCst, Ordering::SeqCst)

        .is_ok()
    }

    fn register(&self) {
        let curproc = scheduler::get_current_thread();
        let mut veclock = self.state.waiting_processes.lock();
        debug!("Registering {:010x} for irq {}", &*curproc as *const _ as usize, self.state.irqnum);
        if veclock.iter().find(|v| Arc::ptr_eq(&curproc, v)).is_none() {
            veclock.push(scheduler::get_current_thread());
        }
    }
}

/// Signal the scheduler and waiters that an IRQ has been triggered.
///
/// Usually, the IRQ handling code calls this. But it may be used to generate
/// synthetic IRQs.
pub fn dispatch_event(irq: usize) {
    IRQ_STATES[irq].counter.fetch_add(1, Ordering::SeqCst);
    let mut processes = IRQ_STATES[irq].waiting_processes.lock();
    while let Some(process) = processes.pop() {
        scheduler::add_to_schedule_queue(process);
    }
}

/// Creates an IRQEvent waiting for the given IRQ number.
pub fn wait_event(irq: u8) -> IRQEvent {
    debug!("Waiting for {}", irq);
    crate::i386::interrupt::unmask(irq);
    IRQEvent {
        state: &IRQ_STATES[irq as usize], ack: AtomicUsize::new(IRQ_STATES[irq as usize].counter.load(Ordering::SeqCst))
    }
}

/// Global state of an IRQ.
///
/// Counts the number of times this IRQ was triggered from kernel boot.
#[derive(Debug)]
struct IRQState {
    /// The irq number this state represents. Only used for debug logs.
    irqnum: usize,
    /// The number of time this IRQ was triggered from kernel boot.
    counter: AtomicUsize,
    /// List of processes waiting on this IRQ. When this IRQ is triggered, all
    /// those processes will be rescheduled.
    waiting_processes: SpinLockIRQ<Vec<Arc<ThreadStruct>>>
}

impl IRQState {
    /// Create a new IRQState for the given IRQ number, with the counter set to
    /// 0.
    pub const fn new(irqnum: usize) -> IRQState {
        IRQState {
            irqnum,
            counter: AtomicUsize::new(0),
            waiting_processes: SpinLockIRQ::new(Vec::new())
        }
    }
}

/// Global state for all the IRQ handled by the IOAPIC.
static IRQ_STATES: [IRQState; 17] = [
    IRQState::new(0x20), IRQState::new(0x21), IRQState::new(0x22), IRQState::new(0x23),
    IRQState::new(0x24), IRQState::new(0x25), IRQState::new(0x26), IRQState::new(0x27),
    IRQState::new(0x28), IRQState::new(0x29), IRQState::new(0x2A), IRQState::new(0x2B),
    IRQState::new(0x2C), IRQState::new(0x2D), IRQState::new(0x2E), IRQState::new(0x2F),
    IRQState::new(0x30),
];
