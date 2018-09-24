//! The core event handling primitives of KFS.
//!
//! The KFS kernel sports a couple sources of events, such as IRQs, timers,
//! userspace-triggered events, and other. It must be possible to await for
//! one or multiple events at the same time.
//!
//! In order to do this, we have the Event trait. It works by (in theory)
//! registering an interest in an event, and putting the current process to
//! sleep (deregistering it from the scheduler). When the event is triggered,
//! the scheduler will wake the process up, allowing it work.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::fmt::Debug;

// TODO: maybe we should use the libcore's task:: stuff...

/// A waitable item.
///
/// There are essentially two kinds of Waitables: user-signaled and IRQ-backed.
/// Right now, only IRQ-backed waitables are implemented. See IRQEvent for more
/// information on them.
///
/// It is possible that the raw IRQEvent is not flexible enough though. For
/// instance, if we want to wait for 1 second, it might be necessary to wait on
/// the timer event multiple times. To do this, it is possible to implement our
/// own Waitable, that defers register to the underlying IRQEvent, but adds
/// additional logic to is_signaled. For example:
///
/// ```
/// use kfs_kernel::event::{IRQEvent, Waitable};
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
pub trait Waitable: Debug {
    /// Checks whether the Waitable was signalled.
    ///
    /// If it returns false, the register function will be called again, in order
    /// to get notified of the next wakeup.
    fn is_signaled(&self) -> bool;

    /// Register the waitable with the scheduler.
    ///
    /// This should ensure that when the event is (or is likely to be) triggered,
    /// the scheduler puts the Process back in the running Vec. Most implementors
    /// will want to defer this to an IRQEvent. For instance:
    ///
    /// ```
    /// #use kfs_kernel::event::{IRQEvent, Waitable};
    /// #struct Wait(IRQEvent);
    /// #impl Waitable for WaitFor5Ticks {
    /// #fn is_signaled(&self) -> bool {
    /// #self.0.is_signaled()
    /// fn register(&self) {
    ///     self.0.register()
    /// }
    /// #}
    /// ```
    fn register(&self);
}

/// A list of waitable objects.
///
/// Allows waiting on multiple Waitables at the same time.
#[derive(Debug)]
pub struct MultiWaiter<'WAIT> {
    waitable: &'WAIT [&'WAIT Waitable]
}

impl<'WAIT> MultiWaiter<'WAIT> {
    pub fn new(arr: &'WAIT [&'WAIT Waitable]) -> MultiWaiter<'WAIT> {
        MultiWaiter {
            waitable: arr
        }
    }

    pub fn wait(waiter: &[&Waitable]) -> &'WAIT Waitable {
        loop {
            // Early-check for events that have already been signaled.
            for item in self.waitable {
                if item.is_signaled() {
                    return *item;
                }
            }

            // Register the process for wakeup on all the possible events
            for item in self.waitable {
                item.register();
            }

            // Schedule
            unsafe { asm!("HLT" : : : : "volatile"); }
        }
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
    counter: &'static AtomicUsize,
    ack: AtomicUsize,
}

impl Waitable for IRQEvent {
    fn is_signaled(&self) -> bool {
        if self.ack.fetch_update(|x| {
            if x < self.counter.load(Ordering::SeqCst) {
                // TODO: If level-triggered, set this to the counter.
                Some(x + 1)
            } else {
                None
            }
        }, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            true
        } else {
            false
        }
    }

    fn register(&self) {
        // TODO: Add process to wait queue.
    }
}

/// Signal the scheduler and waiters that an IRQ has been triggered.
///
/// Usually, the IRQ handling code calls this. But it may be used to generate
/// synthetic IRQs.
pub fn dispatch_event(irq: usize) {
    IRQ_COUNTERS[irq].fetch_add(1, Ordering::SeqCst);
    // TODO: Wake up all the processes waiting on this event.
}

/// Creates an IRQEvent waiting for the given IRQ number.
pub fn wait_event(irq: usize) -> IRQEvent {
    IRQEvent {
        counter: &IRQ_COUNTERS[irq], ack: AtomicUsize::new(IRQ_COUNTERS[irq].load(Ordering::SeqCst))
    }
}

static IRQ_COUNTERS: [AtomicUsize; 16] = [
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
    AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0),
];
