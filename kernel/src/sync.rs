//! Synchronization primitives used by KFS

use spin;

pub use self::spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
pub use self::spin::{Mutex as SpinLock, MutexGuard as SpinLockGuard};
use crate::i386::instructions::interrupts;
use core::sync::atomic::{AtomicBool, Ordering};

/// Placeholder for future Mutex implementation.
pub type Mutex<T> = SpinLock<T>;
/// Placeholder for future Mutex implementation.
pub type MutexGuard<'a, T> = SpinLockGuard<'a, T>;

/// Boolean to [permanently_disable_interrupts].
///
/// If this bool is set, all attempts to enable interrupts through a SpinLockIRQ
/// are ignored, leaving the system in an unrecoverable state.
///
/// This is used by kernel panic handlers.
static INTERRUPT_DISARM: AtomicBool = AtomicBool::new(false);

/// Permanently disables the interrupts. Forever.
///
/// Only used by the panic handlers!
///
/// Simply sets [INTERRUPT_DISARM].
pub unsafe fn permanently_disable_interrupts() {
    INTERRUPT_DISARM.store(true, Ordering::SeqCst);
    unsafe { interrupts::cli() }
}

/// SpinLock that disables IRQ.
///
/// # Description
///
/// This type behaves like a spinlock from the Linux crate. For simplicity of
/// use and implementation. The mapping is as follows:
///
/// - `lock` behaves like a `spinlock_irqsave`. It returns a guard.
/// - Dropping the guard behaves like `spinlock_irqrestore`
///
/// This means that locking a spinlock disables interrupts until all spinlock
/// guards have been dropped.
///
/// A note on reordering: reordering lock drops is prohibited and doing so will
/// result in UB.
//
// TODO: Find sane design for SpinLockIRQ safety
// BODY: Currently, SpinLockIRQ API is unsound. If the guards are dropped in
// BODY: the wrong order, it may cause IF to be reset too early.
// BODY:
// BODY: Ideally, we would need a way to prevent the guard variable to be
// BODY: reassigned. AKA: prevent moving. Note that this is different from what
// BODY: the Pin API solves. The Pin API is about locking a variable in one
// BODY: memory location, but its binding may still be moved and dropped.
// BODY: Unfortunately, Rust does not have a way to express that a value cannot
// BODY: be reassigned.
// BODY:
// BODY: Another possibility would be to switch to a callback API. This would
// BODY: solve the problem, but the scheduler would be unable to consume such
// BODY: locks. Maybe we could have an unsafe "scheduler_relock" function that
// BODY: may only be called from the scheduler?
pub struct SpinLockIRQ<T: ?Sized> {
    /// SpinLock we wrap.
    internal: SpinLock<T>
}

impl<T> SpinLockIRQ<T> {
    /// Creates a new spinlockirq wrapping the supplied data.
    pub const fn new(internal: T) -> SpinLockIRQ<T> {
        SpinLockIRQ {
            internal: SpinLock::new(internal)
        }
    }

    /// Consumes this SpinLockIRQ, returning the underlying data.
    pub fn into_inner(self) -> T {
        self.internal.into_inner()
    }
}

impl<T: ?Sized> SpinLockIRQ<T> {
    /// Disables interrupts and locks the mutex.
    pub fn lock(&self) -> SpinLockIRQGuard<T> {
        if INTERRUPT_DISARM.load(Ordering::SeqCst) {
            let internalguard = self.internal.lock();
            SpinLockIRQGuard(ManuallyDrop::new(internalguard), false)
        } else {
            // Save current interrupt state.
            let saved_intpt_flag = interrupts::are_enabled();

            // Disable interruptions
            unsafe { interrupts::cli(); }

            let internalguard = self.internal.lock();
            SpinLockIRQGuard(ManuallyDrop::new(internalguard), saved_intpt_flag)
        }
    }

    /// Disables interrupts and locks the mutex.
    pub fn try_lock(&self) -> Option<SpinLockIRQGuard<T>> {
        if INTERRUPT_DISARM.load(Ordering::SeqCst) {
            self.internal.try_lock()
                .map(|v| SpinLockIRQGuard(ManuallyDrop::new(v), false))
        } else {
            // Save current interrupt state.
            let saved_intpt_flag = interrupts::are_enabled();

            // Disable interruptions
            unsafe { interrupts::cli(); }

            // Lock spinlock
            let internalguard = self.internal.try_lock();

            if let Some(internalguard) = internalguard {
                // if lock is successful, return guard.
                Some(SpinLockIRQGuard(ManuallyDrop::new(internalguard), saved_intpt_flag))
            } else {
                // Else, restore interrupt state
                if saved_intpt_flag {
                    unsafe { interrupts::sti(); }
                }
                None
            }
        }
    }

    /// Force unlocks the lock.
    pub unsafe fn force_unlock(&self) {
        self.internal.force_unlock()
    }
}

impl<T: fmt::Debug> fmt::Debug for SpinLockIRQ<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(v) = self.try_lock() {
            f.debug_struct("SpinLockIRQ")
                .field("data", &v)
                .finish()
        } else {
            write!(f, "SpinLockIRQ {{ <locked> }}")
        }
    }
}


/// The SpinLockIrq lock guard.
#[derive(Debug)]
pub struct SpinLockIRQGuard<'a, T: ?Sized>(ManuallyDrop<SpinLockGuard<'a, T>>, bool);

impl<'a, T: ?Sized + 'a> Drop for SpinLockIRQGuard<'a, T> {
    fn drop(&mut self) {
        // TODO: Spin release
        // unlock
        unsafe { ManuallyDrop::drop(&mut self.0); }

        // Restore irq
        if self.1 {
            unsafe { interrupts::sti(); }
        }

        // TODO: Enable preempt
    }
}

impl<'a, T: ?Sized + 'a> Deref for SpinLockIRQGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &*self.0
    }
}

impl<'a, T: ?Sized + 'a> DerefMut for SpinLockIRQGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.0
    }
}

/// Abstraction around various kind of locks.
///
/// Some functions need to take a Lock and/or a LockGuard as argument, but don't
/// really care about the kind of lock (schedule comes to mind). This trait is
/// a simple abstraction around this concept.
pub trait Lock<'a, GUARD: 'a> {
    /// Locks the lock until the returned guard is dropped. The actual semantics
    /// is up to the underlying lock. This trait does not make **any** guarantee
    /// about anything like memory ordering or whatnot. Please read the
    /// documentation of the underlying lock type.
    fn lock(&'a self) -> GUARD;
}

impl<'a, T> Lock<'a, SpinLockGuard<'a, T>> for SpinLock<T> {
    fn lock(&self) -> SpinLockGuard<'_, T> {
        self.lock()
    }
}

impl<'a, T> Lock<'a, SpinLockIRQGuard<'a, T>> for SpinLockIRQ<T> {
    fn lock(&self) -> SpinLockIRQGuard<'_, T> {
        self.lock()
    }
}

impl<'a, T> Lock<'a, RwLockReadGuard<'a, T>> for RwLock<T> {
    fn lock(&self) -> RwLockReadGuard<'_, T> {
        self.read()
    }
}

impl<'a, T> Lock<'a, RwLockWriteGuard<'a, T>> for RwLock<T> {
    fn lock(&self) -> RwLockWriteGuard<'_, T> {
        self.write()
    }
}
