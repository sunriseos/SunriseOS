//! Synchronization primitives used by KFS

use spin;

pub use self::spin::{Once, RwLock, RwLockReadGuard, RwLockWriteGuard};

use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
pub use self::spin::{Mutex as SpinLock, MutexGuard as SpinLockGuard};
use crate::i386::instructions::interrupts::*;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::scheduler;

/// Placeholder for future Mutex implementation.
pub type Mutex<T> = SpinLock<T>;
/// Placeholder for future Mutex implementation.
pub type MutexGuard<'a, T> = SpinLockGuard<'a, T>;

/// Decrement the interrupt disable counter.
///
/// Look at documentation for ProcessStruct::pint_disable_counter to know more.
fn enable_interrupts() {
    if !INTERRUPT_DISARM.load(Ordering::SeqCst) {
        if let Some(thread) = scheduler::try_get_current_thread() {
            if thread.int_disable_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
                unsafe { sti() }
            }
        } else {
            // TODO: Safety???
            // don't do anything.
        }
    }
}

/// Increment the interrupt disable counter.
///
/// Look at documentation for INTERRUPT_DISABLE_COUNTER to know more.
fn disable_interrupts() {
    if !INTERRUPT_DISARM.load(Ordering::SeqCst) {
        if let Some(thread) = scheduler::try_get_current_thread() {
            if thread.int_disable_counter.fetch_add(1, Ordering::SeqCst) == 0 {
                unsafe { cli() }
            }
        } else {
            // TODO: Safety???
            // don't do anything.
        }
    }
}

/// Boolean to [permanently_disable_interrupts].
///
/// If this bool is set, all [enable_interrupts] and [disable_interrupts] calls are ignored,
/// and system is put in an unrecoverable state.
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
    unsafe { cli() }
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
/// This means that locking a spinlock disables interrupts until all spinlocks
/// have been dropped.
///
/// Note that it is allowed to lock/unlock the locks in a different order. It uses
/// a global counter to disable/enable interrupts. View INTERRUPT_DISABLE_COUNTER
/// documentation for more information.
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
    pub fn lock(&self) -> SpinLockIRQGuard<'_, T> {
        // Disable irqs
        unsafe { disable_interrupts(); }

        // TODO: Disable preemption.
        // TODO: Spin acquire

        // lock
        let internalguard = self.internal.lock();
        SpinLockIRQGuard(ManuallyDrop::new(internalguard))
    }

    /// Disables interrupts and locks the mutex.
    pub fn try_lock(&self) -> Option<SpinLockIRQGuard<'_, T>> {
        // Disable irqs
        unsafe { disable_interrupts(); }

        // TODO: Disable preemption.
        // TODO: Spin acquire

        // lock
        match self.internal.try_lock() {
            Some(internalguard) => Some(SpinLockIRQGuard(ManuallyDrop::new(internalguard))),
            None => {
                // We couldn't lock. Restore irqs and return None
                unsafe { enable_interrupts(); }
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
        match self.try_lock() {
            Some(d) => {
                write!(f, "SpinLockIRQ {{ data: ")?;
                d.fmt(f)?;
                write!(f, "}}")
            },
            None => write!(f, "SpinLockIRQ {{ <locked> }}")
        }
    }
}

/// The SpinLockIrq lock guard.
#[derive(Debug)]
pub struct SpinLockIRQGuard<'a, T: ?Sized>(ManuallyDrop<SpinLockGuard<'a, T>>);

impl<'a, T: ?Sized + 'a> Drop for SpinLockIRQGuard<'a, T> {
    fn drop(&mut self) {
        // TODO: Spin release
        // unlock
        unsafe { ManuallyDrop::drop(&mut self.0); }

        // Restore irq
        unsafe { enable_interrupts(); }

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
