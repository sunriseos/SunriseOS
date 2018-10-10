//! Synchronization primitives used by KFS

use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use spin::{Mutex as SpinMutex, MutexGuard as SpinMutexGuard};
use i386::instructions::interrupts::*;
use core::sync::atomic::Ordering;
use scheduler;

/// Decrement the interrupt disable counter.
///
/// Look at documentation for ProcessStruct::pint_disable_counter to know more.
fn enable_interrupts() {
    if let Some(proc) = scheduler::try_get_current_process() {
        if proc.pint_disable_counter.fetch_sub(1, Ordering::SeqCst) == 1 {
            unsafe { sti() }
        }
    } else {
        // TODO: Safety???
        // don't do anything.
    }
}

/// Increment the interrupt disable counter.
///
/// Look at documentation for INTERRUPT_DISABLE_COUNTER to know more.
fn disable_interrupts() {
    if let Some(proc) = scheduler::try_get_current_process() {
        if proc.pint_disable_counter.fetch_add(1, Ordering::SeqCst) == 0 {
            unsafe { cli() }
        }
    } else {
        // TODO: Safety???
        // don't do anything.
    }
}

/// Simple SpinLock.
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
#[derive(Debug)]
pub struct SpinLock<T: ?Sized> {
    internal: SpinMutex<T>
}

impl<T> SpinLock<T> {
    pub const fn new(internal: T) -> SpinLock<T> {
        SpinLock {
            internal: SpinMutex::new(internal)
        }
    }

    /// Consumes this SpinLock, returning the underlying data.
    pub fn into_inner(self) -> T {
        self.internal.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Disables interrupts and locks the mutex.
    pub fn lock(&self) -> SpinLockGuard<T> {
        // Disable irqs
        unsafe { disable_interrupts(); }

        // TODO: Disable preemption.
        // TODO: Spin acquire

        // lock
        let internalguard = self.internal.lock();
        SpinLockGuard(ManuallyDrop::new(internalguard))
    }

    /// Disables interrupts and locks the mutex.
    pub fn try_lock(&self) -> Option<SpinLockGuard<T>> {
        // Disable irqs
        unsafe { disable_interrupts(); }

        // TODO: Disable preemption.
        // TODO: Spin acquire

        // lock
        match self.internal.try_lock() {
            Some(internalguard) => Some(SpinLockGuard(ManuallyDrop::new(internalguard))),
            None => {
                // We couldn't lock. Restore irqs and return None
                unsafe { enable_interrupts(); }
                None
            }
        }
    }

    pub unsafe fn force_unlock(&self) {
        self.internal.force_unlock()
    }
}


#[derive(Debug)]
pub struct SpinLockGuard<'a, T: ?Sized + 'a>(ManuallyDrop<SpinMutexGuard<'a, T>>);

impl<'a, T: ?Sized + 'a> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // TODO: Spin release
        // unlock
        unsafe { ManuallyDrop::drop(&mut self.0); }

        // Restore irq
        unsafe { enable_interrupts(); }

        // TODO: Enable preempt
    }
}

impl<'a, T: ?Sized + 'a> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &*self.0
    }
}

impl<'a, T: ?Sized + 'a> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.0
    }
}
