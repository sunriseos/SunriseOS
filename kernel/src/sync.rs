//! Synchronization primitives used by KFS

use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};
use spin::{Mutex as SpinMutex, MutexGuard as SpinMutexGuard};
use i386::instructions::interrupts::*;

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
pub struct SpinLock<T: ?Sized> {
    internal: SpinMutex<T>
}

impl<T> SpinLock<T> {
    pub fn new(internal: T) -> SpinLock<T> {
        SpinLock {
            internal: SpinMutex::new(internal)
        }
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Disables interrupts and locks the mutex.
    pub fn lock(&self) -> SpinLockGuard<T> {
        // Save eflags
        let flags = flags();

        // Disable irqs
        unsafe { cli(); }

        // TODO: Disable preemption.
        // TODO: Spin acquire

        // lock
        let internalguard = self.internal.lock();
        SpinLockGuard(flags, ManuallyDrop::new(internalguard))
    }
}


pub struct SpinLockGuard<'a, T: ?Sized + 'a>(u16, ManuallyDrop<SpinMutexGuard<'a, T>>);

impl<'a, T: ?Sized + 'a> Drop for SpinLockGuard<'a, T> {
    fn drop(&mut self) {
        // TODO: Spin release
        // unlock
        unsafe { ManuallyDrop::drop(&mut self.1); }

        // Restore irq
        unsafe { set_flags(self.0); }

        // TODO: Enable preempt
    }
}

impl<'a, T: ?Sized + 'a> Deref for SpinLockGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &*self.1
    }
}

impl<'a, T: ?Sized + 'a> DerefMut for SpinLockGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.1
    }
}
