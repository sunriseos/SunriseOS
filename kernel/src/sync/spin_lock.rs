//! Lock that panics when used in a IRQ context
//!
//! See the [sync] module documentation.
//!
//! [sync]: crate::sync

use core::fmt;

pub use spin::MutexGuard as SpinLockGuard;

/// This type provides mutual exclusion based on spinning.
/// It will panic if used in the context of an interrupt.
///
/// # Description
///
/// The behaviour of these locks is similar to `std::sync::Mutex`. they
/// differ on the following:
///
/// - The lock will not be poisoned in case of failure;
///
/// # Simple examples
///
/// ```
/// use crate::sync::SpinLock;
/// let spin_lock = SpinLock::new(0);
///
/// // Modify the data
/// {
///     let mut data = spin_lock.lock();
///     *data = 2;
/// }
///
/// // Read the data
/// let answer =
/// {
///     let data = spin_lock.lock();
///     *data
/// };
///
/// assert_eq!(answer, 2);
/// ```
///
/// # Thread-safety example
///
/// ```
/// use crate::sync::SpinLock;
/// use std::sync::{Arc, Barrier};
///
/// let numthreads = 1000;
/// let spin_lock = Arc::new(SpinLock::new(0));
///
/// // We use a barrier to ensure the readout happens after all writing
/// let barrier = Arc::new(Barrier::new(numthreads + 1));
///
/// for _ in (0..numthreads)
/// {
///     let my_barrier = barrier.clone();
///     let my_lock = spin_lock.clone();
///     std::thread::spawn(move||
///     {
///         let mut guard = my_lock.lock();
///         *guard += 1;
///
///         // Release the lock to prevent a deadlock
///         drop(guard);
///         my_barrier.wait();
///     });
/// }
///
/// barrier.wait();
///
/// let answer = { *spin_lock.lock() };
/// assert_eq!(answer, numthreads);
/// ```
#[repr(transparent)]
pub struct SpinLock<T: ?Sized>(spin::Mutex<T>);

impl<T> SpinLock<T> {
    /// Creates a new spinlock wrapping the supplied data.
    ///
    /// May be used statically:
    ///
    /// ```
    /// use crate::sync::SpinLock;
    ///
    /// static SPINLOCK: SpinLock<()> = SpinLock::new(());
    ///
    /// fn demo() {
    ///     let lock = SPINLOCK.lock();
    ///     // do something with lock
    ///     drop(lock);
    /// }
    /// ```
    pub const fn new(data: T) -> SpinLock<T> {
        SpinLock(spin::Mutex::new(data))
    }

    /// Consumes this spinlock, returning the underlying data.
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Locks the spinlock and returns a guard.
    ///
    /// The returned value may be dereferenced for data access
    /// and the lock will be dropped when the guard falls out of scope.
    ///
    /// Panics if called in an interrupt context.
    ///
    /// ```
    /// let mylock = crate::sync::SpinLock::new(0);
    /// {
    ///     let mut data = mylock.lock();
    ///     // The lock is now locked and the data can be accessed
    ///     *data += 1;
    ///     // The lock is implicitly dropped
    /// }
    ///
    /// ```
    pub fn lock(&self) -> SpinLockGuard<T> {
        use core::sync::atomic::Ordering;
        use crate::cpu_locals::ARE_CPU_LOCALS_INITIALIZED_YET;
        use crate::i386::interrupt_service_routines::INSIDE_INTERRUPT_COUNT;
        use super::INTERRUPT_DISARM;
        if !INTERRUPT_DISARM.load(Ordering::SeqCst) && ARE_CPU_LOCALS_INITIALIZED_YET.load(Ordering::SeqCst) && INSIDE_INTERRUPT_COUNT.load(Ordering::SeqCst) != 0 {
            panic!("\
                You have attempted to lock a spinlock in interrupt context. \
                This is most likely a design flaw. \
                See documentation of the sync module.");
        }
        self.0.lock()
    }

    /// Force unlock the spinlock. If the lock isn't held, this is a no-op.
    ///
    /// # Safety
    ///
    /// This is *extremely* unsafe if the lock is not held by the current
    /// thread. However, this can be useful in some instances for exposing the
    /// lock to FFI that doesn't know how to deal with RAII.
    pub unsafe fn force_unlock(&self) {
        self.0.force_unlock()
    }

    /// Tries to lock the spinlock. If it is already locked, it will return None. Otherwise it returns
    /// a guard within Some.
    pub fn try_lock(&self) -> Option<SpinLockGuard<T>> {
        use core::sync::atomic::Ordering;
        if crate::i386::interrupt_service_routines::INSIDE_INTERRUPT_COUNT.load(Ordering::SeqCst) != 0 {
            panic!("\
                You have attempted to lock a spinlock in interrupt context. \
                This is most likely a design flaw. \
                See documentation of the sync module.");
        }
        self.0.try_lock()
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: ?Sized + Default> Default for SpinLock<T> {
    fn default() -> SpinLock<T> {
        Self::new(Default::default())
    }
}
