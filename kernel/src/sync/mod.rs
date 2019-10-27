//! Synchronization primitives used by the kernel
//!
//! In Sunrise kernel we provide different families of locks, that differ on their strategy when
//! the lock cannot be obtained immediately, and how they deal with IRQs when the lock is held.
//!
//! # spin locks
//!
//! [SpinLock], [SpinRwLock], and [Once] are just dumb busy-loop locks.
//! When calling `lock`, they will check if the lock is available and return, and otherwise busy-loop
//! until it is available.
//!
//! These are just the types provided by the spin crate, renamed to reduce ambiguities.
//!
//! Because they are blocking and non-preemptive, they can't be used for long exclusive tasks without
//! badly hurting performance for waiters.
//! However they fit really well for really short tasks, where preempting would cause too much overhead,
//! and because they're so dumb, they can be used pretty much everywhere, especially where
//! preempting is not possible, as in the scheduler itself, or during early boot.
//!
//! ### Deadlock avoidance
//!
//! Those lock are guaranteed to never deadlock, as long you don't:
//!
//! 1. Preempt while holding the lock.
//!    E.g.: On a single core, kernel thread A takes the lock, preempts to thread B, tries to take
//!    the lock again: that's a deadlock.
//! 2. Try to use the lock both in regular context and interrupt context.
//!    E.g.: On a single core, kernel thread A takes the lock, is interrupted,
//!    IRQ handler tries to take the lock: that's a deadlock.
//!
//! Note that you *can* in theory use SpinLocks in interrupt context, as long as you don't
//! try to access it in regular context. This would be useful on multi-core systems to arbitrate
//! access to a resource when two IRQs are run concurrently.
//! But we highly discourage it, as we see no use case for a resource that would be accessed *only*
//! in interrupt context. So, our implementation panics when locked in interrupt context.
//!
//! # SpinLockIRQ
//!
//! [SpinLockIRQ] is a variation of SpinLock, which lifts the restriction on interrupt context access.
//!
//! It still is basically is busy-loop in its essence, but also disables all interrupts on the current core
//! when the lock is held.
//!
//! It fits the same use cases as SpinLock, but because it cannot be interrupted while the lock is
//! held, it can be used to access a resource both in regular and interrupt context.
//!
//! ### Deadlock avoidance
//!
//! Similar to SpinLock, this lock is guaranteed to never deadlock, as long you don't:
//!
//! 1. Preempt while holding the lock.
//!    E.g.: On a single core, kernel thread A takes the lock, preempts to thread B, tries to take
//!    the lock again: that's a deadlock.
//!
//! ### As a interrupt disabler
//!
//! A side-effect of SpinLockIRQs, is that it disables all IRQs for as long as it is held.
//! They often are used in the kernel for this sole purpose.
//!
//! If you create a SpinLockIRQ and wrap no type, i.e. `SpinLockIRQ<()>`, you can control whether
//! interrupts are enabled/disabled simply by locking it and unlocking it.
//!
//! # Mutex
//!
//! [Mutex] is a lock that preempts when it cannot be obtained. Those are the locks you are expected
//! to use when you have to do some long exclusive tasks.
//!
//! However since it uses the scheduler, it cannot be used in early boot.
//!
//! ### Deadlock avoidance
//!
//! Those locks are illegal for interrupt context.
//!
//! However, for every other use case they a lot less constrained compared to SpinLocks.
//! But since they aren't recursive, you still can't lock one while holding it.
//!
//! You *can* preempt while holding such a lock, as long as the scheduler's code doesn't also use it
//! for itself, but this would seem like a bad idea.
//!
//! [SpinLock]: crate::sync::SpinLock
//! [SpinRwLock]: crate::sync::SpinRwLock
//! [Once]: crate::sync::Once
//! [SpinLockIRQ]: crate::sync::SpinLockIRQ
//! [Mutex]: crate::sync::mutex::Mutex

// export spin::Mutex as less ambiguous "SpinLock".
pub use spin::{RwLock as SpinRwLock, RwLockReadGuard as SpinRwLockReadGuard, RwLockWriteGuard as SpinRwLockWriteGuard,
               Once };

pub mod spin_lock_irq;
pub use self::spin_lock_irq::{SpinLockIRQ, SpinLockIRQGuard};

pub mod spin_lock;
pub use self::spin_lock::{SpinLock, SpinLockGuard};

pub mod mutex;
pub use self::mutex::{Mutex, MutexGuard};

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

impl<'a, T> Lock<'a, SpinRwLockReadGuard<'a, T>> for SpinRwLock<T> {
    fn lock(&self) -> SpinRwLockReadGuard<'_, T> {
        self.read()
    }
}

impl<'a, T> Lock<'a, SpinRwLockWriteGuard<'a, T>> for SpinRwLock<T> {
    fn lock(&self) -> SpinRwLockWriteGuard<'_, T> {
        self.write()
    }
}
