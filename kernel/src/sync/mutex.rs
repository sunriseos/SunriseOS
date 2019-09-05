//! Preemptive Mutex
//!
//! # Behaviour
//!
//! Lock that preempts if it cannot be obtained immediately. See the [sync] module.
//!
//! The mutex holds a queue of the waiters, and when unlocking it checks if there is contention,
//! in which case it wakes up the head of the queue by popping it and adding it to the schedule queue.
//!
//! The lock performs additional checks around the owner of the lock, and panics if double-locking
//! is detected.
//!
//! When there is contention and the thread is put to sleep, it is removed from the schedule queue,
//! and an Arc to its [`ThreadStruct`] is put in the waiters queue. This means that the thread will
//! stay alive at least until it is waked up.
//!
//! Most of this module is copy-pasted from std Mutexes, and try to preserve the same structure,
//! while the documentation has been re-written.
//!
//! However we don't implement poisons, as kernel thread panicking while holding a Mutex
//! should simply kernel panic, and abort.
//!
//! # Internal workings
//!
//! The secret about these mutex is that they're just fancy wrappers around a [`SpinLock`].
//!
//! This `SpinLock` protects the queue. When checking for contention, we take the SpinLock,
//! which arbitrates all concurrent operations for us, and then simply check if the queue of waiters
//! is empty.
//!
//! If necessary we add ourselves to the queue, and then both unschedule ourselves and unlock it
//! simultaneously.
//!
//! Unlocking performs pretty much the same operation.
//!
//! [sync]: crate::sync
//! [`ThreadStruct`]: crate::process::ThreadStruct
//! [`SpinLock`]: crate::sync::SpinLock

use super::SpinLock;
use crate::process::ThreadStruct;
use crate::scheduler::{get_current_thread, add_to_schedule_queue, unschedule};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::marker::PhantomData;

/// A type alias for the result of a nonblocking locking method.
pub type TryLockResult<Guard> = Result<Guard, ()>;


/// A mutual exclusion primitive useful for protecting shared data
///
/// This mutex will block kernel threads waiting for the lock to become available. The
/// mutex can also be statically initialized or created via a [`new`]
/// constructor. Each mutex has a type parameter which represents the data that
/// it is protecting. The data can only be accessed through the RAII guards
/// returned from [`lock`] and [`try_lock`], which guarantees that the data is only
/// ever accessed when the mutex is locked.
///
/// [`new`]: Mutex::new
/// [`lock`]: Mutex::lock
/// [`try_lock`]: Mutex::try_lock
pub struct Mutex<T> {
    /// The data that we're protecting.
    ///
    /// Std Mutex boxes the data so it is Pin. We don't care for that in the kernel.
    /// However this adds a bound for T: Sized.
    data: UnsafeCell<T>,
    /// The struct responsible for arbitrating accesses to `.data`.
    inner: MutexInner,
}

unsafe impl<T: Send> Send for Mutex<T> { }
unsafe impl<T: Send> Sync for Mutex<T> { }

/// The type responsible of actually performing the locking of the mutex.
///
/// Just a `SpinLock<`[`MutexInnerInner`]`>>`.
///
/// This might seem a bit weird to have an intermediate a struct just for that,
/// but it is to stay as close as possible to std's Mutex design, so we can copy-paste it with ease.
struct MutexInner {
    /// A spin lock arbitrating accesses to the mutex's state.
    spin_lock: SpinLock<MutexInnerInner>
}


/// The bookkeeping of a Mutex. Knows the current owner, and holds the waiters queue.
struct MutexInnerInner {
    /// The owner of this Mutex. None means free.
    ///
    /// We represent the owner as a pointer to its ThreadStruct.
    owner: Option<usize>,
    /// Queue of threads waiting on this mutex.
    waiters: Vec<Arc<ThreadStruct>>
}

/// An RAII implementation of a "scoped lock" of a mutex. When this structure is
/// dropped (falls out of scope), the lock will be unlocked.
///
/// The data protected by the mutex can be accessed through this guard via its
/// [`Deref`] and [`DerefMut`] implementations.
///
/// This structure is created by the [`lock`] and [`try_lock`] methods on
/// [`Mutex`].
///
/// [`Deref`]: core::ops::Deref
/// [`DerefMut`]: core::ops::DerefMut
/// [`lock`]: Mutex::lock
/// [`try_lock`]: Mutex::try_lock
#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: 'a> {
    /// Reference to the Mutex we'll unlock when dropped.
    __lock: &'a Mutex<T>,
    /// Raw pointer just to make MutexGuard !Send.
    __phantom: PhantomData<*mut ()>
}

unsafe impl<T: Sync> Sync for MutexGuard<'_, T> { }

/* ****************************************** MUTEX ********************************************* */

// copied from std, removed poison and some std specific doc tests //

impl<T> Mutex<T> {
    /// Creates a new mutex in an unlocked state ready for use.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::sync::Mutex;
    ///
    /// let mutex = Mutex::new(0);
    /// ```
    pub const fn new(t: T) -> Mutex<T> {
        Self {
            data: UnsafeCell::new(t),
            inner: MutexInner {
                spin_lock: SpinLock::new(MutexInnerInner {
                    owner: None,
                    waiters: Vec::new()
                })
            }
        }
    }

    /// Consumes this mutex, returning the underlying data.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Mutex;
    ///
    /// let mutex = Mutex::new(0);
    /// assert_eq!(mutex.into_inner().unwrap(), 0);
    /// ```
    pub fn into_inner(self) -> T {
        // We know statically that there are no outstanding references to
        // `self` so there's no need to lock the inner mutex.
        self.data.into_inner()
    }

    /// Acquires a mutex, blocking the current kernel thread until it is able to do so.
    ///
    /// This function will block the local kernel thread until it is available to acquire
    /// the mutex. Upon returning, the thread is the only thread with the lock
    /// held. An RAII guard is returned to allow scoped unlock of the lock. When
    /// the guard goes out of scope, the mutex will be unlocked.
    ///
    /// # Panics
    ///
    /// This function panics when called if the lock is already held by
    /// the current thread.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        unsafe {
            self.inner.raw_lock();
            MutexGuard::new(self)
        }
    }

    /// Attempts to acquire this lock.
    ///
    /// If the lock could not be acquired at this time, then [`Err`] is returned.
    /// Otherwise, an RAII guard is returned. The lock will be unlocked when the
    /// guard is dropped.
    ///
    /// This function does not preempt.
    ///
    /// Note however that it still needs to lock the internal [`SpinLock`], and might temporarily
    /// be blocking.
    ///
    /// # Double locking
    ///
    /// Unlike [`lock`], this function will not panic if we already are the holder of this mutex,
    /// and simply return [`Err`] instead.
    ///
    /// This makes it suitable for the kernel panic handler for example, where we want to acquire
    /// locks to resources possibly already held by the current thread, without panicking once more.
    pub fn try_lock(&self) -> TryLockResult<MutexGuard<'_, T>> {
        unsafe {
            if self.inner.try_lock() {
                Ok(MutexGuard::new(self))
            } else {
                Err(())
            }
        }
    }

    /// Returns a mutable reference to the underlying data.
    ///
    /// Since this call borrows the `Mutex` mutably, no actual locking needs to
    /// take place -- the mutable borrow statically guarantees no locks exist.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Mutex;
    ///
    /// let mut mutex = Mutex::new(0);
    /// *mutex.get_mut().unwrap() = 10;
    /// assert_eq!(*mutex.lock().unwrap(), 10);
    /// ```
    pub fn get_mut(&mut self) -> &mut T {
        unsafe {
            // safe:
            // We know statically that there are no other references to `self`, so
            // there's no need to lock the inner mutex.
            &mut *self.data.get()
        }
    }
}

impl<T> From<T> for Mutex<T> {
    /// Creates a new mutex in an unlocked state ready for use.
    /// This is equivalent to [`Mutex::new`].
    ///
    /// [`Mutex::new`]: ../../std/sync/struct.Mutex.html#method.new
    fn from(t: T) -> Self {
        Mutex::new(t)
    }
}

impl<T: Default> Default for Mutex<T> {
    /// Creates a `Mutex<T>`, with the `Default` value for T.
    fn default() -> Mutex<T> {
        Mutex::new(Default::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Ok(guard) => f.debug_struct("Mutex").field("data", &&*guard).finish(),
            Err(()) => {
                /// Struct displayed as `<locked>`.
                struct LockedPlaceholder;
                impl fmt::Debug for LockedPlaceholder {
                    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("<locked>")
                    }
                }

                f.debug_struct("Mutex").field("data", &LockedPlaceholder).finish()
            }
        }
    }
}

/* *************************************** MUTEX GUARD ****************************************** */

// copied from std, no edits //
impl<'mutex, T> MutexGuard<'mutex, T> {
    /// Create an MutexGuard.
    ///
    /// # Safety
    ///
    /// Must only be called once we are ensured we are holing the lock,
    /// as it will unlock it when dropped
    unsafe fn new(lock: &'mutex Mutex<T>) -> MutexGuard<'mutex, T> {
        MutexGuard {
            __lock: lock,
            __phantom: PhantomData,
        }
    }
}

impl<T> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.__lock.data.get() }
    }
}

impl<T> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.__lock.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        unsafe {
            self.__lock.inner.raw_unlock();
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: fmt::Display> fmt::Display for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

/* *************************************** MUTEX INNER ****************************************** */

// original edits for sunrise kernel //

impl MutexInner {
    /// Try to obtain the mutex, without preempting.
    ///
    /// Returns false if the mutex was not immediately available.
    unsafe fn try_lock(&self) -> bool {
        let mut inner_guard = self.spin_lock.lock();
        if let Some(_owner) = inner_guard.owner {
            // already taken :/
            false
        } else {
            debug_assert!(inner_guard.waiters.is_empty(), "Mutex is not held, but there are some waiters");

            // wow cool ! take it
            let me = &*get_current_thread() as *const ThreadStruct as usize;
            inner_guard.owner = Some(me);
            true
        }
    }

    /// Locks the mutex blocking the current thread until it is available.
    ///
    /// # Panics
    ///
    /// Panics if we're already the owner of the mutex, as this is a deadlock otherwise.
    unsafe fn raw_lock(&self) {
        let me = get_current_thread();
        let mut inner_guard = self.spin_lock.lock();
        if let Some(owner) = inner_guard.owner {
            if owner == &*me as *const ThreadStruct as usize {
                panic!("Deadlock ! Re-taking the mutex when we already are its owner");
            }
            // add ourselves to the queue of waiters,
            inner_guard.waiters.push(me);
            // and unschedule.
            // unschedule will drop the inner_guard only once we're properly unscheduled,
            // so that we can't miss a wake-up between the registration and actual unschedule.
            //
            // it will also re-lock the inner_guard for us when we are finally waked up,
            // but we don't care about that, so immediately drop it.
            let _ = unschedule(&self.spin_lock, inner_guard);
            // cool, we now have the mutex for us,
            // return.
        } else {
            // no owner, we can take it !
            debug_assert!(inner_guard.waiters.is_empty(), "Mutex is not held, but there are some waiters");

            inner_guard.owner = Some(&*me as *const ThreadStruct as usize);
        }
    }

    /// Unlocks the mutex.
    ///
    /// Consider switching from the pair of raw_lock() and raw_unlock() to
    /// lock() whenever possible.
    ///
    /// # Panics
    ///
    /// Panics if the mutex wasn't held, or if our thread was not the owner of this mutex,
    /// as this definitely is a bug and we shouldn't have created a MutexGuard for it.
    unsafe fn raw_unlock(&self) {
        let me = &*get_current_thread() as *const ThreadStruct as usize;
        let mut inner = self.spin_lock.lock();
        match inner.owner {
            None => panic!("Unlocked a non-held mutex"),
            Some(x) if x != me => panic!("Unlocked a mutex held by someone else"),
            Some(_) => (),
        }
        if inner.waiters.is_empty() {
            // no waiter, make the mutex non-held and return
            inner.owner = None
        } else {
            // has a waiter, make it the owner of the mutex, schedule it, and return
            let waiter = inner.waiters.remove(0);
            inner.owner = Some(&*waiter as *const ThreadStruct as usize);
            add_to_schedule_queue(waiter);
        }
    }
}

/* ****************************************** TESTS ********************************************* */

/* Only tests what's trivially testable :/ */

#[cfg(test)]
mod tests {
    /*
    use crate::sync::mpsc::channel;
    use crate::sync::{Arc, Mutex, Condvar};
    use crate::sync::atomic::{AtomicUsize, Ordering};
    use crate::thread;
    */

    use crate::sync::Mutex;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use alloc::sync::Arc;

    /* struct Packet<T>(Arc<(Mutex<T>, Condvar)>); */

    #[derive(Eq, PartialEq, Debug)]
    struct NonCopy(i32);

    /*
    #[test]
    fn smoke() {
        let m = Mutex::new(());
        drop(m.lock());
        drop(m.lock());
    }
    */

    /*
    #[test]
    fn lots_and_lots() {
        const J: u32 = 1000;
        const K: u32 = 3;

        let m = Arc::new(Mutex::new(0));

        fn inc(m: &Mutex<u32>) {
            for _ in 0..J {
                *m.lock().unwrap() += 1;
            }
        }

        let (tx, rx) = channel();
        for _ in 0..K {
            let tx2 = tx.clone();
            let m2 = m.clone();
            thread::spawn(move|| { inc(&m2); tx2.send(()).unwrap(); });
            let tx2 = tx.clone();
            let m2 = m.clone();
            thread::spawn(move|| { inc(&m2); tx2.send(()).unwrap(); });
        }

        drop(tx);
        for _ in 0..2 * K {
            rx.recv().unwrap();
        }
        assert_eq!(*m.lock().unwrap(), J * K * 2);
    }
    */

    /*
    #[test]
    fn try_lock() {
        let m = Mutex::new(());
        *m.try_lock().unwrap() = ();
    }
    */

    #[test]
    fn test_into_inner() {
        let m = Mutex::new(NonCopy(10));
        assert_eq!(m.into_inner(), NonCopy(10));
    }

    #[test]
    fn test_into_inner_drop() {
        struct Foo(Arc<AtomicUsize>);
        impl Drop for Foo {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let num_drops = Arc::new(AtomicUsize::new(0));
        let m = Mutex::new(Foo(num_drops.clone()));
        assert_eq!(num_drops.load(Ordering::SeqCst), 0);
        {
            let _inner = m.into_inner();
            assert_eq!(num_drops.load(Ordering::SeqCst), 0);
        }
        assert_eq!(num_drops.load(Ordering::SeqCst), 1);
    }

    /* no poison here :)
    #[test]
    fn test_into_inner_poison() {
        let m = Arc::new(Mutex::new(NonCopy(10)));
        let m2 = m.clone();
        let _ = thread::spawn(move || {
            let _lock = m2.lock().unwrap();
            panic!("test panic in inner thread to poison mutex");
        }).join();

        assert!(m.is_poisoned());
        match Arc::try_unwrap(m).unwrap().into_inner() {
            Err(e) => assert_eq!(e.into_inner(), NonCopy(10)),
            Ok(x) => panic!("into_inner of poisoned Mutex is Ok: {:?}", x),
        }
    }
    */

    #[test]
    fn test_get_mut() {
        let mut m = Mutex::new(NonCopy(10));
        *m.get_mut() = NonCopy(20);
        assert_eq!(m.into_inner(), NonCopy(20));
    }

    /* no poison :)
    #[test]
    fn test_get_mut_poison() {
        let m = Arc::new(Mutex::new(NonCopy(10)));
        let m2 = m.clone();
        let _ = thread::spawn(move || {
            let _lock = m2.lock().unwrap();
            panic!("test panic in inner thread to poison mutex");
        }).join();

        assert!(m.is_poisoned());
        match Arc::try_unwrap(m).unwrap().get_mut() {
            Err(e) => assert_eq!(*e.into_inner(), NonCopy(10)),
            Ok(x) => panic!("get_mut of poisoned Mutex is Ok: {:?}", x),
        }
    }
    */

    /*
    #[test]
    fn test_mutex_arc_condvar() {
        let packet = Packet(Arc::new((Mutex::new(false), Condvar::new())));
        let packet2 = Packet(packet.0.clone());
        let (tx, rx) = channel();
        let _t = thread::spawn(move|| {
            // wait until parent gets in
            rx.recv().unwrap();
            let &(ref lock, ref cvar) = &*packet2.0;
            let mut lock = lock.lock().unwrap();
            *lock = true;
            cvar.notify_one();
        });

        let &(ref lock, ref cvar) = &*packet.0;
        let mut lock = lock.lock().unwrap();
        tx.send(()).unwrap();
        assert!(!*lock);
        while !*lock {
            lock = cvar.wait(lock).unwrap();
        }
    }
    */

    /* no poison :)
    #[test]
    fn test_arc_condvar_poison() {
        let packet = Packet(Arc::new((Mutex::new(1), Condvar::new())));
        let packet2 = Packet(packet.0.clone());
        let (tx, rx) = channel();

        let _t = thread::spawn(move || -> () {
            rx.recv().unwrap();
            let &(ref lock, ref cvar) = &*packet2.0;
            let _g = lock.lock().unwrap();
            cvar.notify_one();
            // Parent should fail when it wakes up.
            panic!();
        });

        let &(ref lock, ref cvar) = &*packet.0;
        let mut lock = lock.lock().unwrap();
        tx.send(()).unwrap();
        while *lock == 1 {
            match cvar.wait(lock) {
                Ok(l) => {
                    lock = l;
                    assert_eq!(*lock, 1);
                }
                Err(..) => break,
            }
        }
    }
    */

    /* no poison :)
    #[test]
    fn test_mutex_arc_poison() {
        let arc = Arc::new(Mutex::new(1));
        assert!(!arc.is_poisoned());
        let arc2 = arc.clone();
        let _ = thread::spawn(move|| {
            let lock = arc2.lock().unwrap();
            assert_eq!(*lock, 2);
        }).join();
        assert!(arc.lock().is_err());
        assert!(arc.is_poisoned());
    }
    */

    /*
    #[test]
    fn test_mutex_arc_nested() {
        // Tests nested mutexes and access
        // to underlying data.
        let arc = Arc::new(Mutex::new(1));
        let arc2 = Arc::new(Mutex::new(arc));
        let (tx, rx) = channel();
        let _t = thread::spawn(move|| {
            let lock = arc2.lock().unwrap();
            let lock2 = lock.lock().unwrap();
            assert_eq!(*lock2, 1);
            tx.send(()).unwrap();
        });
        rx.recv().unwrap();
    }
    */

    /*
    #[test]
    fn test_mutex_arc_access_in_unwind() {
        let arc = Arc::new(Mutex::new(1));
        let arc2 = arc.clone();
        let _ = thread::spawn(move|| -> () {
            struct Unwinder {
                i: Arc<Mutex<i32>>,
            }
            impl Drop for Unwinder {
                fn drop(&mut self) {
                    *self.i.lock().unwrap() += 1;
                }
            }
            let _u = Unwinder { i: arc2 };
            panic!();
        }).join();
        let lock = arc.lock().unwrap();
        assert_eq!(*lock, 2);
    }
    */

    /* our mutex don't work on T: ?Sized
    #[test]
    fn test_mutex_unsized() {
        let mutex: &Mutex<[i32]> = &Mutex::new([1, 2, 3]);
        {
            let b = &mut *mutex.lock().unwrap();
            b[0] = 4;
            b[2] = 5;
        }
        let comp: &[i32] = &[4, 2, 5];
        assert_eq!(&*mutex.lock().unwrap(), comp);
    }
    */
}
