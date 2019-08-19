//! Preemptive Mutex
//!
//! TODO: doc

use super::{SpinLock, SpinLockGuard};

/// Placeholder for future Mutex implementation.
pub type Mutex<T> = SpinLock<T>;
/// Placeholder for future Mutex implementation.
pub type MutexGuard<'a, T> = SpinLockGuard<'a, T>;
