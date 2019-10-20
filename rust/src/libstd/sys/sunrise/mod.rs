//! System bindings for the sunrise platform
//!
//! This is all super highly experimental and not actually intended for
//! wide/production use yet, it's still all in the experimental category. This
//! will likely change over time.
//!
//! Currently all functions here are basically stubs that immediately return
//! errors.

use crate::os::raw::c_char;

pub mod alloc;
pub mod args;
pub mod cmath;
pub mod env;
pub mod ext;
pub mod fast_thread_local;
pub mod fs;
pub mod io;
pub mod memchr;
pub mod net;
pub mod os;
pub mod path;
pub mod pipe;
pub mod process;
pub mod stack_overflow;
pub mod thread;
pub mod time;
pub mod stdio;

pub use crate::sys_common::os_str_bytes as os_str;

pub mod condvar;
pub mod mutex;
pub mod rwlock;
pub mod thread_local;

#[cfg(not(test))]
pub fn init() {
    fs::init();
}

pub fn unsupported<T>() -> crate::io::Result<T> {
    Err(unsupported_err())
}

pub fn unsupported_err() -> crate::io::Error {
    crate::io::Error::new(crate::io::ErrorKind::Other,
                   "operation not supported on sunrise yet")
}

pub fn decode_error_kind(_code: i32) -> crate::io::ErrorKind {
    crate::io::ErrorKind::Other
}

// This enum is used as the storage for a bunch of types which can't actually
// exist.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Void {}

pub unsafe fn strlen(mut s: *const c_char) -> usize {
    let mut n = 0;
    while *s != 0 {
        n += 1;
        s = s.offset(1);
    }
    return n
}

pub unsafe fn abort_internal() -> ! {
    core::intrinsics::abort();
}

// We don't have randomness yet, but I totally used a random number generator to
// generate these numbers.
//
// More seriously though this is just for DOS protection in hash maps. It's ok
// if we don't do that on sunrise just yet.
pub fn hashmap_random_keys() -> (u64, u64) {
    (1, 2)
}
