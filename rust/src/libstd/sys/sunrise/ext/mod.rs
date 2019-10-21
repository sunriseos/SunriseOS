//! Experimental extensions to `std` for Sunrise platforms.
//!
//! For now, this module is limited to extracting file descriptors,
//! but its functionality will grow over time.
//!
//! # Examples
//!
//! ```no_run
//! use std::fs::File;
//! use std::os::sunrise::prelude::*;
//!
//! fn main() {
//!     // use stuffs with native sunrise bindings
//! }
//! ```

#![stable(feature = "rust1", since = "1.0.0")]
#![doc(cfg(target_os = "sunrise"))]

pub mod ffi;

/// A prelude for conveniently writing platform-specific code.
///
/// Includes all extension traits, and some important type definitions.
#[stable(feature = "rust1", since = "1.0.0")]
pub mod prelude {
    #[doc(no_inline)] #[stable(feature = "rust1", since = "1.0.0")]
    pub use super::ffi::{OsStrExt, OsStringExt};

    #[doc(no_inline)] #[stable(feature = "rust1", since = "1.0.0")]
    pub use sunrise_libuser::capabilities;

    #[doc(no_inline)] #[stable(feature = "rust1", since = "1.0.0")]
    pub use sunrise_libuser::syscalls::nr;
}
