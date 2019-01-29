//! Arch-specific API
//!
//! This module contains the architecture abstraction API, and a module with the
//! arch-specific APIs. For instance, the `i386` module contains i386-specific
//! APIs and is only present when building the kernel for the i386 architecture.
//! As such, it is required to gate access to those APIs behind a `cfg`, to avoid
//! breaking builds on other architectures.

#[cfg(target_arch = "x86")]
pub mod i386;
#[cfg(target_arch = "x86")]
use self::i386 as arch;

// Reexport public API
pub use self::arch::{enable_interrupts, disable_interrupts};
