//! The IO interface
//!
//! Stolen from [Redox Io](https://gitlab.redox-os.org/redox-os/syscall/blob/master/src/io/io.rs)

mod pio;
mod mmio;
pub use self::pio::Pio;
pub use self::mmio::Mmio;

use core::cmp::PartialEq;
use core::ops::{BitAnd, BitOr, Not};
use core::fmt::{Debug, Formatter, Error};

/// The Io trait allows for accessing device IO in a generic way, abstracting
/// over different IO accesses (Port IO and Memory Mapped IO).
pub trait Io {
    /// The width of the IO access.
    /// Should be a primitive type like u8, u16, u32...
    type Value: Copy;

    /// Reads from this Io.
    fn read(&self) -> Self::Value;

    /// Writes `value` to this Io.
    fn write(&mut self, value: Self::Value);

    /// Read from this Io, and mask the value with `flags`.
    #[inline(always)]
    fn readf(&self, flags: Self::Value) -> bool
    where
        Self::Value: PartialEq + BitAnd<Output = Self::Value>
    {
        (self.read() & flags) as Self::Value == flags
    }

    /// Mask `value` with `flags`, and write it to this device address. Note that
    /// this causes a read!
    #[inline(always)]
    fn writef(&mut self, flags: Self::Value, value: bool)
    where
        Self::Value: PartialEq + BitAnd<Output = Self::Value> + BitOr<Output = Self::Value> + Not<Output = Self::Value>
    {
        let tmp: Self::Value = if value {
            self.read() | flags
        } else {
            self.read() & !flags
        };
        self.write(tmp);
    }
}

/// A read-only wrapper around an IO device.
#[derive(Debug)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct ReadOnly<I> {
    inner: I
}

impl<I> ReadOnly<I> {
    /// Create a read-only wrapper around the IO device address.
    pub const fn new(inner: I) -> ReadOnly<I> {
        ReadOnly {
            inner: inner
        }
    }
}

impl<I: Io> ReadOnly<I> {
    /// Reads from this Io.
    #[inline(always)]
    pub fn read(&self) -> I::Value {
        self.inner.read()
    }

    /// Read from this Io, and mask the value with `flags`.
    #[inline(always)]
    pub fn readf(&self, flags: I::Value) -> bool
    where
        <I as Io>::Value: PartialEq + BitAnd<Output = <I as Io>::Value>
    {
        self.inner.readf(flags)
    }
}

/// An Io that we can only write to.
#[allow(clippy::missing_docs_in_private_items)]
pub struct WriteOnly<I> {
    inner: I
}

impl<I> WriteOnly<I> {
    /// Creates a WriteOnly Io.
    pub const fn new(inner: I) -> WriteOnly<I> {
        WriteOnly {
            inner: inner
        }
    }
}

impl<I: Io> WriteOnly<I> {
    /// Writes `value` to this Io.
    #[inline(always)]
    pub fn write(&mut self, value: I::Value) {
        self.inner.write(value)
    }

    // writef() not exposed as it requires a read.
}

impl<I> Debug for WriteOnly<I> {
    /// Debug does not access the **write only** value.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.debug_struct("WriteOnly")
            .finish()
    }
}
