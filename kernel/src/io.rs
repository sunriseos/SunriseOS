//! The IO interface.
//!
//! Copied from [redox io](https://gitlab.redox-os.org/redox-os/syscall/blob/master/src/io/io.rs)

use core::cmp::PartialEq;
use core::ops::{BitAnd, BitOr, Not};

/// Input / Output trait.
pub trait Io {
    /// The type of this Io.
    type Value: Copy + PartialEq + BitAnd<Output = Self::Value> + BitOr<Output = Self::Value> + Not<Output = Self::Value>;

    /// Read from this Io.
    fn read(&self) -> Self::Value;
    /// Write `value` to this Io.
    fn write(&mut self, value: Self::Value);

    /// Read from this Io, and mask the value with `flags`.
    #[inline(always)]
    fn readf(&self, flags: Self::Value) -> bool  {
        (self.read() & flags) as Self::Value == flags
    }

    /// Mask `value` with `flags`, and write it to this Io.
    #[inline(always)]
    fn writef(&mut self, flags: Self::Value, value: bool) {
        let tmp: Self::Value = if value {
            self.read() | flags
        } else {
            self.read() & !flags
        };
        self.write(tmp);
    }
}

/// An Io that we can only read from.
#[derive(Debug)]
pub struct ReadOnly<I: Io> {
    inner: I
}

impl<I: Io> ReadOnly<I> {
    /// Creates a ReadOnly Io.
    pub const fn new(inner: I) -> ReadOnly<I> {
        ReadOnly {
            inner: inner
        }
    }

    /// Read from this Io.
    #[inline(always)]
    pub fn read(&self) -> I::Value {
        self.inner.read()
    }

    /// Mask `value` with `flags`, and write it to this Io.
    #[inline(always)]
    pub fn readf(&self, flags: I::Value) -> bool {
        self.inner.readf(flags)
    }
}

/// An Io that we can only write to.
#[derive(Debug)]
pub struct WriteOnly<I: Io> {
    inner: I
}

impl<I: Io> WriteOnly<I> {
    /// Creates a WriteOnly Io.
    pub const fn new(inner: I) -> WriteOnly<I> {
        WriteOnly {
            inner: inner
        }
    }

    /// Write `value` to this Io.
    #[inline(always)]
    pub fn write(&mut self, value: I::Value) {
        self.inner.write(value)
    }

    /// Mask `value` with `flags`, and write it to this Io.
    #[inline(always)]
    pub fn writef(&mut self, flags: I::Value, value: bool) {
        self.inner.writef(flags, value)
    }
}