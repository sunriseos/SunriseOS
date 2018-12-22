//! The IO interface
//!
//! Copied from [redox io](https://gitlab.redox-os.org/redox-os/syscall/blob/master/src/io/io.rs)

use core::cmp::PartialEq;
use core::ops::{BitAnd, BitOr, Not};

/// The Io trait allows for accessing device IO in a generic way, abstracting
/// over different IO accesses (Port IO and Memory Mapped IO).
pub trait Io {
    /// The width of the IO access.
    /// Should be a primitive type like u8, u16, u32...
    type Value: Copy + PartialEq + BitAnd<Output = Self::Value> + BitOr<Output = Self::Value> + Not<Output = Self::Value>;

    /// Reads from this Io.
    fn read(&self) -> Self::Value;

    /// Writes `value` to this Io.
    fn write(&mut self, value: Self::Value);

    /// Read from this Io, and mask the value with `flags`.
    #[inline(always)]
    fn readf(&self, flags: Self::Value) -> bool  {
        (self.read() & flags) as Self::Value == flags
    }

    /// Mask `value` with `flags`, and write it to this device address. Note that
    /// this causes a read!
    #[inline(always)]
    fn writef(&mut self, flags: Self::Value, value: bool) {
        let tmp: Self::Value = if value {
            self.read() | flags
        }else {
            self.read() & !flags
        };
        self.write(tmp);
    }
}

/// A read-only wrapper around an IO device.
#[derive(Debug)]
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
    pub fn readf(&self, flags: I::Value) -> bool {
        self.inner.readf(flags)
    }
}

/// An Io that we can only write to.
#[derive(Debug)]
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
}

use core::marker::PhantomData;

/// Port IO accessor.
#[cfg(target_arch = "x86")]
#[derive(Copy, Clone, Debug)]
pub struct Pio<T> {
    port: u16,
    value: PhantomData<T>,
}

#[cfg(target_arch = "x86")]
impl<T> Pio<T> {
    /// Create a PIO from a given port
    pub const fn new(port: u16) -> Self {
        Pio::<T> {
            port: port,
            value: PhantomData,
        }
    }
}

/// Read/Write for byte PIO
#[cfg(target_arch = "x86")]
impl Io for Pio<u8> {
    type Value = u8;

    /// Read
    #[inline(always)]
    fn read(&self) -> u8 {
        let value: u8;
        unsafe {
            asm!("in $0, $1" : "={al}"(value) : "{dx}"(self.port) : "memory" : "intel", "volatile");
        }
        value
    }

    /// Write
    #[inline(always)]
    fn write(&mut self, value: u8) {
        unsafe {
            asm!("out $1, $0" : : "{al}"(value), "{dx}"(self.port) : "memory" : "intel", "volatile");
        }
    }
}

/// Read/Write for word PIO
#[cfg(target_arch = "x86")]
impl Io for Pio<u16> {
    type Value = u16;

    /// Read
    #[inline(always)]
    fn read(&self) -> u16 {
        let value: u16;
        unsafe {
            asm!("in $0, $1" : "={ax}"(value) : "{dx}"(self.port) : "memory" : "intel", "volatile");
        }
        value
    }

    /// Write
    #[inline(always)]
    fn write(&mut self, value: u16) {
        unsafe {
            asm!("out $1, $0" : : "{ax}"(value), "{dx}"(self.port) : "memory" : "intel", "volatile");
        }
    }
}

/// Read/Write for doubleword PIO
#[cfg(target_arch = "x86")]
impl Io for Pio<u32> {
    type Value = u32;

    /// Read
    #[inline(always)]
    fn read(&self) -> u32 {
        let value: u32;
        unsafe {
            asm!("in $0, $1" : "={eax}"(value) : "{dx}"(self.port) : "memory" : "intel", "volatile");
        }
        value
    }

    /// Write
    #[inline(always)]
    fn write(&mut self, value: u32) {
        unsafe {
            asm!("out $1, $0" : : "{eax}"(value), "{dx}"(self.port) : "memory" : "intel", "volatile");
        }
    }
}
