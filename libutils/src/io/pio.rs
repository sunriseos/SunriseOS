//! Port Io
//!
//! All PIOs implement the [Io] trait, and can be abstracted that way.
//!
//! Stolen from [Redox OS](https://gitlab.redox-os.org/redox-os/syscall/blob/master/src/io/pio.rs).

use core::arch::asm;
use core::marker::PhantomData;
use super::Io;

/// Port IO accessor.
#[derive(Copy, Clone, Debug)]
pub struct Pio<T> {
    /// The io port address.
    port: u16,
    /// The width of the port.
    value: PhantomData<T>,
}

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
impl Io for Pio<u8> {
    type Value = u8;

    /// Read
    #[inline(always)]
    fn read(&self) -> u8 {
        let value: u8;
        unsafe {
           asm!("in al, dx", out("al") value, in("dx") self.port, options(nomem, preserves_flags, nostack));
        }
        value
    }

    /// Write
    #[inline(always)]
    fn write(&mut self, value: u8) {
        unsafe {
            asm!("out dx, al", in("al") value, in("dx") self.port, options(nomem, preserves_flags, nostack));
        }
    }
}

/// Read/Write for word PIO
impl Io for Pio<u16> {
    type Value = u16;

    /// Read
    #[inline(always)]
    fn read(&self) -> u16 {
        let value: u16;
        unsafe {
           asm!("in ax, dx", out("ax") value, in("dx") self.port, options(nomem, preserves_flags, nostack));
        }
        value
    }

    /// Write
    #[inline(always)]
    fn write(&mut self, value: u16) {
        unsafe {
            asm!("out dx, ax", in("ax") value, in("dx") self.port, options(nomem, preserves_flags, nostack));
        }
    }
}

/// Read/Write for doubleword PIO
impl Io for Pio<u32> {
    type Value = u32;

    /// Read
    #[inline(always)]
    fn read(&self) -> u32 {
        let value: u32;
        unsafe {
           asm!("in eax, dx", out("eax") value, in("dx") self.port, options(nomem, preserves_flags, nostack));
        }
        value
    }

    /// Write
    #[inline(always)]
    fn write(&mut self, value: u32) {
        unsafe {
            asm!("out dx, eax", in("eax") value, in("dx") self.port, options(nomem, preserves_flags, nostack));
        }
    }
}
