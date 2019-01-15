//! Wrapper around a mmio value
//!
//! Defines a pointer that should always be accessed by volatile reads/writes.
//!
//! Stolen from [Redox OS](https://gitlab.redox-os.org/redox-os/syscall/blob/master/src/io/mmio.rs).

use core::ptr::{read_volatile, write_volatile};
use core::mem::uninitialized;
use core::fmt::{Debug, Formatter, Error};

use super::Io;

/// A value that can only be accessed volatilely.
///
/// Generally used behind a pointer, as such:
///
/// ```
///     /// Layout of Mmio registers of a random device.
///     ///
///     /// This struct is repr packed so its field are not re-ordered,
///     /// and no undesired padding is added.
///     ///
///     /// Be careful though, in rust reading an unaligned field is undefined behaviour,
///     /// so you must make sure it is correctly aligned.
///     #[repr(packed)]
///     struct DeviceFooRegisters {
///         register_control: Mmio<u16>,
///         register_command: Mmio<u16>,
///     }
///
///     let device_address = 0xabcdef00 as *mut DeviceFooRegisters;
///
///     let device: &mut DeviceFooRegisters = unsafe {
///         // safety: make sure that mmio_address is valid and we're not violating
///         // rust's aliasing rules.
///         mmio_address.as_mut().unwrap()
///     };
///
///     let status = device.register_control.read();
///     device.register_command.write(0xFOOD);
/// ```
// todo: Mmio<T> UnsafeCell
// body: Figure out if Mmio<T> should implement UnsafeCell.
// body: Does this mean that, just like atomic, write can take self by const reference only ?
// body: But is a Mmio<T> actually atomic ?
// body:
// body: Forward all these questions to @roblabla.
// body:
// body: Note:
// body:
// body: see [volatile cell](https://docs.rs/vcell/0.1.0/src/vcell/lib.rs.html#18-20)
// body: and [this discussion](https://github.com/rust-rfcs/unsafe-code-guidelines/issues/33)
#[repr(packed)]
pub struct Mmio<T> {
    /// The value. Can only be accessed through .read()
    value: T,
}

impl<T> Mmio<T> {
    /// Create a new Mmio without initializing.
    ///
    /// Mostly unused, you would almost always get a Mmio
    /// by casting a raw pointer to a &mut Mmio.
    #[allow(clippy::new_without_default)] // because of Redox.
    pub fn new() -> Self {
        Mmio {
            value: unsafe { uninitialized() }
        }
    }
}

impl<T> Io for Mmio<T> where T: Copy {
    type Value = T;

    /// Performs a volatile read of the value.
    fn read(&self) -> T {
        unsafe { read_volatile(&self.value) }
    }

    /// Performs a volatile write of the value.
    fn write(&mut self, value: T) {
        unsafe { write_volatile(&mut self.value, value) };
    }
}

impl<T> Debug for Mmio<T> where T: Copy + Debug {
    /// Debug volatilely reads `value`.
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        fmt.debug_struct("Mmio")
            .field("value", &self.read())
            .finish()
    }
}
