//! Physical and Virtual address wrappers

use core::fmt::{Formatter, Error, Display, Debug};

/// Represents a Physical address
///
/// Should only be used when paging is off
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysicalAddress(pub usize);

/// Represents a Virtual address
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtualAddress(pub usize);

impl VirtualAddress  { pub fn addr(&self) -> usize { self.0 } }
impl PhysicalAddress { pub fn addr(&self) -> usize { self.0 } }

impl ::core::ops::Add<usize> for VirtualAddress {
    type Output = VirtualAddress;

    fn add(self, other: usize) -> VirtualAddress {
        VirtualAddress(self.0 + other)
    }
}

impl ::core::ops::Add<usize> for PhysicalAddress {
    type Output = PhysicalAddress;

    fn add(self, other: usize) -> PhysicalAddress {
        PhysicalAddress(self.0 + other)
    }
}

impl Debug for PhysicalAddress {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "P {:#010x}", self.0)
    }
}

impl Display for PhysicalAddress {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "P {:#010x}", self.0)
    }
}

impl Debug for VirtualAddress {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "V {:#010x}", self.0)
    }
}

impl Display for VirtualAddress {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "V {:#010x}", self.0)
    }
}
