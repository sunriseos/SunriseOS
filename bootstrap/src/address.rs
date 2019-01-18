//! Physical and Virtual address wrappers

use core::fmt::{Formatter, Error, Display, Debug, LowerHex};
use crate::frame_alloc::{round_to_page, round_to_page_upper};

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

impl VirtualAddress  {
    /// Gets the address as a `usize`.
    pub fn addr(self) -> usize { self.0 }
}

impl PhysicalAddress {
    /// Gets the address as a `usize`.
    pub fn addr(self) -> usize { self.0 }
}

impl ::core::ops::Add<usize> for VirtualAddress {
    type Output = VirtualAddress;
    /// Adding a length to an address gives another address
    fn add(self, other: usize) -> VirtualAddress { VirtualAddress(self.0 + other) }
}

impl ::core::ops::Add<usize> for PhysicalAddress {
    type Output = PhysicalAddress;
    /// Adding a length to an address gives another address
    fn add(self, other: usize) -> PhysicalAddress { PhysicalAddress(self.0 + other) }
}

impl ::core::ops::Add<VirtualAddress> for usize {
    type Output = VirtualAddress;
    /// Adding a length to an address gives another address
    fn add(self, other: VirtualAddress) -> VirtualAddress { VirtualAddress(self + other.0) }
}

impl ::core::ops::Add<PhysicalAddress> for usize {
    type Output = PhysicalAddress;
    /// Adding a length to an address gives another address
    fn add(self, other: PhysicalAddress) -> PhysicalAddress { PhysicalAddress(self + other.0) }
}

impl ::core::ops::Sub<usize> for VirtualAddress {
    type Output = VirtualAddress;
    /// Subtracting a length from an address gives another address
    fn sub(self, other: usize) -> VirtualAddress { VirtualAddress(self.0 - other) }
}

impl ::core::ops::Sub<usize> for PhysicalAddress {
    type Output = PhysicalAddress;
    /// Subtracting a length from an address gives another address
    fn sub(self, other: usize) -> PhysicalAddress { PhysicalAddress(self.0 - other) }
}

impl ::core::ops::AddAssign<usize> for VirtualAddress {
    /// Adding a length to an address gives another address
    fn add_assign(&mut self, rhs: usize) { self.0 += rhs }
}

impl ::core::ops::AddAssign<usize> for PhysicalAddress {
    /// Adding a length to an address gives another address
    fn add_assign(&mut self, rhs: usize) { self.0 += rhs }
}

impl ::core::ops::SubAssign<usize> for VirtualAddress {
    /// Subtracting a length from an address gives another address
    fn sub_assign(&mut self, rhs: usize) { self.0 -= rhs }
}

impl ::core::ops::SubAssign<usize> for PhysicalAddress {
    /// Subtracting a length from an address gives another address
    fn sub_assign(&mut self, rhs: usize) { self.0 -= rhs }
}

impl ::core::ops::Sub<VirtualAddress> for VirtualAddress {
    type Output = usize;
    /// Subtracting two address gives their distance
    fn sub(self, rhs: VirtualAddress) -> usize { self.0 - rhs.0 }
}

impl ::core::ops::Sub<PhysicalAddress> for PhysicalAddress {
    type Output = usize;
    /// Subtracting two address gives their distance
    fn sub(self, rhs: PhysicalAddress) -> usize { self.0 - rhs.0 }
}

impl Debug for PhysicalAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "P {:#010x}", self.0)
    }
}

impl Display for PhysicalAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "P {:#010x}", self.0)
    }
}

impl LowerHex for PhysicalAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "P {:#010x}", self.0)
    }
}

impl Debug for VirtualAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "V {:#010x}", self.0)
    }
}

impl Display for VirtualAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "V {:#010x}", self.0)
    }
}

impl LowerHex for VirtualAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "V {:#010x}", self.0)
    }
}

impl PhysicalAddress {
    /// Rounds down to PAGE_SIZE.
    pub fn floor(self) -> PhysicalAddress { PhysicalAddress(round_to_page(self.0)) }

    /// Rounds up PAGE_SIZE.
    pub fn ceil(self) -> PhysicalAddress { PhysicalAddress(round_to_page_upper(self.0)) }
}

impl VirtualAddress {
    /// Rounds down to PAGE_SIZE.
    pub fn floor(self) -> VirtualAddress { VirtualAddress(round_to_page(self.0)) }

    /// Rounds up PAGE_SIZE.
    pub fn ceil(self) -> VirtualAddress { VirtualAddress(round_to_page_upper(self.0)) }
}
