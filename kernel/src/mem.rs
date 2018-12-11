//! Basic functionality for dealing with memory.
//!
//! Contains definition for VirtualAddress and PhysicalAddress,
//! and UserSpacePointer

use core::ops::{Deref, DerefMut};
use core::mem;
use core::fmt::{Formatter, Error, Display, Debug, LowerHex};
use error::{KernelError, ArithmeticOperation};
use failure::Backtrace;
use core::iter::Step;

use paging::PAGE_SIZE;
use utils::{align_down, align_up, div_ceil};

/// Rounds an address to its page address
#[inline] pub fn round_to_page(addr: usize) -> usize { align_down(addr, PAGE_SIZE) }

/// Rounds an address to the next page address except if its offset in that page is 0
#[inline] pub fn round_to_page_upper(addr: usize) -> usize { align_up(addr, PAGE_SIZE) }

/// Counts the number of pages `size` takes
#[inline] pub fn count_pages(size: usize) -> usize { div_ceil(size, PAGE_SIZE) }

/// Represents a Physical address
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PhysicalAddress(pub usize);

/// Represents a Virtual address
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct VirtualAddress(pub usize);

impl VirtualAddress  {
    /// Gets the address as a `usize`.
    pub fn addr(&self) -> usize { self.0 }
}

impl PhysicalAddress {
    /// Gets the address as a `usize`.
    pub fn addr(&self) -> usize { self.0 }
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
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "P {:#010x}", self.0)
    }
}

impl Display for PhysicalAddress {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "P {:#010x}", self.0)
    }
}

impl LowerHex for PhysicalAddress {
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

impl LowerHex for VirtualAddress {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "V {:#010x}", self.0)
    }
}

impl PhysicalAddress {
    /// Tries to add an offset to a PhysicalAddress, returning a [KernelError] if this would cause an overflow.
    pub fn checked_add(self, rhs: usize) -> Result<PhysicalAddress, KernelError> {
        match self.0.checked_add(rhs) {
            Some(sum) => Ok(PhysicalAddress(sum)),
            None => Err(KernelError::WouldOverflow { lhs: self.0, operation: ArithmeticOperation::Add, rhs, backtrace: Backtrace::new() })
        }
    }

    /// Rounds down to PAGE_SIZE.
    pub fn floor(self) -> PhysicalAddress { PhysicalAddress(round_to_page(self.0)) }

    /// Rounds up PAGE_SIZE.
    pub fn ceil(self) -> PhysicalAddress { PhysicalAddress(round_to_page_upper(self.0)) }
}

impl VirtualAddress {
    /// Tries to add an offset to a VirtualAddress, returning a [KernelError] if this would cause an overflow.
    pub fn checked_add(self, rhs: usize) -> Result<VirtualAddress, KernelError> {
        match self.0.checked_add(rhs) {
            Some(sum) => Ok(VirtualAddress(sum)),
            None => Err(KernelError::WouldOverflow { lhs: self.0, operation: ArithmeticOperation::Add, rhs, backtrace: Backtrace::new() })
        }
    }

    /// Rounds down to PAGE_SIZE.
    pub fn floor(self) -> VirtualAddress { VirtualAddress(round_to_page(self.0)) }

    /// Rounds up PAGE_SIZE.
    pub fn ceil(self) -> VirtualAddress { VirtualAddress(round_to_page_upper(self.0)) }
}

impl core::iter::Step for PhysicalAddress {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> { Step::steps_between(&start.0, &end.0) }
    fn replace_one(&mut self) -> Self { PhysicalAddress(Step::replace_one(&mut self.0)) }
    fn replace_zero(&mut self) -> Self { PhysicalAddress(Step::replace_zero(&mut self.0)) }
    fn add_one(&self) -> Self { PhysicalAddress(Step::add_one(&self.0)) }
    fn sub_one(&self) -> Self { PhysicalAddress(Step::sub_one(&self.0)) }
    fn add_usize(&self, n: usize) -> Option<Self> { self.0.add_usize(n).map(PhysicalAddress) }
}

impl core::iter::Step for VirtualAddress {
    fn steps_between(start: &Self, end: &Self) -> Option<usize> { Step::steps_between(&start.0, &end.0) }
    fn replace_one(&mut self) -> Self { VirtualAddress(Step::replace_one(&mut self.0)) }
    fn replace_zero(&mut self) -> Self { VirtualAddress(Step::replace_zero(&mut self.0)) }
    fn add_one(&self) -> Self { VirtualAddress(Step::add_one(&self.0)) }
    fn sub_one(&self) -> Self { VirtualAddress(Step::sub_one(&self.0)) }
    fn add_usize(&self, n: usize) -> Option<Self> { self.0.add_usize(n).map(VirtualAddress) }
}

#[repr(transparent)]
pub struct UserSpacePtr<T: ?Sized>(pub *const T);

impl<T: ?Sized> Clone for UserSpacePtr<T> {
    fn clone(&self) -> UserSpacePtr<T> {
        UserSpacePtr(self.0)
    }
}
impl<T: ?Sized> Copy for UserSpacePtr<T> {}

impl<I> UserSpacePtr<[I]> {
    pub fn from_raw_parts(data: *const I, len: usize) -> UserSpacePtr<[I]> {
        unsafe {
            UserSpacePtr(mem::transmute(FatPtr {
                data: data as usize,
                len: len
            }))
        }
    }
}

impl<T: ?Sized> Deref for UserSpacePtr<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe {
            // TODO: Verify that we are allowed to read, panic otherwise.
            &*self.0
        }
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct UserSpacePtrMut<T: ?Sized>(pub *mut T);

impl<I> UserSpacePtrMut<[I]> {
    pub fn from_raw_parts_mut(data: *mut I, len: usize) -> UserSpacePtrMut<[I]> {
        unsafe {
            UserSpacePtrMut(mem::transmute(FatPtr {
                data: data as usize,
                len: len
            }))
        }
    }
}

impl<T: ?Sized> Clone for UserSpacePtrMut<T> {
    fn clone(&self) -> UserSpacePtrMut<T> {
        UserSpacePtrMut(self.0)
    }
}
impl<T: ?Sized> Copy for UserSpacePtrMut<T> {}

impl<T: ?Sized> Deref for UserSpacePtrMut<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe {
            // TODO: Verify that we are allowed to read, panic otherwise.
            &*self.0
        }
    }
}

impl<T: ?Sized> DerefMut for UserSpacePtrMut<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe {
            // TODO: Verify that we are allowed to read, panic otherwise.
            &mut *self.0
        }
    }
}

impl<T> Into<UserSpacePtr<T>> for UserSpacePtrMut<T> {
    fn into(self) -> UserSpacePtr<T> {
        UserSpacePtr(self.0)
    }
}

// TODO: This sucks!
#[repr(C)]
pub struct FatPtr {
    pub data: usize,
    pub len: usize,
}
