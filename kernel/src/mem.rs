//! Basic functionality for dealing with memory.
//!
//! Contains definition for VirtualAddress and PhysicalAddress,
//! and UserSpacePointer

use core::ops::{Deref, DerefMut};
use core::mem;
use core::fmt::{Formatter, Error, Display, Debug};
use error::{KernelError, ArithmeticOperation};
use failure::Backtrace;

use paging::PAGE_SIZE;
use utils::{align_down, align_up, div_round_up};

/// Rounds an address to its page address
#[inline] pub fn round_to_page(addr: usize) -> usize { align_down(addr, PAGE_SIZE) }

/// Rounds an address to the next page address except if its offset in that page is 0
#[inline] pub fn round_to_page_upper(addr: usize) -> usize { align_up(addr, PAGE_SIZE) }

/// Counts the number of pages `size` takes
#[inline] pub fn count_pages(size: usize) -> usize { div_round_up(size, PAGE_SIZE) }

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

impl PhysicalAddress {
    pub fn checked_add(self, rhs: usize) -> Result<PhysicalAddress, KernelError> {
        match self.0.checked_add(rhs) {
            Some(sum) => Ok(PhysicalAddress(sum)),
            None => Err(KernelError::WouldOverflow { lhs: self.0, operation: ArithmeticOperation::Add, rhs, backtrace: Backtrace::new() })
        }
    }
}

impl VirtualAddress {
    pub fn checked_add(self, rhs: usize) -> Result<VirtualAddress, KernelError> {
        match self.0.checked_add(rhs) {
            Some(sum) => Ok(VirtualAddress(sum)),
            None => Err(KernelError::WouldOverflow { lhs: self.0, operation: ArithmeticOperation::Add, rhs, backtrace: Backtrace::new() })
        }
    }
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
