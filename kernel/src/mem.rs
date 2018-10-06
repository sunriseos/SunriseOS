//! Basic functionality for dealing with memory.

use core::ops::{Deref, DerefMut};

#[repr(transparent)]
pub struct UserSpacePtr<T: ?Sized>(pub *const T);

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
pub struct UserSpacePtrMut<T: ?Sized>(pub *mut T);

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

// TODO: This sucks!
#[repr(C)]
pub struct FatPtr {
    pub data: usize,
    pub len: usize,
}
