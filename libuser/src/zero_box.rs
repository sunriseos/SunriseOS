//! A module that allocates zeroed types on the heap without copying them from the stack first.
//!
//! This is useful for big types that would otherwise cause a stack overflow.

use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

/// A wrapper around a Box that can initialize itself directly on the heap.
#[repr(transparent)]
#[derive(Debug)]
pub struct ZeroBox<T> {
    owned_box: Box<T>
}

impl<T> ZeroBox<T> {
    /// Regular Box initialisation.
    pub fn new(x: T) -> ZeroBox<T> {
        ZeroBox { owned_box: Box::new(x) }
    }

    /// Allocate a ZeroBox directly on the heap, and zero it.
    ///
    /// This function does not cause any stack-to-heap copy.
    pub fn new_zeroed() -> ZeroBox<T>
    where T: ZeroInitialized {
        // Dirty workaround
        #[doc(hidden)]
        #[allow(unions_with_drop_fields)] // we will have a Box<T> in the end.
        #[repr(C)]
        union ZeroedBuilder<X> {
            empty: (),
            t: X
        }
        #[doc(hidden)]
        unsafe fn zeroed<T>() -> Box<T> {
            let alloc: Box<ZeroedBuilder<T>> = box ZeroedBuilder {
                empty: ()
            };
            let alloc = Box::into_raw(alloc);
            ::core::ptr::write_bytes(alloc, 0x00, 1);
            // Recast the pointer as the unwrapped union, and give it back to Box.
            // Hopefully this is not UB, but that's the best I could come up with
            // which actually worked, even in debug builds.
            Box::<T>::from_raw(alloc as *mut T)
        }
        ZeroBox { owned_box: unsafe { zeroed() } }
    }
}

impl<T> Deref for ZeroBox<T> {
    type Target = T;

    fn deref(&self) -> &<Self as Deref>::Target { &*self.owned_box }
}

impl<T> DerefMut for ZeroBox<T> {
    fn deref_mut(&mut self) -> &mut <Self as Deref>::Target { &mut *self.owned_box }
}

impl<T> AsRef<T> for ZeroBox<T> {
    fn as_ref(&self) -> &T {
        &self.owned_box
    }
}

impl<T> AsMut<T> for ZeroBox<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.owned_box
    }
}

/// A marker trait indicating that zero values is a valid representation for this type.
///
/// Used by [ZeroBox] to safely allocate zeroed types on the heap.
pub unsafe trait ZeroInitialized {}
