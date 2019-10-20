//! This is an implementation of a global allocator on the surnise platform using libuser.
use crate::alloc::{GlobalAlloc, Layout, System};
use sunrise_libuser::ALLOCATOR;

#[stable(feature = "alloc_system_type", since = "1.28.0")]
unsafe impl GlobalAlloc for System {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATOR.alloc(layout)
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALLOCATOR.dealloc(ptr, layout)
    }

}
