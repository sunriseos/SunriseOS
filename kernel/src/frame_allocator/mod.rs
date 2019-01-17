//! Physical memory manager.
//!
//! This module can only allocate and free whole frames.

use alloc::vec::Vec;
use error::KernelError;
use paging::PAGE_SIZE;

pub mod physical_mem_region;
pub use self::physical_mem_region::{PhysicalMemRegion, PhysicalMemRegionIter};

/// Architecture specific-behaviour
mod i386;
pub use self::i386::{FrameAllocator, init, mark_frame_bootstrap_allocated};

/// An arch-specific FrameAllocator must expose the following functions
pub trait FrameAllocatorTrait: FrameAllocatorTraitPrivate {
    /// Allocates a single PhysicalMemRegion.
    /// Frames are physically consecutive.
    fn allocate_region(length: usize) -> Result<PhysicalMemRegion, KernelError>;

    /// Allocates physical frames, possibly fragmented across several physical regions.
    fn allocate_frames_fragmented(length: usize) -> Result<Vec<PhysicalMemRegion>, KernelError>;

    /// Allocates a single physical frame.
    fn allocate_frame() -> Result<PhysicalMemRegion, KernelError> {
        Self::allocate_region(PAGE_SIZE)
    }
}

use self::private::FrameAllocatorTraitPrivate;

mod private {
    //! Private FrameAllocator API

    use super::PhysicalMemRegion;
    use mem::PhysicalAddress;

    /// An arch-specifig FrameAllocator must expose the following functions.
    ///
    /// These only provide an internal API for [PhysicalMemRegion]s.
    pub trait FrameAllocatorTraitPrivate {
        /// Marks a region as deallocated.
        /// Called when a PhysicalMemRegion is dropped.
        ///
        /// # Panic
        ///
        /// Panics if the region was not known as allocated
        fn free_region(region: &PhysicalMemRegion);

        /// Checks if a region is marked allocated.
        fn check_is_allocated(address: PhysicalAddress, length: usize) -> bool;

        /// Checks if a region is marked reserved.
        fn check_is_reserved(region: PhysicalAddress, length: usize) -> bool;
    }
}
