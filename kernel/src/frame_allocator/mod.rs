//! A module defining a physical memory manager that allocates and frees memory frames
//!
//! This module can only allocate and free whole frames.

use alloc::vec::Vec;
use mem::PhysicalAddress;
use utils::{align_down, align_up, div_round_up, check_aligned};
use utils::Splittable;
use core::ops::{Index, Range};
use core::iter::StepBy;
use core::fmt::{Formatter, Error, Display, Debug};
use core::marker::PhantomData;
use error::KernelError;

/// Architecture specific-behaviour
mod i386;
pub use self::i386::{MEMORY_FRAME_SIZE, FrameAllocator, init, mark_frame_bootstrap_allocated};

/// A span of physical frames. A frame is MEMORY_FRAME_SIZE.
///
/// PhysicalMemRegions are allocated by the FRAME_ALLOCATOR.
/// Dropping a PhysicalMemRegion frees it.
pub struct PhysicalMemRegion {
    frames: usize,
    start_addr: usize,
    should_free_on_drop: bool
}

impl PhysicalMemRegion {
     /// Get the start address of this PhysicalMemRegion
    pub fn address(&self) -> PhysicalAddress { PhysicalAddress(self.start_addr) }

    /// Get the size this PhysicalMemRegion spans
    pub fn size(&self) -> usize { self.frames * MEMORY_FRAME_SIZE }

    /// Constructs a PhysicalMemRegiom by circumventing the FAME_ALLOCATOR.
    /// Used for accessing fixed mmio regions, as they should have been marked
    /// reserved in the FRAME_ALLOCATOR and will never be returned by it.
    ///
    /// On drop the region won't be given back to the FRAME_ALLOCATOR,
    /// and thous stay marked as reserved.
    ///
    /// # Panic
    ///
    /// Panics if any of the frames in this span wasn't marked as reserved in
    /// the frame allocator, as it could had mistakenly given it as regular ram.
    pub unsafe fn on_fixed_mmio(start_addr: PhysicalAddress, len: usize) -> Self {
        let region = PhysicalMemRegion {
            start_addr: align_down(start_addr.addr(), MEMORY_FRAME_SIZE),
            frames: div_round_up(len, MEMORY_FRAME_SIZE),
            should_free_on_drop: false
        };
        assert!(FrameAllocator::check_is_reserved(&region));
        region
    }

    /// Constructs a PhysicalMemRegion from a physical address, and a len.
    /// Region will be given back to the FRAME_ALLOCATOR on drop.
    ///
    /// # Unsafe
    ///
    /// This function by-passes the FRAME_ALLOCATOR, and should only be used
    /// for frames that have been deconstructed and put in the Page Tables,
    /// and that are lacking any other form of tracking.
    /// This is the case for kernel pages.
    ///
    /// This function cannot make any guaranty that the frame can be written to,
    /// or even exists at all.
    ///
    /// # Panic
    ///
    /// Panics if any of the frames in this span wasn't marked as allocated in
    /// the frame allocator.
    /// Panics when the address is not framesize-aligned
    /// Panics when the len is not framesize-aligned
    pub unsafe fn reconstruct(physical_addr: PhysicalAddress, len: usize) -> Self {
        assert_eq!(physical_addr.addr() % MEMORY_FRAME_SIZE, 0,
                   "PhysicalMemRegion must be constructed from a framesize-aligned pointer");
        assert_eq!(len % MEMORY_FRAME_SIZE, 0,
                   "PhysicalMemRegion must have a framesize-aligned length");
        let region = PhysicalMemRegion {
            start_addr: physical_addr.addr(),
            frames: len / MEMORY_FRAME_SIZE,
            should_free_on_drop: true
        };
        assert!(FrameAllocator::check_is_allocated(&region));
        region
    }

    /// Constructs a PhysicalMemRegion from a physical address, and a len.
    /// Region won't be given back to the FRAME_ALLOCATOR on drop.
    ///
    /// # Unsafe
    ///
    /// This function by-passes the FRAME_ALLOCATOR, and should only be used
    /// for frames that have been deconstructed and put in the Page Tables,
    /// and that are lacking any other form of tracking.
    /// This is the case for kernel pages.
    ///
    /// This function cannot make any guaranty that the frame can be written to,
    /// or even exists at all.
    ///
    /// # Panic
    ///
    /// Panics if any of the frames in this span wasn't marked as allocated in
    /// the frame allocator.
    /// Panics when the address is not framesize-aligned
    /// Panics when the len is not framesize-aligned
    pub unsafe fn reconstruct_no_dealloc(physical_addr: PhysicalAddress, len: usize) -> Self {
        let mut ret = Self::reconstruct(physical_addr, len);
        ret.should_free_on_drop = false;
        ret
    }
}

impl Drop for PhysicalMemRegion {
    fn drop(&mut self) {
        if self.should_free_on_drop {
            FrameAllocator::free_region(self)
        }
    }
}

pub struct PhysicalMemRegionIter<'a>(StepBy<Range<usize>>, PhantomData<&'a ()>);

impl<'a> Iterator for PhysicalMemRegionIter<'a> {
    type Item = PhysicalAddress;

    fn next(&mut self) -> Option<PhysicalAddress> {
        self.0.next().map(PhysicalAddress)
    }
}

impl<'a> IntoIterator for &'a PhysicalMemRegion {
    type Item = PhysicalAddress;
    type IntoIter = PhysicalMemRegionIter<'a>;

    fn into_iter(self) -> <Self as IntoIterator>::IntoIter {
        PhysicalMemRegionIter((self.start_addr..self.start_addr + (self.frames * MEMORY_FRAME_SIZE)).step_by(MEMORY_FRAME_SIZE), PhantomData)
    }
}

impl Debug for PhysicalMemRegion {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "P region {:#010x} - {:#010x}, {} frames", self.start_addr,
               self.start_addr + self.frames * MEMORY_FRAME_SIZE - 1, self.frames)
    }
}

impl Splittable for PhysicalMemRegion {
    /// Splits the given PhysicalMemRegion in two parts, at the given offset.
    fn split_at(&mut self, offset: usize) -> Result<Option<Self>, KernelError> {
        check_aligned(offset, MEMORY_FRAME_SIZE)?;
        if offset != 0 && offset < self.size() {
            let frames_count = self.frames;
            self.frames = offset / MEMORY_FRAME_SIZE;
            Ok(Some(PhysicalMemRegion {
                start_addr: self.start_addr + self.frames * MEMORY_FRAME_SIZE,
                frames: frames_count - self.frames,
                should_free_on_drop: self.should_free_on_drop
            }))
        } else {
            Ok(None) // no need to split
        }
    }
}

impl Splittable for Vec<PhysicalMemRegion> {
    /// Splits a Vec of Physical regions in two Vec at the given offset.
    ///
    /// If the offset falls in the middle of a PhysicalMemRegion, it is splitted,
    /// and the right part is moved to the second Vec.
    fn split_at(&mut self, offset: usize) -> Result<Option<Self>, KernelError> {
        check_aligned(offset, MEMORY_FRAME_SIZE)?;
        if offset == 0 { return Ok(None) };

        let mut length_acc = 0;
        let split_pos_in_vec_opt = self.iter().position(|r| {
            if length_acc + r.frames * MEMORY_FRAME_SIZE > offset {
                true
            } else {
                length_acc += r.frames * MEMORY_FRAME_SIZE;
                false
            }
        });
        match split_pos_in_vec_opt {
            None => Ok(None), // no need to split the vec
            Some(split_pos_in_vec) => {
                // ok, split the vec in two parts
                let mut vec_right = self.split_off(split_pos_in_vec);
                // and split right vec's first region
                match self.first_mut().unwrap().right_split(offset - length_acc)? {
                    None => Ok(Some(vec_right)), // did not require splitting a region
                    Some(region_left) => {
                        self.push(region_left);
                        Ok(Some(vec_right))
                    }
                }
            }
        }
    }
}

/// An arch-specific FrameAllocator must expose the following functions
pub trait FrameAllocatorTrait: FrameAllocatorTraitPrivate {
    /// Allocates a single PhysicalMemRegion.
    /// Frames are physically consecutive.
    fn allocate_region(nr_frames: usize) -> Result<PhysicalMemRegion, KernelError>;

    /// Allocates `nr` physical frames, possibly fragmented across several physical regions.
    fn allocate_frames_fragmented(nr: usize) -> Result<Vec<PhysicalMemRegion>, KernelError>;

    /// Allocates a single physical frame.
    fn allocate_frame() -> Result<PhysicalMemRegion, KernelError> {
        Self::allocate_region(1)
    }
}

use self::private::FrameAllocatorTraitPrivate;

mod private {
    use super::PhysicalMemRegion;

    pub trait FrameAllocatorTraitPrivate {
        /// Marks a region as deallocated.
        /// Called when a PhysicalMemRegion is dropped.
        ///
        /// # Panic
        ///
        /// Panics if the region was not known as allocated
        fn free_region(region: &PhysicalMemRegion);

        /// Checks if a region is marked allocated
        fn check_is_allocated(region: &PhysicalMemRegion) -> bool;

        /// Checks if a region is marked reserved
        fn check_is_reserved(region: &PhysicalMemRegion) -> bool;
    }
}
