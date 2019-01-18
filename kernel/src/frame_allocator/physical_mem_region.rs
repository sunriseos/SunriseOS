//! PhysicalMemRegion
//!
//! A [PhysicalMemRegion] is a span of consecutive physical frames.

use super::{FrameAllocator, FrameAllocatorTraitPrivate};
use crate::paging::PAGE_SIZE;
use crate::mem::PhysicalAddress;
use crate::utils::{align_down, div_ceil, check_aligned, Splittable};
use core::ops::Range;
use core::iter::StepBy;
use core::fmt::{Formatter, Error, Debug};
use core::marker::PhantomData;
use crate::error::KernelError;
use alloc::vec::Vec;

/// A span of adjacent physical frames. A frame is [PAGE_SIZE].
///
/// `PhysicalMemRegions` are allocated by the [FrameAllocator].
/// Dropping a `PhysicalMemRegion` frees it.
pub struct PhysicalMemRegion {
    /// The number of frames in this region.
    pub(super) frames: usize,
    /// The (physical) address of the start of this region.
    pub(super) start_addr: usize,
    /// Denotes if the frames held in this region should be freed when the whole region is freed.
    /// The default have this set to `true`.
    ///
    /// We provide (unsafe) methods for duplicating `PhysicalMemRegions`, to ease working with them,
    /// but the duplicated region must not also free the frames when dropped,
    /// as this would cause a double-free.
    pub(super) should_free_on_drop: bool
}

impl PhysicalMemRegion {
     /// Get the start address of this PhysicalMemRegion
    pub fn address(&self) -> PhysicalAddress { PhysicalAddress(self.start_addr) }

    /// Get the size this PhysicalMemRegion spans
    pub fn size(&self) -> usize { self.frames * PAGE_SIZE }

    /// Constructs a `PhysicalMemRegion` by circumventing the [FrameAllocator].
    /// Used for accessing fixed mmio regions, as they should have been marked
    /// reserved in the [FrameAllocator] and will never be returned by it.
    ///
    /// On drop the region won't be given back to the [FrameAllocator],
    /// and thous stay marked as reserved.
    ///
    /// # Panic
    ///
    /// * Panics if any of the frames in this span wasn't marked as reserved in
    /// the [FrameAllocator], as it could had mistakenly given it as regular ram.
    pub unsafe fn on_fixed_mmio(start_addr: PhysicalAddress, len: usize) -> Self {
        assert!(FrameAllocator::check_is_reserved(start_addr, len));
        PhysicalMemRegion {
            start_addr: align_down(start_addr.addr(), PAGE_SIZE),
            frames: div_ceil(len, PAGE_SIZE),
            should_free_on_drop: false
        }
    }

    /// Constructs a `PhysicalMemRegion` from a physical address, and a len.
    /// Region will be given back to the [FrameAllocator] on drop.
    ///
    /// # Unsafe
    ///
    /// This function by-passes the [FrameAllocator], and should only be used
    /// for frames that have been deconstructed and put in the Page Tables,
    /// and that are lacking any other form of tracking.
    /// This is the case for kernel pages.
    ///
    /// This function cannot make any guaranty that the frame can be written to,
    /// or even exists at all.
    ///
    /// # Panic
    ///
    /// * Panics if any of the frames in this span wasn't marked as allocated in
    /// the frame allocator.
    /// * Panics when the address is not framesize-aligned
    /// * Panics when the len is not framesize-aligned
    pub unsafe fn reconstruct(physical_addr: PhysicalAddress, len: usize) -> Self {
        assert_eq!(physical_addr.addr() % PAGE_SIZE, 0,
                   "PhysicalMemRegion must be constructed from a framesize-aligned pointer");
        assert_eq!(len % PAGE_SIZE, 0,
                   "PhysicalMemRegion must have a framesize-aligned length");
        assert!(FrameAllocator::check_is_allocated(physical_addr, len));
        PhysicalMemRegion {
            start_addr: physical_addr.addr(),
            frames: len / PAGE_SIZE,
            should_free_on_drop: true
        }
    }

    /// Constructs a `PhysicalMemRegion` from a physical address, and a len.
    /// Region won't be given back to the [FrameAllocator] on drop.
    ///
    /// # Unsafe
    ///
    /// This function by-passes the [FrameAllocator], and should only be used
    /// for frames that have been deconstructed and put in the Page Tables,
    /// and that are lacking any other form of tracking.
    /// This is the case for kernel pages.
    ///
    /// This function cannot make any guaranty that the frame can be written to,
    /// or even exists at all.
    ///
    /// # Panic
    ///
    /// * Panics if any of the frames in this span wasn't marked as allocated in
    /// the frame allocator.
    /// * Panics when the address is not framesize-aligned
    /// * Panics when the len is not framesize-aligned
    pub unsafe fn reconstruct_no_dealloc(physical_addr: PhysicalAddress, len: usize) -> Self {
        let mut ret = Self::reconstruct(physical_addr, len);
        ret.should_free_on_drop = false;
        ret
    }
}

impl Drop for PhysicalMemRegion {
    /// Dropping a `PhysicalMemRegion` may free its frames.
    fn drop(&mut self) {
        if self.should_free_on_drop {
            FrameAllocator::free_region(self)
        }
    }
}

/// An iterator over a physical region. Yields the address of each contained frame.
#[derive(Debug, Clone)]
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
        PhysicalMemRegionIter((self.start_addr..self.start_addr + (self.frames * PAGE_SIZE)).step_by(PAGE_SIZE), PhantomData)
    }
}

impl Debug for PhysicalMemRegion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "P region {:#010x} - {:#010x}, {} frames", self.start_addr,
               self.start_addr + self.frames * PAGE_SIZE - 1, self.frames)
    }
}

impl Splittable for PhysicalMemRegion {
    /// Splits the given PhysicalMemRegion in two parts, at the given offset.
    fn split_at(&mut self, offset: usize) -> Result<Option<Self>, KernelError> {
        check_aligned(offset, PAGE_SIZE)?;
        if offset != 0 && offset < self.size() {
            let frames_count = self.frames;
            self.frames = offset / PAGE_SIZE;
            Ok(Some(PhysicalMemRegion {
                start_addr: self.start_addr + self.frames * PAGE_SIZE,
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
        check_aligned(offset, PAGE_SIZE)?;
        if offset == 0 { return Ok(None) };

        let mut length_acc = 0;
        let split_pos_in_vec_opt = self.iter().position(|r| {
            if length_acc + r.frames * PAGE_SIZE > offset {
                true
            } else {
                length_acc += r.frames * PAGE_SIZE;
                false
            }
        });
        match split_pos_in_vec_opt {
            None => Ok(None), // no need to split the vec
            Some(split_pos_in_vec) => {
                // ok, split the vec in two parts
                let mut vec_right = self.split_off(split_pos_in_vec);
                // and split right vec's first region
                match vec_right.first_mut().unwrap().right_split(offset - length_acc)? {
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

#[cfg(test)]
mod test {
    use super::super::{FrameAllocator, FrameAllocatorTrait};
    use super::{PhysicalMemRegion, PhysicalMemRegionIter};
    use crate::utils::Splittable;
    use crate::mem::PhysicalAddress;
    use crate::paging::PAGE_SIZE;

    #[test]
    #[should_panic]
    fn on_fixed_mmio_checks_reserved() {
        let _f = crate::frame_allocator::init();
        unsafe { PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(0x00000000), PAGE_SIZE) };
    }

    #[test]
    fn on_fixed_mmio_rounds_unaligned() {
        let _f = crate::frame_allocator::init();
        // reserve them so we don't panic
        crate::frame_allocator::mark_frame_bootstrap_allocated(PhysicalAddress(0));
        crate::frame_allocator::mark_frame_bootstrap_allocated(PhysicalAddress(PAGE_SIZE));

        let region = unsafe { PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(0x00000007), PAGE_SIZE + 1) };
        assert_eq!(region.start_addr, 0);
        assert_eq!(region.frames, 2);
    }

    #[test]
    #[should_panic]
    fn reconstruct_checks_was_allocated() {
        let _f = crate::frame_allocator::init();
        unsafe { PhysicalMemRegion::reconstruct(PhysicalAddress(0), 4 * PAGE_SIZE) };
    }

    #[test]
    #[should_panic]
    fn reconstruct_too_long() {
        let _f = crate::frame_allocator::init();
        unsafe { PhysicalMemRegion::reconstruct(PhysicalAddress(4 * PAGE_SIZE), 64 * PAGE_SIZE) };
    }

    #[test]
    fn reconstruct_no_dealloc_doesnt_dealloc() {
        let _f = crate::frame_allocator::init();
        let region = FrameAllocator::allocate_region(PAGE_SIZE).unwrap();
        let addr = region.address();
        ::core::mem::forget(region);
        let reconstruct = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(addr, PAGE_SIZE)};
        // drop shouldn't deallocate it
        drop(reconstruct);
        // meaning that we can reconstruct once again:
        let reconstruct = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(addr, PAGE_SIZE)};
        drop(reconstruct);
    }

    #[test]
    fn iterate_zero() {
        let region = PhysicalMemRegion { frames: 0, start_addr: 0, should_free_on_drop: false };
        assert_eq!(region.into_iter().count(), 0);
    }

    #[test]
    fn iterate_one() {
        let region = PhysicalMemRegion { frames: 1, start_addr: 0, should_free_on_drop: false };
        assert_eq!(region.into_iter().count(), 1);
    }

    #[test]
    fn iterate_five() {
        let region = PhysicalMemRegion { frames: 5, start_addr: 0, should_free_on_drop: false };
        assert_eq!(region.into_iter().count(), 5);
    }

    #[test]
    fn splittable_unaligned() {
        let mut left = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        left.split_at(7).unwrap_err();
    }

    #[test]
    fn splittable_len_zero_a() {
        let mut left = PhysicalMemRegion { frames: 0, start_addr: 0, should_free_on_drop: false };
        let right = left.split_at(PAGE_SIZE).unwrap();
        assert!(right.is_none())
    }

    #[test]
    fn splittable_len_zero_b() {
        let mut left = PhysicalMemRegion { frames: 0, start_addr: 0, should_free_on_drop: false };
        let right = left.split_at(0).unwrap();
        assert!(right.is_none())
    }

    #[test]
    fn splittable_split_at_zero() {
        let mut left = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        let right = left.split_at(0).unwrap();
        assert!(right.is_none())
    }

    #[test]
    fn splittable_split_at_too_big() {
        let mut left = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        let right = left.split_at(4 * PAGE_SIZE).unwrap();
        assert!(right.is_none())
    }

    #[test]
    fn splittable_split_at() {
        let mut left = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        let right_opt = left.split_at(3 * PAGE_SIZE).unwrap();
        let right = right_opt.unwrap();
        assert_eq!(left.start_addr, 0);
        assert_eq!(left.frames, 3);
        assert_eq!(right.start_addr, 3 * PAGE_SIZE);
        assert_eq!(right.frames, 1);
    }

    #[test]
    fn splittable_right_split_at() {
        let mut right = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        let left_opt = right.right_split(3 * PAGE_SIZE).unwrap();
        let left = left_opt.unwrap();
        assert_eq!(left.start_addr, 0);
        assert_eq!(left.frames, 3);
        assert_eq!(right.start_addr, 3 * PAGE_SIZE);
        assert_eq!(right.frames, 1);
    }

    #[test]
    fn right_split_unaligned() {
        let mut right = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        right.split_at(7).unwrap_err();
    }

    #[test]
    fn right_split_len_zero_a() {
        let mut right = PhysicalMemRegion { frames: 0, start_addr: 0, should_free_on_drop: false };
        let left = right.split_at(PAGE_SIZE).unwrap();
        assert!(left.is_none())

    }

    #[test]
    fn right_split_len_zero_b() {
        let mut right = PhysicalMemRegion { frames: 0, start_addr: 0, should_free_on_drop: false };
        let left = right.split_at(0).unwrap();
        assert!(left.is_none())
    }

    #[test]
    fn right_split_split_at_zero() {
        let mut right = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        let left = right.split_at(0).unwrap();
        assert!(left.is_none())
    }

    #[test]
    fn right_split_split_at_too_big() {
        let mut right = PhysicalMemRegion { frames: 4, start_addr: 0, should_free_on_drop: false };
        let left = right.split_at(4 * PAGE_SIZE).unwrap();
        assert!(left.is_none())
    }

    #[test]
    fn split_physmemregion_vec() {
        let region1 = PhysicalMemRegion { frames: 3, start_addr: 0, should_free_on_drop: false };
        let region2 = PhysicalMemRegion { frames: 2, start_addr: 16 * PAGE_SIZE, should_free_on_drop: false };
        let mut left = vec![region1, region2];
        let right_opt = left.split_at(PAGE_SIZE).unwrap();
        let right = right_opt.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].frames, 1);
        assert_eq!(right.len(), 2);
        assert_eq!(right[0].frames, 2);
        assert_eq!(right[1].frames, 2);
        assert_eq!(right[0].start_addr, PAGE_SIZE);
    }

    #[test]
    fn split_physmemregion_vec_exact_cut() {
        let region1 = PhysicalMemRegion { frames: 3, start_addr: 0, should_free_on_drop: false };
        let region2 = PhysicalMemRegion { frames: 2, start_addr: 16 * PAGE_SIZE, should_free_on_drop: false };
        let region3 = PhysicalMemRegion { frames: 5, start_addr: 32 * PAGE_SIZE, should_free_on_drop: false };
        let mut left = vec![region1, region2, region3];
        let right_opt = left.split_at(3 * PAGE_SIZE).unwrap();
        let right = right_opt.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].frames, 3);
        assert_eq!(left[0].start_addr, 0);
        assert_eq!(right.len(), 2);
        assert_eq!(right[0].frames, 2);
        assert_eq!(right[0].start_addr, 16 * PAGE_SIZE);
        assert_eq!(right[1].frames, 5);
        assert_eq!(right[1].start_addr, 32 * PAGE_SIZE);
    }

    #[test]
    fn split_physmemregion_vec_threshold() {
        let region1 = PhysicalMemRegion { frames: 3, start_addr: 0, should_free_on_drop: false };
        let region2 = PhysicalMemRegion { frames: 2, start_addr: 16 * PAGE_SIZE, should_free_on_drop: false };
        let region3 = PhysicalMemRegion { frames: 5, start_addr: 32 * PAGE_SIZE, should_free_on_drop: false };
        let mut left = vec![region1, region2, region3];
        let right_opt = left.split_at(9 * PAGE_SIZE).unwrap();
        let right = right_opt.unwrap();
        assert_eq!(left.len(), 3);
        assert_eq!(left[0].frames, 3);
        assert_eq!(left[0].start_addr, 0);
        assert_eq!(left[1].frames, 2);
        assert_eq!(left[1].start_addr, 16 * PAGE_SIZE);
        assert_eq!(left[2].frames, 4);
        assert_eq!(left[2].start_addr, 32 * PAGE_SIZE);
        assert_eq!(right.len(), 1);
        assert_eq!(right[0].frames, 1);
        assert_eq!(right[0].start_addr, (32 + 4) * PAGE_SIZE);
    }

    #[test]
    fn split_physmemregion_vec_unaligned() {
        let region1 = PhysicalMemRegion { frames: 3, start_addr: 0, should_free_on_drop: false };
        let region2 = PhysicalMemRegion { frames: 2, start_addr: 16 * PAGE_SIZE, should_free_on_drop: false };
        let mut left = vec![region1, region2];
        left.split_at(7).unwrap_err();
    }

    #[test]
    fn split_physmemregion_vec_zero() {
        let region1 = PhysicalMemRegion { frames: 3, start_addr: 0, should_free_on_drop: false };
        let region2 = PhysicalMemRegion { frames: 2, start_addr: 16 * PAGE_SIZE, should_free_on_drop: false };
        let mut left = vec![region1, region2];
        let right = left.split_at(0).unwrap();
        assert!(right.is_none());
    }

    #[test]
    fn split_physmemregion_vec_too_big() {
        let region1 = PhysicalMemRegion { frames: 3, start_addr: 0, should_free_on_drop: false };
        let region2 = PhysicalMemRegion { frames: 2, start_addr: 16 * PAGE_SIZE, should_free_on_drop: false };
        let mut left = vec![region1, region2];
        let right = left.split_at(5 * PAGE_SIZE).unwrap();
        assert!(right.is_none());
    }
}
