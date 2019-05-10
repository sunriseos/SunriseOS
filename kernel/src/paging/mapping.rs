//! Mapping

use crate::mem::VirtualAddress;
use crate::paging::{PAGE_SIZE, MappingAccessRights};
use crate::error::KernelError;
use crate::frame_allocator::PhysicalMemRegion;
use alloc::{vec::Vec, sync::Arc};
use crate::utils::check_nonzero_length;
use failure::Backtrace;
use sunrise_libkern::{MemoryType, MemoryState};
use crate::sync::{RwLock, RwLockReadGuard};
use core::ops::Range;
use core::iter::StepBy;
use crate::mem::PhysicalAddress;

/// A memory mapping.
/// Stores the address, the length, and the type it maps.
/// A mapping is guaranteed to have page aligned address, length and offset,
/// and the length will never be zero.
///
/// If the mapping maps physical frames, we also guarantee that the mapping
/// contains enough physical frames to cover the whole virtual mapping (taking
/// into account length and offset).
///
/// Getting the last address of this mapping (length - 1 + address) is guaranteed to not overflow.
/// However we do not make any assumption on address + length, which falls outside of the mapping.
#[derive(Debug)]
#[allow(clippy::len_without_is_empty)] // length **cannot** be zero.
pub struct Mapping {
    /// The first address of this mapping.
    address: VirtualAddress,
    /// The length of this mapping.
    length: usize,
    /// The type of this mapping.
    state: MemoryState,
    /// The frames this mapping is referencing.
    frames: MappingFrames,
    /// Physical frame offset of this mapping,
    offset: usize,
    /// The access rights of this mapping.
    flags: MappingAccessRights,
}

/// Frames associated with a [Mapping].
#[derive(Debug)]
pub enum MappingFrames {
    /// The frames are Shared between multiple mappings.
    Shared(Arc<RwLock<Vec<PhysicalMemRegion>>>),
    /// The frames are Owned by this mapping.
    Owned(Vec<PhysicalMemRegion>),
    /// This Mapping has no frames.
    None,
}

impl Mapping {
    /// Tries to construct a mapping.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * `address` is not page aligned.
    ///     * `offset` is not page aligned.
    ///     * `offset` is bigger than the amount of pages in `frames`.
    ///     * `address` plus `length` would overflow.
    /// * `InvalidSize`:
    ///     * `length` is bigger than the amount of pages in `frames`, minus the offset.
    ///     * `length` is zero.
    ///     * `length` is not page-aligned.
    /// * `WrongMappingFramesForTy`:
    ///     * `frames` didnt' contain the variant of [MappingFrames] expected by `ty`.
    pub fn new(address: VirtualAddress, frames: MappingFrames, offset: usize, length: usize, ty: MemoryType, flags: MappingAccessRights) -> Result<Mapping, KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        VirtualAddress(offset).check_aligned_to(PAGE_SIZE)?;
        VirtualAddress(length).check_aligned_to(PAGE_SIZE)?;
        check_nonzero_length(length)?;

        let frames_len = match &frames {
            MappingFrames::Owned(v) => v.iter().flatten().count() * PAGE_SIZE,
            MappingFrames::Shared(v) => v.read().iter().flatten().count() * PAGE_SIZE,
            MappingFrames::None => usize::max_value()
        };

        if frames_len < offset {
            return Err(KernelError::InvalidAddress { address: offset, backtrace: Backtrace::new() });
        }

        if frames_len - offset < length {
            return Err(KernelError::InvalidSize { size: length, backtrace: Backtrace::new() });
        }

        address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;

        let state = ty.get_memory_state();
        match (&frames, state.is_reference_counted(), ty) {
            (MappingFrames::None, _, MemoryType::Unmapped) => (),
            (MappingFrames::None, _, MemoryType::Reserved) => (),
            (MappingFrames::None, _, MemoryType::KernelStack) => (),
            (MappingFrames::Shared(_), true, _) => (),
            (MappingFrames::Owned(_), false, _) => (),
            _ => return Err(KernelError::WrongMappingFramesForTy { ty, backtrace: Backtrace::new() })
        }

        Ok(Mapping { address, frames, offset, length, state: ty.get_memory_state(), flags })
    }

    /// Returns the address of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn address(&self) -> VirtualAddress { self.address }

    /// Returns the address of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn length(&self) -> usize { self.length }

    /// Returns the frames in this mapping.
    pub fn frames(&self) -> &MappingFrames { &self.frames }

    /// Returns an iterator over the Physical Addresses mapped by this region.
    /// This takes into account the physical offset and the length of the
    /// mapping.
    pub fn frames_it(&self) -> impl Iterator<Item = PhysicalAddress> + Clone + core::fmt::Debug + '_ {
        /// Anonymous iterator over mapping frames' PhysicalAddresses.
        #[derive(Debug)]
        enum MappingFramesIt<'a> {
            None,
            Owned(&'a [PhysicalMemRegion], usize, StepBy<Range<usize>>),
            Shared(&'a Arc<RwLock<Vec<PhysicalMemRegion>>>, RwLockReadGuard<'a, Vec<PhysicalMemRegion>>, usize, StepBy<Range<usize>>),
        }
        impl<'a> Iterator for MappingFramesIt<'a> {
            type Item = PhysicalAddress;
            fn next(&mut self) -> Option<Self::Item> {
                let (frames, curframe, rangeit) = match self {
                    MappingFramesIt::Owned(ref frames, ref mut curframe, ref mut rangeit) => {
                        (*frames, curframe, rangeit)
                    },
                    MappingFramesIt::Shared(_, frames, ref mut curframe, ref mut rangeit) => {
                        (&***frames, curframe, rangeit)
                    },
                    _ => return None
                };

                if let Some(s) = rangeit.next().map(PhysicalAddress) {
                    Some(s)
                } else if *curframe < frames.len() {
                    let frame = &frames[*curframe];
                    *rangeit = (frame.address().0..frame.address().0 + frame.size()).step_by(PAGE_SIZE);
                    *curframe += 1;
                    rangeit.next().map(PhysicalAddress)
                } else {
                    None
                }
            }
        }

        impl<'a> Clone for MappingFramesIt<'a> {
            fn clone(&self) -> MappingFramesIt<'a> {
                match self {
                    MappingFramesIt::Owned(frames, curframe, rangeit) => MappingFramesIt::Owned(frames, *curframe, rangeit.clone()),
                    MappingFramesIt::Shared(frames, _lock, curframe, rangeit) => MappingFramesIt::Shared(frames, frames.read(), *curframe, rangeit.clone()),
                    MappingFramesIt::None => MappingFramesIt::None,
                }
            }
        }

        let it = match self.frames() {
            MappingFrames::Owned(frames) => MappingFramesIt::Owned(&frames[..], 0, (0..0).step_by(1)),
            MappingFrames::Shared(frames) => MappingFramesIt::Shared(frames, frames.read(), 0, (0..0).step_by(1)),
            MappingFrames::None => MappingFramesIt::None,
        };
        it
            .skip(self.phys_offset() / PAGE_SIZE)
            .take(self.length() / PAGE_SIZE)
    }

    /// Returns the offset in `frames` this mapping starts from.
    ///
    /// This will be different from 0 when this mapping was created as a partial
    /// remapping of a different shared memory mapping (such as when creating
    /// an IPC buffer).
    pub fn phys_offset(&self) -> usize { self.offset }

    /// Returns the [MemoryState] of this mapping.
    pub fn state(&self) -> MemoryState { self.state }

    /// Returns the type of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn flags(&self) -> MappingAccessRights { self.flags }
}

#[cfg(test)]
mod test {
    use super::Mapping;
    use super::MappingAccessRights;
    use super::MappingFrames;
    use super::MemoryType;
    use crate::mem::{VirtualAddress, PhysicalAddress};
    use crate::paging::PAGE_SIZE;
    use crate::frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait};
    use std::sync::Arc;
    use std::vec::Vec;
    use crate::utils::Splittable;
    use crate::error::KernelError;
    use crate::sync::RwLock;

    /// Applies the same tests to Unmapped, Reserved and KernelStack.
    macro_rules! test_empty_mapping {
        ($($x:ident),*) => {
            mashup! {
                $(
                m["new_" $x] = new_ $x;
                m["mapping_ok_" $x] = $x _mapping_ok;
                m["mapping_zero_length_" $x] = $x _mapping_zero_length;
                m["mapping_non_aligned_addr_" $x] = $x _mapping_non_aligned_addr;
                m["mapping_non_aligned_length_" $x] = $x _mapping_non_aligned_length;
                m["mapping_length_threshold_" $x] = $x _mapping_length_threshold;
                m["mapping_length_overflow_" $x] = $x _mapping_length_overflow;
                )*
            }
            m! {
                $(
                #[test]
                fn "mapping_ok_" $x () {
                    Mapping::new(VirtualAddress(0x40000000), MappingFrames::None, 0, 3 * PAGE_SIZE, MemoryType::$x, MappingAccessRights::empty()).unwrap();
                }

                #[test]
                fn "mapping_zero_length_" $x () {
                    Mapping::new(VirtualAddress(0x40000000), MappingFrames::None, 0, 0, MemoryType::$x, MappingAccessRights::empty()).unwrap_err();
                }

                #[test]
                fn "mapping_non_aligned_addr_" $x () {
                    Mapping::new(VirtualAddress(0x40000007), MappingFrames::None, 0, 3 * PAGE_SIZE, MemoryType::$x, MappingAccessRights::empty()).unwrap_err();
                }

                #[test]
                fn "mapping_non_aligned_length_" $x () {
                    Mapping::new(VirtualAddress(0x40000000), MappingFrames::None, 0, 3, MemoryType::$x, MappingAccessRights::empty()).unwrap_err();
                }

                #[test]
                fn "mapping_length_threshold_" $x () {
                    Mapping::new(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), MappingFrames::None, 0, 2 * PAGE_SIZE, MemoryType::$x, MappingAccessRights::empty()).unwrap();
                }

                #[test]
                fn "mapping_length_overflow_" $x () {
                    Mapping::new(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), MappingFrames::None, 0, 3 * PAGE_SIZE, MemoryType::$x, MappingAccessRights::empty()).unwrap_err();
                }
                )*
            }
        }
    }

    test_empty_mapping!(Unmapped, Reserved, KernelStack);

    #[test]
    fn mapping_regular_ok() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Owned(frames), 0, 2 * PAGE_SIZE, MemoryType::Normal, flags).unwrap();
    }

    #[test]
    fn mapping_shared_ok() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(RwLock::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap()));
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Shared(frames), 0, 2 * PAGE_SIZE, MemoryType::Stack, flags).unwrap();
    }

    #[test]
    fn mapping_regular_empty_vec() {
        let _f = crate::frame_allocator::init();
        let frames = Vec::new();
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Owned(frames), 0, 2 * PAGE_SIZE, MemoryType::Normal, flags).unwrap_err();
    }

    #[test]
    fn mapping_shared_empty_vec() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(RwLock::new(Vec::new()));
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Shared(frames), 0, 2 * PAGE_SIZE, MemoryType::Stack, flags).unwrap_err();
    }

    #[test]
    fn mapping_regular_zero_sized_region() {
        let _f = crate::frame_allocator::init();
        let region = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(PhysicalAddress(PAGE_SIZE), 0) };
        let frames = vec![region];
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Owned(frames), 0, 0, MemoryType::Normal, flags).unwrap_err();
    }

    #[test]
    fn mapping_regular_zero_sized_regions() {
        let _f = crate::frame_allocator::init();
        let region1 = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(PhysicalAddress(PAGE_SIZE), 0) };
        let region2 = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(PhysicalAddress(PAGE_SIZE), 0) };
        let frames = vec![region1, region2];
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Owned(frames), 0, 0, MemoryType::Normal, flags).unwrap_err();
    }

    #[test]
    fn mapping_regular_unaligned_addr() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new(VirtualAddress(0x40000007), MappingFrames::Owned(frames), 0, 2 * PAGE_SIZE, MemoryType::Normal, flags).unwrap_err();
    }

    #[test]
    fn mapping_shared_unaligned_addr() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(RwLock::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap()));
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new(VirtualAddress(0x40000007), MappingFrames::Shared(frames), 0, 2 * PAGE_SIZE, MemoryType::Stack, flags).unwrap_err();
    }


    #[test]
    #[should_panic]
    fn mapping_regular_unaligned_len() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE + 7).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Owned(frames), 0, 2 * PAGE_SIZE + 7, MemoryType::Normal, flags).unwrap();
    }

    #[test]
    #[should_panic]
    fn mapping_shared_unaligned_len() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(RwLock::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE + 7).unwrap()));
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(0x40000000), MappingFrames::Shared(frames), 0, 2 * PAGE_SIZE + 7, MemoryType::Stack, flags).unwrap();
    }

    #[test]
    fn mapping_regular_threshold() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), MappingFrames::Owned(frames), 0, 2 * PAGE_SIZE, MemoryType::Normal, flags).unwrap();
    }

    #[test]
    fn mapping_shared_threshold() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(RwLock::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap()));
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), MappingFrames::Shared(frames), 0, 2 * PAGE_SIZE, MemoryType::Stack, flags).unwrap();
    }

    #[test]
    fn mapping_regular_overflow() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE), MappingFrames::Owned(frames), 0, 2 * PAGE_SIZE, MemoryType::Normal, flags).unwrap_err();
    }

    #[test]
    fn mapping_shared_overflow() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(RwLock::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap()));
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE), MappingFrames::Shared(frames), 0, 2 * PAGE_SIZE, MemoryType::Stack, flags).unwrap_err();
    }

    #[test]
    fn mapping_shared_offset() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();

        // Get the address that will get mapped
        let test_addr = frames.iter().flatten().last().unwrap();

        let frames = Arc::new(RwLock::new(frames));
        let flags = MappingAccessRights::u_rw();
        let mapping = Mapping::new(VirtualAddress(0), MappingFrames::Shared(frames), 1 * PAGE_SIZE, 1 * PAGE_SIZE, MemoryType::Stack, flags).unwrap();
        assert!(mapping.frames_it().count() == 1, "Frames_it has the wrong size.");
        assert!(mapping.frames_it().next().unwrap() == test_addr, "Frames_it has the wrong value.");
    }

    #[test]
    fn mapping_shared_offset_overflow() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(RwLock::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap()));
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new(VirtualAddress(0), MappingFrames::Shared(frames), 1 * PAGE_SIZE, 2 * PAGE_SIZE, MemoryType::Stack, flags).unwrap_err();
    }
}
