//! Mapping

use crate::mem::VirtualAddress;
use crate::paging::{PAGE_SIZE, MappingAccessRights};
use crate::error::KernelError;
use crate::frame_allocator::PhysicalMemRegion;
use alloc::{vec::Vec, sync::Arc};
use crate::utils::check_nonzero_length;
use failure::Backtrace;
use sunrise_libkern::{MemoryType, MemoryState};
use crate::sync::RwLock;

/// A memory mapping.
/// Stores the address, the length, and the type it maps.
/// A mapping is guaranteed to have page aligned address and length,
/// and the length will never be zero.
///
/// If the mapping maps physical frames, we also guarantee that the
/// the virtual length of the mapping is equal to the physical length it maps.
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

        VirtualAddress(length).check_aligned_to(PAGE_SIZE)?;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;

        let state = ty.get_memory_state();
        match (&frames, state.is_reference_counted(), ty) {
            (MappingFrames::None, _, MemoryType::Unmapped) => (),
            (MappingFrames::None, _, MemoryType::Reserved) => (),
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
    use super::MappingType;
    use crate::mem::{VirtualAddress, PhysicalAddress};
    use crate::paging::PAGE_SIZE;
    use crate::frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait};
    use std::sync::Arc;
    use std::vec::Vec;
    use crate::utils::Splittable;
    use crate::error::KernelError;

    /// Applies the same tests to guard, available and system_reserved.
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
                    Mapping:: "new_" $x (VirtualAddress(0x40000000), 3 * PAGE_SIZE).unwrap();
                }

                #[test]
                fn "mapping_zero_length_" $x () {
                    Mapping:: "new_" $x (VirtualAddress(0x40000000), 0).unwrap_err();
                }

                #[test]
                fn "mapping_non_aligned_addr_" $x () {
                    Mapping::"new_" $x (VirtualAddress(0x40000007), 3 * PAGE_SIZE).unwrap_err();
                }

                #[test]
                fn "mapping_non_aligned_length_" $x () {
                    Mapping::"new_" $x (VirtualAddress(0x40000000), 3).unwrap_err();
                }

                #[test]
                fn "mapping_length_threshold_" $x () {
                    Mapping::"new_" $x (VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), 2 * PAGE_SIZE).unwrap();
                }

                #[test]
                fn "mapping_length_overflow_" $x () {
                    Mapping::"new_" $x (VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), 3 * PAGE_SIZE).unwrap_err();
                }
                )*
            }
        }
    }

    test_empty_mapping!(guard, available, system_reserved);

    #[test]
    fn mapping_regular_ok() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new_regular(VirtualAddress(0x40000000), frames, flags).unwrap();
    }

    #[test]
    fn mapping_shared_ok() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap());
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new_shared(VirtualAddress(0x40000000), frames, flags).unwrap();
    }

    #[test]
    fn mapping_regular_empty_vec() {
        let _f = crate::frame_allocator::init();
        let frames = Vec::new();
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_regular(VirtualAddress(0x40000000), frames, flags).unwrap_err();
    }

    #[test]
    fn mapping_shared_empty_vec() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(Vec::new());
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_shared(VirtualAddress(0x40000000), frames, flags).unwrap_err();
    }

    #[test]
    fn mapping_regular_zero_sized_region() {
        let _f = crate::frame_allocator::init();
        let region = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(PhysicalAddress(PAGE_SIZE), 0) };
        let frames = vec![region];
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_regular(VirtualAddress(0x40000000), frames, flags).unwrap_err();
    }

    #[test]
    fn mapping_regular_zero_sized_regions() {
        let _f = crate::frame_allocator::init();
        let region1 = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(PhysicalAddress(PAGE_SIZE), 0) };
        let region2 = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(PhysicalAddress(PAGE_SIZE), 0) };
        let frames = vec![region1, region2];
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_regular(VirtualAddress(0x40000000), frames, flags).unwrap_err();
    }

    #[test]
    fn mapping_regular_unaligned_addr() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_regular(VirtualAddress(0x40000007), frames, flags).unwrap_err();
    }

    #[test]
    fn mapping_shared_unaligned_addr() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap());
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_shared(VirtualAddress(0x40000007), frames, flags).unwrap_err();
    }


    #[test]
    #[should_panic]
    fn mapping_regular_unaligned_len() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE + 7).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new_regular(VirtualAddress(0x40000000), frames, flags).unwrap();
    }

    #[test]
    #[should_panic]
    fn mapping_shared_unaligned_len() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE + 7).unwrap());
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new_shared(VirtualAddress(0x40000000), frames, flags).unwrap();
    }

    #[test]
    fn mapping_regular_threshold() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new_regular(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), frames, flags).unwrap();
    }

    #[test]
    fn mapping_shared_threshold() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap());
        let flags = MappingAccessRights::u_rw();
        let _mapping = Mapping::new_shared(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE + 1), frames, flags).unwrap();
    }

    #[test]
    fn mapping_regular_overflow() {
        let _f = crate::frame_allocator::init();
        let frames = FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap();
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_regular(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE), frames, flags).unwrap_err();
    }

    #[test]
    fn mapping_shared_overflow() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(FrameAllocator::allocate_frames_fragmented(2 * PAGE_SIZE).unwrap());
        let flags = MappingAccessRights::u_rw();
        let _mapping_err = Mapping::new_shared(VirtualAddress(usize::max_value() - 2 * PAGE_SIZE), frames, flags).unwrap_err();
    }

    /// Splitting a mapping should only be valid for a PAGE_SIZE aligned offset.
    #[test]
    fn splittable_unaligned() {
        let _f = crate::frame_allocator::init();
        let frames = vec![FrameAllocator::allocate_region(3 * PAGE_SIZE).unwrap()];
        let mut mapping = Mapping::new_regular(VirtualAddress(2 * PAGE_SIZE), frames, MappingAccessRights::k_r()).unwrap();
        match mapping.split_at(PAGE_SIZE + 1).unwrap_err() {
            KernelError::InvalidSize { .. } => (),
            unexpected_err => panic!("test failed, error {:?}", unexpected_err)
        }
        // check mapping was untouched
        assert_eq!(mapping.address(), VirtualAddress(2 * PAGE_SIZE));
        assert_eq!(mapping.length(), 3 * PAGE_SIZE);
        if let MappingType::Regular(held_frames) = mapping.mtype_ref() {
            assert_eq!(held_frames.iter().flatten().count(), 3)
        } else {
            panic!("test failed, splitting changed type")
        }
    }

    /// Splitting a shared mapping should unconditionally fail.
    #[test]
    fn splittable_shared() {
        let _f = crate::frame_allocator::init();
        let frames = Arc::new(vec![FrameAllocator::allocate_region(3 * PAGE_SIZE).unwrap()]);
        let mut mapping = Mapping::new_shared(VirtualAddress(2 * PAGE_SIZE), frames, MappingAccessRights::k_r()).unwrap();
        match mapping.split_at(0).unwrap_err() {
            KernelError::InvalidAddress { .. } => (),
            unexpected_err => panic!("test failed, error {:?}", unexpected_err)
        }
        // check mapping was untouched
        assert_eq!(mapping.address(), VirtualAddress(2 * PAGE_SIZE));
        assert_eq!(mapping.length(), 3 * PAGE_SIZE);
        if let MappingType::Shared(held_frames) = mapping.mtype_ref() {
            assert_eq!(held_frames.iter().flatten().count(), 3)
        } else {
            panic!("test failed, splitting changed type")
        }
    }

    /// Splitting a system reserved mapping should unconditionally fail.
    #[test]
    fn splittable_system_reserved() {
        let mut mapping = Mapping::new_system_reserved(VirtualAddress(2 * PAGE_SIZE), 3 * PAGE_SIZE).unwrap();
        match mapping.split_at(0).unwrap_err() {
            KernelError::InvalidAddress { .. } => (),
            unexpected_err => panic!("test failed, error {:?}", unexpected_err)
        }
        // check mapping was untouched
        assert_eq!(mapping.address(), VirtualAddress(2 * PAGE_SIZE));
        assert_eq!(mapping.length(), 3 * PAGE_SIZE);
        if let MappingType::SystemReserved = mapping.mtype_ref() {
            // ok
        } else {
            panic!("test failed, splitting changed type")
        }
    }

    #[test]
    fn splittable_split_at_zero() {
        let _f = crate::frame_allocator::init();
        let frames = vec![FrameAllocator::allocate_region(3 * PAGE_SIZE).unwrap()];
        let mut mapping = Mapping::new_regular(VirtualAddress(2 * PAGE_SIZE), frames, MappingAccessRights::k_r()).unwrap();
        let right = mapping.split_at(0).unwrap();
        assert!(right.is_none());
        // check mapping was untouched
        assert_eq!(mapping.address(), VirtualAddress(2 * PAGE_SIZE));
        assert_eq!(mapping.length(), 3 * PAGE_SIZE);
        if let MappingType::Regular(held_frames) = mapping.mtype_ref() {
            assert_eq!(held_frames.iter().flatten().count(), 3)
        } else {
            panic!("test failed, splitting changed type")
        }
    }

    #[test]
    fn splittable_split_at_too_big() {
        let _f = crate::frame_allocator::init();
        let frames = vec![FrameAllocator::allocate_region(3 * PAGE_SIZE).unwrap()];
        let mut mapping = Mapping::new_regular(VirtualAddress(2 * PAGE_SIZE), frames, MappingAccessRights::k_r()).unwrap();
        let right = mapping.split_at(3 * PAGE_SIZE).unwrap();
        assert!(right.is_none());
        // check mapping was untouched
        assert_eq!(mapping.address(), VirtualAddress(2 * PAGE_SIZE));
        assert_eq!(mapping.length(), 3 * PAGE_SIZE);
        if let MappingType::Regular(held_frames) = mapping.mtype_ref() {
            assert_eq!(held_frames.iter().flatten().count(), 3)
        } else {
            panic!("test failed, splitting changed type")
        }
    }

    #[test]
    fn splittable_split_at() {
        let _f = crate::frame_allocator::init();
        let frames = vec![FrameAllocator::allocate_region(3 * PAGE_SIZE).unwrap()];
        let mut left = Mapping::new_regular(VirtualAddress(5 * PAGE_SIZE), frames, MappingAccessRights::k_r()).unwrap();
        // 3 -> 2 + 1
        let right = left.split_at(2 * PAGE_SIZE).unwrap().unwrap();

        assert_eq!(left.address(), VirtualAddress(5 * PAGE_SIZE));
        assert_eq!(left.length(), 2 * PAGE_SIZE);
        if let MappingType::Regular(held_frames) = left.mtype_ref() {
            assert_eq!(held_frames.iter().flatten().count(), 2)
        } else {
            panic!("test failed, splitting changed type")
        }

        assert_eq!(right.address(), VirtualAddress((5 + 2) * PAGE_SIZE));
        assert_eq!(right.length(), 1 * PAGE_SIZE);
        if let MappingType::Regular(held_frames) = right.mtype_ref() {
            assert_eq!(held_frames.iter().flatten().count(), 1)
        } else {
            panic!("test failed, splitting changed type")
        }
    }
}
