//! Mapping

use crate::mem::VirtualAddress;
use crate::paging::{PAGE_SIZE, MappingAccessRights};
use crate::error::KernelError;
use crate::frame_allocator::PhysicalMemRegion;
use alloc::{vec::Vec, sync::Arc};
use crate::utils::{check_size_aligned, check_nonzero_length, Splittable};
use failure::Backtrace;
use kfs_libkern;

/// A memory mapping.
/// Stores the address, the length, and the type it maps.
///
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
    /// The type of this mapping, and frames it maps.
    mtype: MappingType,
    /// The access rights of this mapping.
    flags: MappingAccessRights,
}

/// The types that a UserSpace mapping can be in.
///
/// If it maps physical memory regions, we hold them in a Vec.
/// They will be de-allocated when this enum is dropped.
#[derive(Debug)]
pub enum MappingType {
    /// Available, nothing is stored there. Accessing to it will page fault.
    /// An allocation can use this region.
    Available,
    /// Guarded, like Available, but nothing can be allocated here.
    /// Used to implement guard pages.
    Guarded,
    /// Regular, a region known only by this process.
    /// Access rights are stored in Mapping.mtype.
    Regular(Vec<PhysicalMemRegion>),
//    Stack(Vec<PhysicalMemRegion>),
    /// Shared, a region that can be mapped in multiple processes.
    /// Access rights are stored in Mapping.mtype.
    Shared(Arc<Vec<PhysicalMemRegion>>),
    /// SystemReserved, used to denote the KernelLand and other similar regions that the user
    /// cannot access, and shouldn't know anything more about.
    /// Cannot be unmapped, nor modified in any way.
    SystemReserved
}

impl<'a> From<&'a MappingType> for kfs_libkern::MemoryType {
    fn from(ty: &'a MappingType) -> kfs_libkern::MemoryType {
        match ty {
            // TODO: Extend MappingType to cover all MemoryTypes
            // BODY: Currently, MappingType only covers a very limited view of the mappings.
            // It should have the ability to understand all the various kind of memory allocations,
            // such as "Heap", "CodeMemory", "SharedMemory", "TransferMemory", etc...

            MappingType::Available => kfs_libkern::MemoryType::Unmapped,
            MappingType::Guarded => kfs_libkern::MemoryType::Reserved,
            MappingType::Regular(_) => kfs_libkern::MemoryType::Normal,
            MappingType::Shared(_) => kfs_libkern::MemoryType::SharedMemory,
            MappingType::SystemReserved => kfs_libkern::MemoryType::Reserved,
        }
    }
}

impl Mapping {
    /// Tries to construct a regular mapping.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * `address` is not page aligned.
    ///     * `address` + `frames`'s length would overflow.
    /// * `InvalidSize`:
    ///     * `frames` is empty.
    pub fn new_regular(address: VirtualAddress, frames: Vec<PhysicalMemRegion>, flags: MappingAccessRights) -> Result<Mapping, KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        let length = frames.iter().flatten().count() * PAGE_SIZE;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;
        Ok(Mapping { address, length, mtype: MappingType::Regular(frames), flags })
    }

    /// Tries to construct a shared mapping.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * `address` is not page aligned.
    ///     * `address` + `frame`'s length would overflow.
    /// * `InvalidSize`:
    ///     * `frames` is empty.
    pub fn new_shared(address: VirtualAddress, frames: Arc<Vec<PhysicalMemRegion>>, flags: MappingAccessRights) -> Result<Mapping, KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        let length = frames.iter().flatten().count() * PAGE_SIZE;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;
        Ok(Mapping { address, length, mtype: MappingType::Shared(frames), flags })
    }

    /// Tries to construct a guarded mapping.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * `address` is not page aligned.
    ///     * `address + length - 1` would overflow.
    /// * `InvalidSize`:
    ///     * `length` is not page aligned.
    ///     * `length` is 0.
    pub fn new_guard(address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        check_size_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;
        Ok(Mapping { address, length, mtype: MappingType::Guarded, flags: MappingAccessRights::empty() })
    }

    /// Tries to construct an available mapping.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * `address` is not page aligned.
    ///     * `address + length - 1` would overflow.
    /// * `InvalidSize`:
    ///     * `length` is not page aligned.
    ///     * `length` is 0.
    pub fn new_available(address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        check_size_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;
        Ok(Mapping { address, length, mtype: MappingType::Available, flags: MappingAccessRights::empty() })
    }

    /// Tries to construct a system reserved mapping.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * `address` is not page aligned.
    ///     * `address + length - 1` would overflow.
    /// * `InvalidSize`:
    ///     * `length` is not page aligned.
    ///     * `length` is 0.
    pub fn new_system_reserved(address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        check_size_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;
        Ok(Mapping { address, length, mtype: MappingType::SystemReserved, flags: MappingAccessRights::empty() })
    }

    /// Returns the address of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn address(&self) -> VirtualAddress { self.address }

    /// Returns the address of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn length(&self) -> usize { self.length }

    /// Returns a reference to the type of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn mtype_ref(&self) -> &MappingType { &self.mtype }

    /// Returns the type of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn mtype(self) -> MappingType { self.mtype }

    /// Returns the type of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn flags(&self) -> MappingAccessRights { self.flags }
}

impl Splittable for Mapping {
    /// Splits a mapping at a given offset.
    ///
    /// Because it is reference counted, a Shared mapping cannot be splitted.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * shared or system reserved mapping, which cannot be split.
    /// * `InvalidSize`:
    ///     * `offset` is not page aligned.
    fn split_at(&mut self, offset: usize) -> Result<Option<Self>, KernelError> {
        check_size_aligned(offset, PAGE_SIZE)?;
        match self.mtype_ref() {
            MappingType::Shared(_) | MappingType::SystemReserved => return Err(KernelError::InvalidAddress { address: self.address.addr(), backtrace: Backtrace::new() }),
            _ => ()
        }

        if offset == 0 || offset >= self.length { return Ok(None) };
        let right = Mapping {
            address: self.address + offset,
            length: self.length - offset,
            flags: self.flags,
            mtype: match &mut self.mtype {
                MappingType::Shared(_) | MappingType::SystemReserved => unreachable!(),
                MappingType::Available => MappingType::Available,
                MappingType::Guarded => MappingType::Guarded,
                MappingType::Regular(ref mut frames) => MappingType::Regular(frames.split_at(offset)?.unwrap()),
            },
        };
        // split succeeded, now modify left part
        self.length = offset;
        Ok(Some(right))
    }
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
