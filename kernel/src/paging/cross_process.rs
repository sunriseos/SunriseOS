//! Cross Process Mapping
//!
//! Provides mechanics for temporarily mirroring a Userland mapping in KernelLand.
//!
//! When kernel has to access memory in UserLand (for example a user has provided a buffer as an
//! argument of a syscall), it can do it in two ways:
//!
//! * Either the buffer is mapped in the same page tables that the kernel is currently using,
//!   in this case it accesses it directly, through a UserspacePtr.
//! * Either the buffer is only mapped in the page tables of another process, in which case
//!   it has to temporarily map it to KernelLand, make the modifications, and unmap it from KernelLand.
//!
//! This module covers the second case.
//!
//! The remapping is represented by an CrossProcessMapping structure. It is created from a reference
//! to the mapping being mirrored, and the KernelLand address where it will be remapped.
//! When this struct is dropped, the frames are unmap'd from KernelLand.
//!
//! A CrossProcessMapping is temporary by nature, and has the same lifetime as the reference to the
//! mapping it remaps, which is chained to the lifetime of the lock protecting ProcessMemory.
//!
//! Because of this, a CrossProcessMapping cannot outlive the ProcessMemory lock guard held by the
//! function that created it. This ensures that:
//!
//! * All CrossProcessMappings will be unmapped before returning to UserSpace.
//! * Another thread cannot make any modification to a ProcessMemory while a CrossProcessMapping
//!   exists for this ProcessMemory.
//! * The UserLand side of the mapping cannot be deleted while it is still being mirrored,
//!   as this would require a mutable borrow of the ProcessMemory lock,
//!   and it is currently (constly) borrowed by the CrossProcessMapping.
//!

use crate::mem::VirtualAddress;
use super::{PAGE_SIZE, MappingFlags};
use super::mapping::{Mapping, MappingType};
use super::kernel_memory::get_kernel_memory;
use super::error::MmError;
use crate::utils::{check_nonzero_length, add_or_error};
use failure::Backtrace;
use crate::error::KernelError;

/// A struct representing a UserLand mapping temporarily mirrored in KernelSpace.
pub struct CrossProcessMapping<'a> {
    kernel_address: VirtualAddress,
    len: usize,
    mapping: &'a Mapping,
}

impl<'a> CrossProcessMapping<'a> {
    /// Creates a CrossProcessMapping.
    ///
    /// Temporarily remaps a subsection of the mapping in KernelLand.
    ///
    /// # Error
    ///
    /// Returns an Error if the mapping is Available/Guarded/SystemReserved, as there would be
    /// no point to remap it, and dereferencing the pointer would cause the kernel to page-fault.
    /// Returns an Error if `offset` + `len` > `mapping` length.
    /// Returns an Error if `offset` + `len` would overflow.
    // todo: should be offset + (len - 1), but need to check that it wouldn't overflow in our function
    /// Returns an Error if `len` is 0.
    pub fn mirror_mapping(mapping: &Mapping, offset: usize, len: usize) -> Result<CrossProcessMapping, KernelError> {
        check_nonzero_length(len)?;
        if add_or_error(offset, len)? > mapping.length() {
            return Err(KernelError::MmError(MmError::InvalidMapping { backtrace: Backtrace::new() }))
        }
        let regions = match mapping.mtype_ref() {
            MappingType::Guarded | MappingType::Available | MappingType::SystemReserved
                => return Err(KernelError::MmError(MmError::InvalidMapping { backtrace: Backtrace::new() })),
            MappingType::Regular(ref f) => f,
            //MappingType::Stack(ref f) => f,
            MappingType::Shared(ref f) => f
        };
        let map_start = (mapping.address() + offset).floor();
        let map_end = (mapping.address() + offset + len).ceil();
        // iterator[map_start..map_end]
        let frames_iterator = regions.iter().flatten()
            .skip((map_start - mapping.address()) / PAGE_SIZE)
            .take((map_end - map_start) / PAGE_SIZE);
        let kernel_map_start = unsafe {
            // safe, the frames won't be dropped, they still are tracked by the userspace mapping.
            get_kernel_memory().map_frame_iterator(frames_iterator, MappingFlags::k_rw())
        };
        Ok(CrossProcessMapping {
            kernel_address: kernel_map_start + (offset % PAGE_SIZE),
            mapping,
            len,
        })
    }

    /// The address of the region asked to be remapped.
    pub fn addr(&self) -> VirtualAddress {
        self.kernel_address
    }

    /// The length of the region asked to be remapped.
    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'a> Drop for CrossProcessMapping<'a> {
    /// Unmaps itself from KernelLand when dropped.
    fn drop(&mut self) {
        let map_start = self.kernel_address.floor();
        let map_len = (self.kernel_address + self.len).ceil() - map_start;
        // don't dealloc the frames, they are still tracked by the mapping
        get_kernel_memory().unmap_no_dealloc(map_start, map_len)
    }
}
