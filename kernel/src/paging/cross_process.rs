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
// todo
//! For now we only support mirroring the whole mapping, but being able to mirror only a single
//! frame would be really nice.

use mem::VirtualAddress;
use super::{PAGE_SIZE, MappingFlags};
use super::bookkeeping::{Mapping, MappingType, UserspaceBookkeeping};
use super::process_memory::ProcessMemory;
use super::kernel_memory::get_kernel_memory;
use super::error::MmError;
use utils::{check_aligned, check_nonzero_length};
use failure::Backtrace;
use error::KernelError;

/// A struct representing a UserLand mapping temporarily mirrored in KernelSpace.
pub struct CrossProcessMapping<'a> {
    kernel_address: VirtualAddress,
    mapping: &'a Mapping,
    offset: usize,
    len: usize,
    // keep at least one private field, to forbid it from being constructed.
    private: ()
}

impl<'a> CrossProcessMapping<'a> {
    /// Creates a CrossProcessMapping.
    ///
    /// Temporarily remaps the whole mapping in KernelLand.
    ///
    /// # Error
    ///
    /// Returns an Error if the mapping is Available/Guarded/SystemReserved, as there would be
    /// no point to remap it, and dereferencing the pointer would cause the kernel to page-fault.
    pub fn mirror_mapping(mapping: &Mapping, offset: usize, len: usize) -> Result<CrossProcessMapping, KernelError> {
        let frames = match mapping.mtype {
            MappingType::Guarded | MappingType::Available | MappingType::SystemReserved
                => return Err(KernelError::MmError(MmError::InvalidMapping { backtrace: Backtrace::new() })),
            MappingType::Regular(ref f) => f,
            MappingType::Stack(ref f) => f,
            MappingType::Shared(ref f) => f
        };
        let kernel_address = unsafe {
            // safe, the frames won't be dropped, they still are tracked by the userspace mapping.
            get_kernel_memory().map_phys_regions(frames, MappingFlags::u_rw())
        };
        Ok(CrossProcessMapping {
            kernel_address,
            mapping,
            offset,
            len,
            private: ()
        })
    }

    /// Gets the address of the mapping.
    pub fn addr(&self) -> VirtualAddress {
        self.kernel_address + self.offset
    }

    /// The length in byte of the mapping.
    pub fn len(&self) -> usize {
        self.len
    }
}

impl<'a> Drop for CrossProcessMapping<'a> {
    /// Unmaps itself from KernelLand when dropped.
    fn drop(&mut self) {
        // don't dealloc the frames, they are still tracked by the mapping
        get_kernel_memory().unmap_no_dealloc(
            self.kernel_address,
            self.mapping.length)
    }
}
