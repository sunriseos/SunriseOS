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
//! The remapping is represented by a [`CrossProcessMapping`] structure. It is created from a reference
//! to the mapping being mirrored, and the KernelLand address where it will be remapped.
//! When this struct is dropped, the frames are unmap'd from KernelLand.
//!
//! A [`CrossProcessMapping`] shares the ownership of the underlying frames. As such, only refcounted
//! memory regions can be mirror-mapped. This is rarely a problem, as almost all memory is refcounted.
//!
//! There is no guarantee that the CrossProcessMapping doesn't outlive the original mapping.
//!
//! [`CrossProcessMapping`]: self::CrossProcessMapping<'a>
//! [`ProcessMemory`]: crate::paging::process_memory::ProcessMemory

use crate::mem::VirtualAddress;
use super::{PAGE_SIZE, MappingAccessRights};
use super::mapping::{Mapping, MappingFrames};
use super::kernel_memory::get_kernel_memory;
use crate::utils::{align_down, align_up};
use failure::Backtrace;
use crate::error::KernelError;

/// A struct representing a UserLand mapping mirrored in KernelSpace.
#[derive(Debug)]
pub struct CrossProcessMapping {
    /// The KernelLand address it was remapped to. Has the desired offset.
    kernel_address: VirtualAddress,
    /// The frames this mapping covers.
    mapping: Mapping
}

#[allow(clippy::len_without_is_empty)]
impl CrossProcessMapping {
    /// Creates an `CrossProcessMapping`.
    ///
    /// Remaps a subsection of the mapping in KernelLand.
    ///
    /// # Error
    ///
    /// * Error if the mapping is not Shared, as only refcounted mappings can be owned.
    /// * Error if `offset` + `len` > `mapping` length.
    /// * Error if `offset` + `len` would overflow.
    // todo: should be offset + (len - 1), but need to check that it wouldn't overflow in our function
    /// * Error if `len` is 0.
    ///
    /// # Panics
    ///
    /// * Panics if `mapping.phys_offset()` + `offset` overflows.
    pub fn mirror_mapping(mapping: &Mapping, offset: usize, len: usize) -> Result<CrossProcessMapping, KernelError> {
        // Ensure we have Shared frames.
        let frames = match mapping.frames() {
            MappingFrames::Shared(frames) => MappingFrames::Shared(frames.clone()),
            _ => return Err(KernelError::InvalidMemState { address: mapping.address(), ty: mapping.state().ty(), backtrace: Backtrace::new() })
        };

        // Get the full page length required for this mapping.
        let full_len = align_up((offset % PAGE_SIZE) + len, PAGE_SIZE);

        let mut kmem = get_kernel_memory();
        let kernel_map_start = kmem.find_virtual_space(full_len)?;

        // Calculate the offset from the raw PhysicalMemRegion vector.
        // NOTE: This can overflow, it's up to the caller to ensure this can't happen.
        let full_offset = mapping.phys_offset() + align_down(offset, PAGE_SIZE);

        // TODO: Use a separate MemoryType for the CrossProcessMapping
        let new_mapping = Mapping::new(kernel_map_start, frames, full_offset, full_len, mapping.state().ty(), MappingAccessRights::k_rw())?;
        unsafe {
            // safe, the frames won't be dropped, they still are tracked by the userspace mapping.
            kmem.map_frame_iterator_to(new_mapping.frames_it(), kernel_map_start, MappingAccessRights::k_rw());
        }
        Ok(CrossProcessMapping {
            kernel_address: kernel_map_start + (offset % PAGE_SIZE),
            mapping: new_mapping
        })
    }

    /// The address of the region asked to be remapped.
    pub fn addr(&self) -> VirtualAddress {
        self.kernel_address
    }

    /// The length of the region asked to be remapped.
    pub fn len(&self) -> usize {
        self.mapping.length()
    }
}

impl Drop for CrossProcessMapping {
    fn drop(&mut self) {
        // don't dealloc the frames, they are tracked by the Arc.
        get_kernel_memory().unmap_no_dealloc(self.mapping.address(), self.mapping.length())
    }
}
