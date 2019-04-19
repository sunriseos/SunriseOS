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
use crate::utils::{check_nonzero_length, align_down, align_up};
use failure::Backtrace;
use crate::error::KernelError;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::sync::RwLock;
use crate::frame_allocator::physical_mem_region::PhysicalMemRegion;

/// A struct representing a UserLand mapping mirrored in KernelSpace.
#[derive(Debug)]
pub struct CrossProcessMapping {
    /// The KernelLand address it was remapped to. Has the desired offset.
    kernel_address: VirtualAddress,
    /// Stores the desired length.
    len: usize,
    /// The frames this mapping covers.
    frames: Arc<RwLock<Vec<PhysicalMemRegion>>>
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
    pub fn mirror_mapping(mapping: &Mapping, offset: usize, len: usize) -> Result<CrossProcessMapping, KernelError> {
        check_nonzero_length(len)?;
        let end_offset = offset.checked_add(len)
            .ok_or_else(|| KernelError::InvalidSize { size: usize::max_value(), backtrace: Backtrace::new() })?;

        let pages = if let MappingFrames::Shared(frames) = mapping.frames() {
            frames.clone()
        } else {
            return Err(KernelError::InvalidMemState { address: mapping.address(), ty: mapping.state().ty(), backtrace: Backtrace::new() })
        };

        let page_lock = pages.read();
        if end_offset > page_lock.iter().flatten().count() * PAGE_SIZE {
            return Err(KernelError::InvalidSize { size: len, backtrace: Backtrace::new() })
        }
        let map_start = align_down(offset, PAGE_SIZE);
        let map_end = align_up(offset + len, PAGE_SIZE);
        // iterator[map_start..map_end]
        let frames_iterator = page_lock.iter().flatten()
            .skip(map_start / PAGE_SIZE)
            .take((map_end - map_start) / PAGE_SIZE);
        let kernel_map_start = unsafe {
            // safe, the frames won't be dropped, they still are tracked by the userspace mapping.
            get_kernel_memory().map_frame_iterator(frames_iterator, MappingAccessRights::k_rw())
        };
        drop(page_lock);
        Ok(CrossProcessMapping {
            kernel_address: kernel_map_start + (offset % PAGE_SIZE),
            len,
            frames: pages
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

impl Drop for CrossProcessMapping {
    fn drop(&mut self) {
        let map_start = self.kernel_address.floor();
        let map_len = (self.kernel_address + self.len).ceil() - map_start;
        // don't dealloc the frames, they are tracked by the Arc.
        get_kernel_memory().unmap_no_dealloc(map_start, map_len)
    }
}
