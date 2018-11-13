//! The management of a process' memory
//!
//! j-------------------------------j j---------------------j
//! |        Process Memory         | |    Kernel Memory    |
//! j-------------------------------j j---------------------j
//!                 |                            |
//!     j-----------------------j                |
//!     | Userspace Bookkeeping |                |
//!     j-----------------------j                |
//!                 |                            |
//! j--------------------------------+----------------~-----j
//! |           User Land            |   Kernel Land  | RTL |
//! j--------------------------------+----------------~-----j
//!                         Page tables

use super::hierarchical_table::*;
use super::arch::{PAGE_SIZE, InactiveHierarchy, ActiveHierarchy};
use super::lands::{UserLand, KernelLand, VirtualSpaceLand};
use super::kernel_memory::get_kernel_memory;
use super::bookkeeping::{UserspaceBookkeeping, Mapping, MappingType, QuerryMemory};
use super::MappingFlags;
use mem::{VirtualAddress, PhysicalAddress};
use frame_allocator::{FrameAllocator, FrameAllocatorTrait, PhysicalMemRegion, mark_frame_bootstrap_allocated};
use scheduler::{get_current_process, try_get_current_process};
use sync::{Mutex, MutexGuard};
use paging::arch::EntryFlags;
use paging::arch::Entry;
use error::KernelError;
use failure::Backtrace;
use utils::{check_aligned, check_nonzero_length};
use alloc::{vec::Vec, sync::Arc};

/// The struct representing a process' memory, stored in the ProcessStruct behind a lock.
///
/// We always store the table_hierarchy as an inactive hierarchy, and use a shortcut function
/// accessing ActiveHierarchy instead if we detect it's the same cr3 as the currently active one.
///
/// A process is the only owner of a ProcessMemory
#[derive(Debug)]
pub struct ProcessMemory {
    userspace_bookkeping: UserspaceBookkeeping,
    table_hierarchy: InactiveHierarchy,
}

enum DynamicHierarchy<'a> {
    Active(ActiveHierarchy),
    Inactive(&'a mut InactiveHierarchy)
}

impl HierarchicalTable for () {
    type EntryType = Entry;
    type CacheFlusherType = NoFlush;
    type ChildTableType = ();

    fn entries(&mut self) -> &mut [Entry] {
        unimplemented!()
    }

    fn table_level() -> usize {
        unimplemented!()
    }

    fn get_child_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType>> {
        unimplemented!()
    }

    fn create_child_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType> {
        unimplemented!()
    }
}

impl<'b> TableHierarchy for DynamicHierarchy<'b> {
    type TopLevelTableType = (); // Ignored

    fn get_top_level_table<'a>(&'a mut self) -> SmartHierarchicalTable<'a, ()> {
        panic!("Dynamic DynamicHierarchy reimplements everything");
    }

    fn map_to(&mut self, physical_regions: &[PhysicalMemRegion], start_address: VirtualAddress, flags: MappingFlags) {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.map_to(physical_regions, start_address, flags),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.map_to(physical_regions, start_address, flags),
        }
    }

    fn guard(&mut self, address: VirtualAddress, mut length: usize) {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.guard(address, length),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.guard(address, length),
        }
    }

    fn unmap<C>(&mut self, address: VirtualAddress, mut length: usize, callback: C) where C: FnMut(PhysicalAddress) {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.unmap(address, length, callback),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.unmap(address, length, callback),
        }
    }

    fn for_every_entry<C>(&mut self, address: VirtualAddress, mut length: usize, callback: C) where C: FnMut(PageState<PhysicalAddress>, usize) {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.for_every_entry(address, length, callback),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.for_every_entry(address, length, callback),
        }
    }

    fn find_available_virtual_space_aligned(&mut self, length: usize, start_addr: VirtualAddress, end_addr: VirtualAddress, alignment: usize) -> Option<VirtualAddress> {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.find_available_virtual_space_aligned(length, start_addr, end_addr, alignment),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.find_available_virtual_space_aligned(length, start_addr, end_addr, alignment),
        }
    }
}

impl ProcessMemory {
    /// Creates a ProcessMemory, allocating the userspace-bookkeeping,
    /// and the top-level table of the table hierarchy.
    pub fn new() -> Self {
        ProcessMemory {
            userspace_bookkeping: UserspaceBookkeeping::new(),
            table_hierarchy: InactiveHierarchy::new()
        }
    }

    /// Creates a ProcessMemory referencing the current page tables.
    /// Used only when becoming the first process for creating the first ProcessMemory.
    ///
    /// # Unsafety
    ///
    /// Having multiple ProcessMemory pointing to the same table hierarchy is unsafe.
    pub unsafe fn from_active_page_tables() -> Self {
        ProcessMemory {
            userspace_bookkeping: UserspaceBookkeeping::new(),
            table_hierarchy: InactiveHierarchy::from_currently_active()
        }
    }

    /// If these tables are the one currently in use, we return them as an ActiveHierarchy instead.
    fn get_hierarchy(&mut self) -> DynamicHierarchy {
        if self.table_hierarchy.is_currently_active() {
            unsafe {
                // safe because the lock in the ProcessStuct is held, and there is no other safe way
                // of getting a mut ref to the ActiveHierarchy
                DynamicHierarchy::Active(ActiveHierarchy)
            }
        } else {
            DynamicHierarchy::Inactive(&mut self.table_hierarchy)
        }
    }

    /// Deprecated.
    ///
    /// Maps a single physical regions to a given virtual address.
    ///
    /// # Panics
    ///
    /// Panics if encounters any kind of bookkeeping error.
    // todo delete this as soon as possible
    #[deprecated(since="0.0.0", note="this function is about to be deleted for a better and safer interface")]
    pub fn map_phys_region_to(&mut self, phys: PhysicalMemRegion, address: VirtualAddress, flags: MappingFlags) {
        // really dumb implementation, because this function is scheduled to be removed
        let length = phys.size();
        let frames_vec = vec![phys];
        self.get_hierarchy().map_to(&frames_vec, address, flags);
        self.userspace_bookkeping.add_mapping(Mapping {
            address, length, mtype: MappingType::Regular(frames_vec)
        }).unwrap();
    }

    /// Allocates the physical regions, and maps them to specified address.
    ///
    /// # Error
    ///
    /// Returns a KernelError if there was already a mapping in the range.
    /// Returns a KernelError if address does not fall in UserLand.
    /// Returns a KernelError if address or length is not PAGE_SIZE aligned.
    pub fn create_regular_mapping(&mut self, address: VirtualAddress, length: usize, flags: MappingFlags) -> Result<(), KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        UserLand::check_contains_region(address, length)?;
        self.userspace_bookkeping.check_vacant(address, length)?;
        let frames = FrameAllocator::allocate_frames_fragmented(length / PAGE_SIZE)?;
        self.get_hierarchy().map_to(&frames, address, flags);
        self.userspace_bookkeping.add_mapping(Mapping {
            address, length, mtype: MappingType::Regular(frames)
        }).unwrap();
        Ok(())
    }

    /// Maps a previously created shared mapping to specified address.
    ///
    /// # Error
    ///
    /// Returns a KernelError if there was already a mapping in the range.
    /// Returns a KernelError if address does not fall in UserLand.
    /// Returns a KernelError if address or length is not PAGE_SIZE aligned.
    pub fn map_shared_mapping(&mut self,
                              shared_mapping: Arc<Vec<PhysicalMemRegion>>,
                              address: VirtualAddress,
                              flags: MappingFlags)
                              -> Result<(), KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        // compute the length
        let length = shared_mapping.iter().flatten().count() * PAGE_SIZE;
        check_nonzero_length(length)?;
        check_aligned(length, PAGE_SIZE)?;
        UserLand::check_contains_region(address, length)?;
        self.userspace_bookkeping.check_vacant(address, length)?;
        self.get_hierarchy().map_to(&shared_mapping, address, flags);
        self.userspace_bookkeping.add_mapping(Mapping {
            address, length, mtype: MappingType::Shared(shared_mapping)
        }).unwrap();
        Ok(())
    }

    /// Guards a range of addresses
    ///
    /// # Error
    ///
    /// Returns a KernelError if there was already a mapping in the range.
    /// Returns a KernelError if address does not fall in UserLand.
    /// Returns a KernelError if address or length is not PAGE_SIZE aligned.
    pub fn guard(&mut self, address: VirtualAddress, length: usize) -> Result<(), KernelError>{
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        UserLand::check_contains_region(address, length)?;
        self.userspace_bookkeping.add_mapping(Mapping { address, length, mtype: MappingType::Guarded})?;
        self.get_hierarchy().guard(address, length);
        Ok(())
    }

    /// Deletes a mapping in the page tables.
    ///
    /// This function will never split an existing mapping, thus address and length must match exactly.
    ///
    /// If the range maps physical memory, it will be de-allocated.
    ///
    /// # Error
    ///
    /// Returns a KernelError if there was no mapping corresponding to the range.
    /// Returns a KernelError if address does not fall in UserLand.
    /// Returns a KernelError if address or length is not PAGE_SIZE aligned.
    pub fn unmap(&mut self, address: VirtualAddress, length: usize) -> Result<(), KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        let mapping = self.userspace_bookkeping.remove_mapping(address, length)?;
        self.get_hierarchy().unmap(address, length, |_| {
            /* leak the mapped frames here, we still have them in `mapping` */
        });
        // we drop the mapping. If it contained PhysicalMemRegions, they will be dropped
        drop(mapping);
        Ok(())
    }

    /// Reads the state of the mapping at a given address
    ///
    /// # Error
    ///
    /// Returns a KernelError if address does not fall in UserLand.
    pub fn query_memory(&mut self, address: VirtualAddress) -> Result<QuerryMemory, KernelError> {
        UserLand::check_contains_address(address)?;
        Ok(self.userspace_bookkeping.mapping_at(address))
    }

    /// Unmaps a KernelLand page, and remaps it to process' memory.
    // todo work on a special "AcrossLandMapping" type, that controls this behaviour more strictly
    pub fn remap_frame_to_userland(&mut self,
                                from_addr: VirtualAddress,
                                dest_addr: VirtualAddress,
                                dest_flags: MappingFlags) {
        assert!(KernelLand::contains_region(from_addr, PAGE_SIZE));
        assert!(UserLand::contains_region(dest_addr, PAGE_SIZE));
        let mut kernel_memory_lock = get_kernel_memory();
        // read the pointed frame
        let mapping = kernel_memory_lock.mapping_state(from_addr);
        // unmap it.
        // don't deallocate, we still have a reference to possibly pointed frame in 'mapping'
        kernel_memory_lock.unmap_no_dealloc(from_addr, PAGE_SIZE);
        drop(kernel_memory_lock);
        // remap it
        match mapping {
            PageState::Available => { panic!("Asked to remap an available kernelland mapping to userland") },
            PageState::Guarded => self.guard(dest_addr, PAGE_SIZE).unwrap(),
            PageState::Present(paddr) => {
                let frame = unsafe { PhysicalMemRegion::reconstruct_no_dealloc(paddr, PAGE_SIZE) };
                self.map_phys_region_to(frame, dest_addr, dest_flags);

            }
        }
    }

    /// Unmaps a KernelLand region, and remaps it to process' memory.
    // todo work on a special "AcrossLandMapping" type, that controls this behaviour more strictly
    pub fn remap_to_userland(&mut self,
                            from_addr: VirtualAddress,
                            length: usize,
                            dest_addr: VirtualAddress,
                            dest_flags: MappingFlags) {
        assert!(KernelLand::contains_region(from_addr, length));
        assert!(UserLand::contains_region(dest_addr, length));
        assert!(length % PAGE_SIZE == 0, "length is not PAGE_SIZE aligned");
        for offset in (0..length).step_by(PAGE_SIZE) {
            // this is so slow it hurts
            self.remap_frame_to_userland(from_addr + offset, dest_addr + offset, dest_flags);
        }
    }

    /// Switches to this process memory
    pub fn switch_to(&mut self) {
        self.table_hierarchy.switch_to();
    }
}


