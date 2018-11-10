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
use super::MappingFlags;
use mem::{VirtualAddress, PhysicalAddress};
use frame_allocator::{FrameAllocator, FrameAllocatorTrait, PhysicalMemRegion, mark_frame_bootstrap_allocated};
use scheduler::{get_current_process, try_get_current_process};
use sync::{Mutex, MutexGuard};
use paging::arch::EntryFlags;
use paging::arch::Entry;
use error::KernelError;
use failure::Backtrace;

/// The struct representing a process' memory, stored in the ProcessStruct behind a lock.
///
/// We always store the table_hierarchy as an inactive hierarchy, and use a shortcut function
/// accessing ActiveHierarchy instead if we detect it's the same cr3 as the currently active one.
///
/// A process is the only owner of a ProcessMemory
#[derive(Debug)]
pub struct ProcessMemory {
    userspace_bookkeping: (),
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
            userspace_bookkeping: (),
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
            userspace_bookkeping: (),
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

    /// Maps a list of physical regions to a given virtual address
    fn map_to(&mut self, phys: &[PhysicalMemRegion], address: VirtualAddress, flags: MappingFlags) {
        self.get_hierarchy().map_to(phys, address, flags)
    }

    /// Maps a single physical regions to a given virtual address
    pub fn map_phys_region_to(&mut self, phys: PhysicalMemRegion, address: VirtualAddress, flags: MappingFlags) {
        // convert region as a slice of 1 region
        let region_as_slice = unsafe {
            ::core::slice::from_raw_parts(&phys as *const PhysicalMemRegion, 1)
        };
        self.map_to(region_as_slice, address, flags);
        // physical region must not be deallocated while it is mapped
        ::core::mem::forget(phys);
    }

    /// Allocates the physical regions, and maps them to specified address
    pub fn map_allocate(&mut self, address: VirtualAddress, length: usize, flags: MappingFlags) {
        let frames_nr = ::utils::div_round_up(length, PAGE_SIZE);
        let regions = FrameAllocator::allocate_frames_fragmented(frames_nr)
            .expect("Could not allocate physical memory");
        self.map_to(&regions, address, flags)
    }

    /// Guards a range of addresses
    pub fn guard(&mut self, address: VirtualAddress, length: usize) {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.get_hierarchy().guard(address, length);
    }

    /// Deletes a mapping in the page tables.
    pub fn unmap(&mut self, address: VirtualAddress, length: usize) {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.get_hierarchy().unmap(address, length, |paddr| {
            let pr = unsafe {
                // safe, they were only tracked by the page tables
                PhysicalMemRegion::reconstruct(paddr, PAGE_SIZE);
            };
            drop(pr)
        });
    }

    /// Deletes a mapping in the page tables, but does not free the underlying physical memory
    pub fn unmap_no_dealloc(&mut self, address: VirtualAddress, length: usize) {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.get_hierarchy().unmap(address, length, |paddr| { /* leak the frame */ });
    }

    /// Finds a hole in the virtual space at least 'length' long, and respecting alignment
    pub fn find_virtual_space_aligned<Land: VirtualSpaceLand>(&mut self, length: usize, alignment: usize) -> Result<VirtualAddress, KernelError> {
        match self.get_hierarchy().find_available_virtual_space_aligned(length, Land::start_addr(), Land::end_addr(), alignment) {
            Some(addr) => Ok(addr),
            None => Err(KernelError::VirtualMemoryExhaustion { backtrace: Backtrace::new() })
        }
    }

    /// Finds a hole in the virtual space at least 'length' long.
    pub fn find_virtual_space<Land: VirtualSpaceLand>(&mut self, length: usize) -> Result<VirtualAddress, KernelError> {
        self.find_virtual_space_aligned::<Land>(length, PAGE_SIZE)
    }

    /// Allocates and maps the given length, chosing a spot in VMEM for it.
    ///
    /// # Panics
    ///
    /// Panics if we are out of memory.
    /// Panics if length is not a multiple of PAGE_SIZE.
    pub fn get_pages<Land: VirtualSpaceLand>(&mut self, length: usize) -> VirtualAddress {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        let va = self.find_virtual_space::<Land>(length).unwrap();
        let mut prs = FrameAllocator::allocate_frames_fragmented(length / PAGE_SIZE).unwrap();
        let flags = MappingFlags::WRITABLE;
        self.map_to(&prs, va, flags);

        // do not drop the frames !
        while let Some(region) = prs.pop() {
            ::core::mem::forget(region);
        }
        va
    }

    /// Allocates and maps a single page, choosing a spot in VMEM for it.
    pub fn get_page<Land: VirtualSpaceLand>(&mut self) -> VirtualAddress {
        let va = self.find_virtual_space::<Land>(PAGE_SIZE).unwrap();
        let pr = FrameAllocator::allocate_frame().unwrap();
        let flags = MappingFlags::WRITABLE;
        self.map_phys_region_to(pr, va, flags);
        va
    }

    /// Reads the state of the mapping at a given address
    pub fn mapping_state(&mut self, addr: VirtualAddress) -> PageState<PhysicalAddress> {
        let mut mapping = None;
        let addr_aligned = VirtualAddress(::utils::align_down(addr.addr(), PAGE_SIZE));
        // use for_every_entry with length of just one page
        self.get_hierarchy().for_every_entry(addr_aligned, PAGE_SIZE,
        | state, _ | mapping = Some(state));
        mapping.unwrap()
    }

    /// Marks all frames mapped in KernelLand as reserve
    /// This is used at startup to reserve frames mapped by the bootstrap
    ///
    /// # Panic
    ///
    /// Panics if it tries to overwrite an existing reservation
    pub fn reserve_kernel_land_frames(&mut self) {
        self.get_hierarchy().for_every_entry(KernelLand::start_addr(), KernelLand::length(),
        |entry_state, length| {
            if let PageState::Present(mapped_frame) = entry_state {
                mark_frame_bootstrap_allocated(mapped_frame)
            }
        });
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
            PageState::Guarded => self.guard(dest_addr, PAGE_SIZE),
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
