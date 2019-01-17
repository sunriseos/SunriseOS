//! The management of a process' memory
//!
//! ```
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
//! ```

pub use super::bookkeeping::QueryMemory;

use super::hierarchical_table::*;
use super::arch::{PAGE_SIZE, InactiveHierarchy, ActiveHierarchy};
use super::lands::{UserLand, VirtualSpaceLand};
use super::bookkeeping::UserspaceBookkeeping;
use super::mapping::{Mapping, MappingType};
use super::cross_process::CrossProcessMapping;
use super::error::MmError;
use super::MappingFlags;
use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::frame_allocator::{FrameAllocator, FrameAllocatorTrait, PhysicalMemRegion};
use crate::paging::arch::Entry;
use crate::error::KernelError;
use crate::utils::{check_aligned, check_nonzero_length};
use crate::utils::Splittable;
use alloc::{vec::Vec, sync::Arc};
use failure::Backtrace;

/// The struct representing a process' memory, stored in the ProcessStruct behind a lock.
///
/// We always store the table_hierarchy as an inactive hierarchy, and use a shortcut function
/// accessing ActiveHierarchy instead if we detect it's the same cr3 as the currently active one.
///
/// A process is the only owner of a ProcessMemory
#[derive(Debug)]
pub struct ProcessMemory {
    /// The list of mappings in this address space.
    userspace_bookkeping: UserspaceBookkeeping,
    /// The architecture-dependent paging hierarchy.
    table_hierarchy: InactiveHierarchy,
    /// The start of the heap of this process. The heap is managed as a brk
    /// by the [set_heap_size] syscall.
    ///
    /// The location of each process's heap should be random, to implement ASLR.
    ///
    /// [set_heap_size]: ::interrupts::syscalls::set_heap_size
    heap_base_address: VirtualAddress,
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

    fn get_child_table<'a>(&'a mut self, _index: usize) -> PageState<SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType>> {
        unimplemented!()
    }

    fn create_child_table<'a>(&'a mut self, _index: usize) -> SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType> {
        unimplemented!()
    }
}

impl<'b> TableHierarchy for DynamicHierarchy<'b> {
    type TopLevelTableType = (); // Ignored

    fn get_top_level_table<'a>(&'a mut self) -> SmartHierarchicalTable<'a, ()> {
        panic!("Dynamic DynamicHierarchy reimplements everything");
    }

    fn map_to_from_iterator<I>(&mut self,
                               frames_iterator: I,
                               start_address: VirtualAddress,
                               flags: MappingFlags)
    where I: Iterator<Item=PhysicalAddress>
    {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.map_to_from_iterator(frames_iterator, start_address, flags),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.map_to_from_iterator(frames_iterator, start_address, flags),
        }
    }

    fn guard(&mut self, address: VirtualAddress, length: usize) {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.guard(address, length),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.guard(address, length),
        }
    }

    fn unmap<C>(&mut self, address: VirtualAddress, length: usize, callback: C) where C: FnMut(PhysicalAddress) {
        match self {
            &mut DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.unmap(address, length, callback),
            &mut DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.unmap(address, length, callback),
        }
    }

    fn for_every_entry<C>(&mut self, address: VirtualAddress, length: usize, callback: C) where C: FnMut(PageState<PhysicalAddress>, usize) {
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
        // we don't have ASRL yet :(
        let heap_base_address = VirtualAddress(0x80000000);

        let mut ret = ProcessMemory {
            userspace_bookkeping: UserspaceBookkeeping::new(),
            table_hierarchy: InactiveHierarchy::new(),
            heap_base_address,
        };
        // unconditionally guard the very first page, for NULL pointers.
        ret.guard(VirtualAddress(0x00000000), PAGE_SIZE)
            .expect("Cannot guard first page of ProcessMemory");
        ret
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
            table_hierarchy: InactiveHierarchy::from_currently_active(),
            heap_base_address: VirtualAddress(0x55555555), // just a dummy value, the first process
                                                           // should never use its process's heap !
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

    /// Maps a single physical regions to a given virtual address.
    /// Used to map mmio regions in UserSpace.
    ///
    /// # Error
    ///
    /// Returns a KernelError if length is not page aligned.
    /// Returns a KernelError if length is 0.
    pub fn map_phys_region_to(&mut self,
                              phys: PhysicalMemRegion,
                              address: VirtualAddress,
                              flags: MappingFlags)
                              -> Result<(), KernelError> {
        let length = phys.size();
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        UserLand::check_contains_region(address, length)?;
        self.userspace_bookkeping.check_vacant(address, length)?;
        // ok, everything seems good, from now on treat errors as unexpected

        self.get_hierarchy().map_to_from_iterator(phys.into_iter(), address, flags);
        let mapping = Mapping::new_regular(address, vec![phys], flags)
            .expect("We checked everything, but bookkeeping refuses to create the mapping");
        self.userspace_bookkeping.add_mapping(mapping)
            .expect("We checked everything, but bookkeeping refuses to add the mapping");
        Ok(())
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
        let frames = FrameAllocator::allocate_frames_fragmented(length)?;
        // ok, everything seems good, from now on treat errors as unexpected

        self.get_hierarchy().map_to_from_iterator(frames.iter().flatten(), address, flags);
        let mapping = Mapping::new_regular(address, frames, flags)
            .expect("We checked everything, but bookkeeping refuses to create the mapping");
        self.userspace_bookkeping.add_mapping(mapping)
            .expect("We checked everything, but bookkeeping refuses to add the mapping");
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
        // ok, everything seems good, from now on treat errors as unexpected

        self.get_hierarchy().map_to_from_iterator(shared_mapping.iter().flatten(), address, flags);
        let mapping = Mapping::new_shared(address, shared_mapping, flags)
            .expect("We checked everything, but bookkeeping refuses to create the mapping");
        self.userspace_bookkeping.add_mapping(mapping)
            .expect("We checked everything, but bookkeeping refuses to add the mapping");
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
        UserLand::check_contains_region(address, length)?;
        let mapping = Mapping::new_guard(address, length)?;
        self.userspace_bookkeping.add_mapping(mapping)?;

        // everything is ok, actually map the guard
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
    pub fn unmap(&mut self, address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        UserLand::check_contains_region(address, length)?;
        let mapping = self.userspace_bookkeping.remove_mapping(address, length)?;
        self.get_hierarchy().unmap(address, length, |_| {
            /* leak the mapped frames here, we still have them in `mapping` */
        });
        Ok(mapping)
    }

    /// Reads the state of the mapping at a given address
    ///
    /// # Error
    ///
    /// Returns a KernelError if address does not fall in UserLand.
    pub fn query_memory(&self, address: VirtualAddress) -> Result<QueryMemory, KernelError> {
        UserLand::check_contains_address(address)?;
        Ok(self.userspace_bookkeping.mapping_at(address))
    }

    /// Shrink the mapping at `address` to `new_size`.
    ///
    /// If `new_size` == 0, the mapping is unmapped entirely.
    ///
    /// The removed part is returned, it is no longer mapped.
    ///
    /// If `new_size` is equal to old size, nothing is done, and Ok(None) is returned.
    ///
    /// Because it is reference counted, a Shared mapping cannot be resized.
    ///
    /// # Error
    ///
    /// * WasAvailable if `address` does not match any existent mapping.
    /// * InvalidSize if `new_size` > previous mapping length.
    /// * InvalidSize if `new_size` is not PAGE_SIZE aligned.
    /// * SharedMapping if `address` falls in a shared mapping.
    /// * InvalidMapping if `address` falls in a system reserved mapping.
    pub fn shrink_mapping(&mut self, address: VirtualAddress, new_size: usize) -> Result<Option<Mapping>, KernelError> {
        check_aligned(new_size, PAGE_SIZE)?;
        // 1. get the previous mapping's address and size.
        let (start_addr, old_size) = {
            let old_mapping_ref = self.userspace_bookkeping.occupied_mapping_at(address)?;
            (old_mapping_ref.address(), old_mapping_ref.length())
        };
        if new_size == 0 {
            // remove the mapping entirely, return everything as spill.
            return self.unmap(start_addr, old_size).map(|mapping| Some(mapping))
        }
        if new_size == old_size {
            // don't do anything, and produce no spill
            return Ok(None)
        }
        if new_size > old_size {
            return Err(KernelError::InvalidSize { size: new_size, backtrace: Backtrace::new() });
        }
        // 2. remove it from the bookkeeping
        let mut mapping = self.userspace_bookkeping.remove_mapping(start_addr, old_size)
            .expect("shrink_mapping: removing the mapping failed.");
        // 3. split it in two
        let spill = mapping.split_at(new_size)?
            .expect("shrink_mapping: shrinking did not produce a right part, but new size < old size");
        // 4. re-add the left part
        self.userspace_bookkeping.add_mapping(mapping)
            .expect("shrink_mapping: re-adding the mapping failed");
        // 5. unmap the right part from the page_tables
        self.get_hierarchy().unmap(spill.address(), spill.length(), |_| {
            /* leak the mapped frames here, we still have them in `mapping` */
        });
        Ok(Some(spill))
    }

    /// Expand the mapping at `address` to `new_size`.
    ///
    /// If the mapping used to map physical memory, new frames are allocated to match `new_size`.
    ///
    /// If `new_size` is equal to old size, nothing is done.
    ///
    /// Because it is reference counted, a Shared mapping cannot be resized.
    ///
    /// # Error
    ///
    /// * WasAvailable if `address` does not match any existent mapping.
    /// * SharedMapping if `address` falls in a shared mapping.
    /// * InvalidMapping if `address` falls in a system reserved mapping.
    /// * InvalidSize if `new_size` < previous mapping length.
    /// * InvalidSize if `new_size` is not PAGE_SIZE aligned.
    /// * InvalidSize if \[`address`..`new_size`\] does not fall in UserLand.
    /// * WasOccupied if a mapping was already present in the expanding area.
    pub fn expand_mapping(&mut self, address: VirtualAddress, new_size: usize) -> Result<(), KernelError> {
        check_aligned(new_size, PAGE_SIZE)?;
        // 1. get the previous mapping's address and size.
        let (start_addr, old_size) = {
            let old_mapping_ref = self.userspace_bookkeping.occupied_mapping_at(address)?;
            // check it's not a shared mapping.
            if let MappingType::Shared(..) = old_mapping_ref.mtype_ref() {
                return Err(KernelError::MmError(MmError::SharedMapping { backtrace: Backtrace::new() }));
            }
            if let MappingType::SystemReserved = old_mapping_ref.mtype_ref() {
                return Err(KernelError::MmError(MmError::InvalidMapping { backtrace: Backtrace::new() }));
            }
            (old_mapping_ref.address(), old_mapping_ref.length())
        };
        UserLand::check_contains_region(start_addr, new_size)?;
        if new_size < old_size {
            return Err(KernelError::InvalidSize { size: new_size, backtrace: Backtrace::new() });
        }
        if new_size == old_size {
            return Ok(()) // don't do anything.
        }
        let added_length = new_size - old_size;
        self.userspace_bookkeping.check_vacant(start_addr + old_size, added_length)?;
        // 2. remove it from the bookkeeping.
        let old_mapping = self.userspace_bookkeping.remove_mapping(start_addr, old_size)
            .expect("expand_mapping: removing the mapping failed.");
        let flags = old_mapping.flags();
        // 3. construct a new bigger mapping, with the same type and flags.
        // 4. map the added part accordingly.
        let new_mapping = match old_mapping.mtype() {
            MappingType::Available | MappingType::Shared(..) | MappingType::SystemReserved => unreachable!(),
            MappingType::Guarded => {
                // guard the added part in the page tables.
                self.get_hierarchy().guard(start_addr + old_size, added_length);
                Mapping::new_guard(start_addr, new_size)
                    .expect("expand_mapping: couldn't recreate mapping")
            },
            MappingType::Regular(mut frames) => {
                // allocate the new frames.
                let mut new_frames = FrameAllocator::allocate_frames_fragmented(added_length)?;
                // map them.
                self.get_hierarchy().map_to_from_iterator(new_frames.iter().flatten(), start_addr + old_size, flags);
                // create a mapping from the two parts.
                frames.append(&mut new_frames);
                Mapping::new_regular(start_addr, frames, flags)
                    .expect("expand_mapping: couldn't recreate mapping")
            },
        };
        self.userspace_bookkeping.add_mapping(new_mapping)
            .expect("expand_mapping: failed re-adding the mapping to the bookkeeping");
        Ok(())
    }

    /// Finds a hole in virtual space at least `length` long.
    ///
    /// # Error
    ///
    /// Returns a KernelError if no sufficiently big hole was found.
    /// Returns a KernelError if `length` is 0.
    pub fn find_available_space(&self, length: usize) -> Result<VirtualAddress, KernelError> {
        self.userspace_bookkeping.find_available_space(length)
    }

    /// Retrieves the mapping that `address` falls into, and mirror it in KernelLand
    ///
    /// # Error
    ///
    /// Returns an Error if the mapping is Available/Guarded/SystemReserved, as there would be
    /// no point to remap it, and dereferencing the pointer would cause the kernel to page-fault.
    pub fn mirror_mapping(&self, address: VirtualAddress, length: usize) -> Result<CrossProcessMapping, KernelError> {
        UserLand::check_contains_address(address)?;
        let mapping = self.userspace_bookkeping.occupied_mapping_at(address)?;
        let offset = address - mapping.address();
        CrossProcessMapping::mirror_mapping(mapping, offset, length)
    }

    /// Resize the heap of this process, just like a brk.
    /// It can both expand or shrink the heap.
    ///
    /// If `new_size` == 0, it is completely de-allocated.
    ///
    /// # Return
    ///
    /// The address of the start of the heap.
    ///
    /// # Error
    ///
    /// * InvalidSize if `new_size` is not [PAGE_SIZE] aligned.
    /// * InvalidSize if \[`address`..`new_size`\] does not fall in UserLand,
    ///   or overlaps an existing mapping.
    pub fn resize_heap(&mut self, new_size: usize) -> Result<VirtualAddress, KernelError> {
        enum HeapState { NoHeap, Heap(usize) };
        UserLand::check_contains_region(self.heap_base_address, new_size)?;
        // get the previous heap size
        let previous_heap_state = {
            let query = self.userspace_bookkeping.mapping_at(self.heap_base_address);
            let heap = query.as_ref();
            if let MappingType::Available = heap.mtype_ref() {
                HeapState::NoHeap
            } else {
                HeapState::Heap(heap.length())
            }
        };
        let heap_base_address = self.heap_base_address;
        match previous_heap_state {
            HeapState::NoHeap if new_size == 0 => (), // don't do anything
            HeapState::NoHeap => self.create_regular_mapping(heap_base_address, new_size, MappingFlags::u_rw())?,
            HeapState::Heap(old_size) if new_size < old_size => { self.shrink_mapping(heap_base_address, new_size)?; },
            HeapState::Heap(_) => self.expand_mapping(heap_base_address, new_size)?
        }
        Ok(self.heap_base_address)
    }

    /// Switches to this process memory
    pub fn switch_to(&mut self) {
        self.table_hierarchy.switch_to();
    }
}

