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
use super::mapping::{Mapping, MappingFrames};
use sunrise_libkern::{MemoryType, MemoryState, MemoryAttributes, MemoryPermissions};
use super::cross_process::CrossProcessMapping;
use super::MappingAccessRights;
use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::frame_allocator::{FrameAllocator, FrameAllocatorTrait, PhysicalMemRegion};
use crate::paging::arch::Entry;
use crate::error::KernelError;
use crate::utils::{check_size_aligned, check_nonzero_length};
use crate::sync::SpinRwLock;
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
    /// [set_heap_size]: crate::syscalls::set_heap_size
    heap_base_address: VirtualAddress,
}

/// Page tables selector.
///
/// A process always stores its table_hierarchy as an inactive hierarchy. When it wants to modify
/// its page tables, it will first call [`get_hierarchy`], which will detect if the hierarchy
/// is already the currently active one, and return a `DynamicHierarchy`.
///
/// This returned `DynamicHierarchy` is just a wrapper which will dispatch all its calls to the right
/// hierarchy, either the already active one, shortcutting the method calls by not having to map
/// temporary directories and page tables, or going the long way and actually use the inactive one.
///
/// [`get_hierarchy`]: self::ProcessMemory::get_hierarchy
enum DynamicHierarchy<'a> {
    /// The process's hierarchy is already the currently active one.
    Active(ActiveHierarchy),
    /// The process's hierarchy an inactive one.
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

    fn get_child_table(&mut self, _index: usize) -> PageState<SmartHierarchicalTable<<Self as HierarchicalTable>::ChildTableType>> {
        unimplemented!()
    }

    fn create_child_table(&mut self, _index: usize) -> SmartHierarchicalTable<<Self as HierarchicalTable>::ChildTableType> {
        unimplemented!()
    }
}

impl<'b> TableHierarchy for DynamicHierarchy<'b> {
    type TopLevelTableType = (); // Ignored

    fn get_top_level_table(&mut self) -> SmartHierarchicalTable<()> {
        panic!("Dynamic DynamicHierarchy reimplements everything");
    }

    fn map_to_from_iterator<I>(&mut self,
                               frames_iterator: I,
                               start_address: VirtualAddress,
                               flags: MappingAccessRights)
    where I: Iterator<Item=PhysicalAddress>
    {
        match *self {
            DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.map_to_from_iterator(frames_iterator, start_address, flags),
            DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.map_to_from_iterator(frames_iterator, start_address, flags),
        }
    }

    fn guard(&mut self, address: VirtualAddress, length: usize) {
        match *self {
            DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.guard(address, length),
            DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.guard(address, length),
        }
    }

    fn unmap<C>(&mut self, address: VirtualAddress, length: usize, callback: C) where C: FnMut(PhysicalAddress) {
        match *self {
            DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.unmap(address, length, callback),
            DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.unmap(address, length, callback),
        }
    }

    fn for_every_entry<C>(&mut self, address: VirtualAddress, length: usize, callback: C) where C: FnMut(PageState<PhysicalAddress>, usize) {
        match *self {
            DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.for_every_entry(address, length, callback),
            DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.for_every_entry(address, length, callback),
        }
    }

    fn find_available_virtual_space_aligned(&mut self, length: usize, start_addr: VirtualAddress, end_addr: VirtualAddress, alignment: usize) -> Option<VirtualAddress> {
        match *self {
            DynamicHierarchy::Active(ref mut hierarchy) => hierarchy.find_available_virtual_space_aligned(length, start_addr, end_addr, alignment),
            DynamicHierarchy::Inactive(ref mut hierarchy) => hierarchy.find_available_virtual_space_aligned(length, start_addr, end_addr, alignment),
        }
    }
}

impl Default for ProcessMemory {
    /// Creates a ProcessMemory, allocating the userspace-bookkeeping,
    /// and the top-level table of the table hierarchy.
    fn default() -> Self {
        // we don't have ASRL yet :(
        let heap_base_address = VirtualAddress(0x80000000);

        ProcessMemory {
            userspace_bookkeping: UserspaceBookkeeping::new(),
            table_hierarchy: InactiveHierarchy::new(),
            heap_base_address,
        }
    }
}

impl ProcessMemory {

    /// If these tables are the one currently in use, we return them as an ActiveHierarchy instead.
    fn get_hierarchy(&mut self) -> DynamicHierarchy<'_> {
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
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * there was already a mapping in the range.
    ///     * range does not fall in UserLand.
    ///     * `address` is not page aligned.
    pub fn map_phys_region_to(&mut self,
                              phys: PhysicalMemRegion,
                              address: VirtualAddress,
                              ty: MemoryType,
                              flags: MappingAccessRights)
                              -> Result<(), KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        let length = phys.size();
        UserLand::check_contains_region(address, length)?;
        self.userspace_bookkeping.check_vacant(address, length)?;
        // ok, everything seems good, from now on treat errors as unexpected

        self.get_hierarchy().map_to_from_iterator(phys.into_iter(), address, flags);
        let mapping = Mapping::new(address, MappingFrames::Owned(vec![phys]), 0, length, ty, flags)
            .expect("We checked everything, but bookkeeping refuses to create the mapping");
        self.userspace_bookkeping.add_mapping(mapping)
            .expect("We checked everything, but bookkeeping refuses to add the mapping");
        Ok(())
    }

    /// Allocates the physical regions, and maps them to specified address.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * there was already a mapping in the range.
    ///     * range does not fall in UserLand.
    ///     * `address` is not page aligned.
    /// * `InvalidSize` :
    ///     * `length` is not page aligned.
    ///     * `length` is 0.
    /// * `PhysicalMemoryExhaustion`: Frames could not be allocated.
    pub fn create_regular_mapping(&mut self, address: VirtualAddress, length: usize, ty: MemoryType, flags: MappingAccessRights) -> Result<(), KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        check_size_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        UserLand::check_contains_region(address, length)?;
        self.userspace_bookkeping.check_vacant(address, length)?;
        let frames = FrameAllocator::allocate_frames_fragmented(length)?;
        // ok, everything seems good, from now on treat errors as unexpected

        self.get_hierarchy().map_to_from_iterator(frames.iter().flatten(), address, flags);
        let frames = if ty.get_memory_state().contains(MemoryState::IS_REFERENCE_COUNTED) {
            MappingFrames::Shared(Arc::new(SpinRwLock::new(frames)))
        } else {
            MappingFrames::Owned(frames)
        };

        let mapping = Mapping::new(address, frames, 0, length, ty, flags)
            .expect("We checked everything, but bookkeeping refuses to create the mapping");
        self.userspace_bookkeping.add_mapping(mapping)
            .expect("We checked everything, but bookkeeping refuses to add the mapping");
        Ok(())
    }

    /// Maps a previously created shared mapping to specified address.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * there was already a mapping in the range.
    ///     * range does not fall in UserLand.
    ///     * `address` is not page aligned.
    /// * `InvalidSize` :
    ///     * `length` is not page aligned.
    ///     * `length` is 0.
    pub fn map_partial_shared_mapping(&mut self,
                                      shared_mapping: Arc<SpinRwLock<Vec<PhysicalMemRegion>>>,
                                      address: VirtualAddress,
                                      phys_offset: usize,
                                      length: usize,
                                      ty: MemoryType,
                                      flags: MappingAccessRights)
                                     -> Result<(), KernelError> {
        address.check_aligned_to(PAGE_SIZE)?;
        check_nonzero_length(length)?;
        check_size_aligned(length, PAGE_SIZE)?;
        let max_length = shared_mapping.read().iter().flatten().count() * PAGE_SIZE - phys_offset;
        if max_length < length {
            return Err(KernelError::InvalidSize { size: length, backtrace: Backtrace::new() })
        }
        UserLand::check_contains_region(address, length)?;
        self.userspace_bookkeping.check_vacant(address, length)?;
        // ok, everything seems good, from now on treat errors as unexpected

        let mapping = Mapping::new(address, MappingFrames::Shared(shared_mapping), phys_offset, length, ty, flags)
            .expect("We checked everything, but bookkeeping refuses to create the mapping");
        self.get_hierarchy().map_to_from_iterator(mapping.frames_it(), address, flags);
        self.userspace_bookkeping.add_mapping(mapping)
            .expect("We checked everything, but bookkeeping refuses to add the mapping");
        Ok(())
    }

    /// Guards a range of addresses
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * there was already a mapping in the range.
    ///     * range does not fall in UserLand.
    ///     * `address` is not page aligned.
    /// * `InvalidSize` :
    ///     * `length` is not page aligned.
    ///     * `length` is 0.
    pub fn guard(&mut self, address: VirtualAddress, length: usize, ty: MemoryType) -> Result<(), KernelError>{
        UserLand::check_contains_region(address, length)?;
        let mapping = Mapping::new(address, MappingFrames::None, 0, length, ty, MappingAccessRights::empty())?;
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
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * there was no mapping starting at `address`.
    ///     * range does not fall in UserLand.
    /// * `InvalidSize`:
    ///     * `length` is not the size of the mapping at `address`.
    pub fn unmap(&mut self, address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        UserLand::check_contains_region(address, length)?;
        // allow address and length to be unaligned, remove_mapping will just not find anything.
        let mapping = self.userspace_bookkeping.remove_mapping(address, length)?;
        self.get_hierarchy().unmap(address, length, |_| {
            /* leak the mapped frames here, we still have them in `mapping` */
        });
        Ok(mapping)
    }

    /// Reads the state of the mapping at a given address.
    pub fn query_memory(&self, address: VirtualAddress) -> QueryMemory<'_> {
        self.userspace_bookkeping.mapping_at(address)
    }

    /*/// Shrink the mapping at `address` to `new_size`.
    ///
    /// If `new_size` == 0, the mapping is unmapped entirely.
    ///
    /// The removed part is returned, it is no longer mapped.
    ///
    /// If `new_size` is equal to old size, nothing is done, and Ok(None) is returned.
    ///
    /// Because it is reference counted, a Shared mapping cannot be resized.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * No mapping was found starting at `address`.
    /// * `InvalidSize`:
    ///     * `new_size` > previous mapping length.
    ///     * `new_size` is not PAGE_SIZE aligned.
    ///
    /// * SharedMapping if `address` falls in a shared mapping.
    /// * InvalidMapping if `address` falls in a system reserved mapping.
    // todo shrink_mapping seems extremely fishy
    // body I should check everything is right with its return types and early returns.
    // body It should at least check early for Shared and SystemReserved mappings.
    pub fn shrink_mapping(&mut self, address: VirtualAddress, new_size: usize) -> Result<Option<Mapping>, KernelError> {
        check_size_aligned(new_size, PAGE_SIZE)?;
        // 1. get the previous mapping's address and size.
        let (start_addr, old_size) = {
            let old_mapping_ref = self.userspace_bookkeping.occupied_mapping_at(address)?;
            (old_mapping_ref.address(), old_mapping_ref.length())
        };
        if new_size == 0 {
            // remove the mapping entirely, return everything as spill.
            return self.unmap(start_addr, old_size).map(Some)
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
    }*/

    /// Expand the Heap at `address` to `new_size`.
    ///
    /// New frames are allocated to match `new_size`.
    ///
    /// If `new_size` is equal to old size, nothing is done.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * There was already a mapping in the range `address..(address + new_size)`.
    ///     * `address` does not match any existent mapping.
    ///     * `address` falls in a shared or system reserved mapping, which cannot be resized.
    /// * `InvalidSize`:
    ///     * `address..(address + new_size)` does not fall in UserLand.
    ///     * `new_size` < previous mapping length.
    ///     * `new_size` is not page aligned.
    /// * `InvalidMemState`:
    ///     * `address` does not point to a Heap memory mapping.
    pub fn expand_mapping(&mut self, address: VirtualAddress, new_size: usize) -> Result<(), KernelError> {
        check_size_aligned(new_size, PAGE_SIZE)?;
        // 1. get the previous mapping's address and size.
        let old_mapping_ref = self.userspace_bookkeping.occupied_mapping_at(address)?;
        let (start_addr, old_size) = {
            // Check we're resizing the heap.
            if old_mapping_ref.state().ty() != MemoryType::Heap {
                return Err(KernelError::InvalidMemState { address: address, ty: old_mapping_ref.state().ty(), backtrace: Backtrace::new() });
            }
            // check it's not a system reserved or regular mapping.
            if let MappingFrames::Owned(..) | MappingFrames::None = old_mapping_ref.frames() {
                return Err(KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new() });
            }
            (old_mapping_ref.address(), old_mapping_ref.length())
        };

        // 2. Check the area we're extending to is available.
        UserLand::check_contains_region(start_addr, new_size)?;
        if new_size < old_size {
            return Err(KernelError::InvalidSize { size: new_size, backtrace: Backtrace::new() });
        }
        if new_size == old_size {
            return Ok(()) // don't do anything.
        }
        let added_length = new_size - old_size;
        self.userspace_bookkeping.check_vacant(start_addr + old_size, added_length)?;

        // 3. allocate the new frames.
        let mut new_frames = FrameAllocator::allocate_frames_fragmented(added_length)?;

        // 4. remove old mapping from the bookkeeping.
        let old_mapping = self.userspace_bookkeping.remove_mapping(start_addr, old_size)
            .expect("expand_mapping: removing the mapping failed.");
        let flags = old_mapping.flags();

        // 5. construct a new bigger mapping, with the same type and flags.
        let new_mapping = if let MappingFrames::Shared(frames) = old_mapping.frames() {
            // 6. map the added part accordingly.
            self.get_hierarchy().map_to_from_iterator(new_frames.iter().flatten(), start_addr + old_size, flags);
            // create a mapping from the freshly allocated frames and the flags.
            frames.write().append(&mut new_frames);
            Mapping::new(start_addr, MappingFrames::Shared(frames.clone()), 0, new_size, MemoryType::Heap, flags)
                .expect("expand_mapping: couldn't recreate mapping")
        } else {
            unreachable!("We checked we could only get a MappingFrames earlier.");
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

    /// Retrieves the mapping that `address` falls into, and mirror it in KernelLand.
    /// The mapping will be kept alive until the `CrossProcessMapping` is dropped.
    ///
    /// # Error
    ///
    /// Returns an Error if the mapping is not RefCounted.
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
        #[allow(clippy::missing_docs_in_private_items)]
        enum HeapState { NoHeap, Heap(usize) }
        UserLand::check_contains_region(self.heap_base_address, new_size)?;
        // get the previous heap size
        let previous_heap_state = {
            let query = self.userspace_bookkeping.mapping_at(self.heap_base_address);
            let heap = query.mapping();
            if let MemoryType::Unmapped = heap.state().ty() {
                HeapState::NoHeap
            } else {
                HeapState::Heap(heap.length())
            }
        };
        let heap_base_address = self.heap_base_address;
        match previous_heap_state {
            HeapState::NoHeap if new_size == 0 => (), // don't do anything
            HeapState::NoHeap => self.create_regular_mapping(heap_base_address, new_size, MemoryType::Heap, MappingAccessRights::u_rw())?,
            // TODO: Shrink mapping
            HeapState::Heap(old_size) if new_size < old_size => (),
            //HeapState::Heap(old_size) if new_size < old_size => { self.shrink_mapping(heap_base_address, new_size)?; },
            HeapState::Heap(_) => self.expand_mapping(heap_base_address, new_size)?
        }
        Ok(self.heap_base_address)
    }

    /// Switches to this process memory
    pub fn switch_to(&mut self) {
        self.table_hierarchy.switch_to();
    }

    /// Checks that the given memory range is homogenous (that is, all blocks
    /// within the range have the same permissions and state), and that it has
    /// an expected set of state, permissions and attributes.
    ///
    /// # Errors
    ///
    /// - `InvalidMemState`
    ///   - The state of a subsection of the memory region is not in the
    ///     expected state.
    ///   - The perms of a subsection of the memory region is not in the
    ///     expected state.
    ///   - The attrs of a subsection of the memory region is not in the
    ///     expected state.
    ///   - The range does not have homogenous state or perms. All mappings in
    ///     a region should have the same perms and state.
    #[allow(clippy::too_many_arguments)]
    pub fn check_range(&self, addr: VirtualAddress, size: usize,
        state_mask: MemoryState, state_expected: MemoryState,
        perms_mask: MemoryPermissions, perms_expected: MemoryPermissions,
        _attrs_mask: MemoryAttributes, _attrs_expected: MemoryAttributes,
        _attrs_ignore_mask: MemoryAttributes) -> Result<(MemoryState, MemoryPermissions, MemoryAttributes), KernelError>
    {
        let addr_end = addr + size;
        let mut cur_addr = addr;
        let mut first_block_state = None;
        let mut first_block_perms: Option<MemoryPermissions> = None;
        loop {
            let mem = self.query_memory(cur_addr);
            let mapping_perms = mem.mapping().flags().into();

            // First check for coherence: Blocks after the first must have the
            // same state and permissions.
            if *first_block_state.get_or_insert(mem.mapping().state()) != mem.mapping().state() {
                return Err(KernelError::InvalidMemState {
                    address: cur_addr,
                    ty: mem.mapping().state().ty(),
                    backtrace: Backtrace::new()
                })
            }
            if *first_block_perms.get_or_insert(mapping_perms) != mapping_perms {
                return Err(KernelError::InvalidMemState {
                    address: cur_addr,
                    ty: mem.mapping().state().ty(),
                    backtrace: Backtrace::new()
                })
            }

            // If the blocks are coherent, (or if this is the first block) we
            // should check that the state, permissions and attributes are all
            // in the expected state.
            if mem.mapping().state() & state_mask != state_expected ||
                // mem.mapping().attributes() & attrs_mask != attrs_expected ||
                mapping_perms & perms_mask != perms_expected
            {
                return Err(KernelError::InvalidMemState {
                    address: cur_addr,
                    ty: mem.mapping().state().ty(),
                    backtrace: Backtrace::new()
                });
            }

            cur_addr = mem.mapping().address() + mem.mapping().length();
            if cur_addr >= addr_end {
                return Ok((mem.mapping().state(), mem.mapping().flags().into(), MemoryAttributes::empty()))
            }
        }
    }
}

