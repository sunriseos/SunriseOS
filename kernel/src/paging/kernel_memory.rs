//! The management of kernel memory
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
//!
//! We choose to separate UserLand and KernelLand + RecursiveTablesLand memory management.
//! This way we can allow concurrent access on different lands, and modifying the kernel memory
//! directly accesses the active page tables, without need to lock the ProcessStruct.
//!
//! This solves the problem of accessing the page tables in an early state, where there is no
//! current process yet.

use super::lands::{KernelLand, RecursiveTablesLand, VirtualSpaceLand};
use super::arch::{PAGE_SIZE, ActiveHierarchy};
use super::hierarchical_table::{TableHierarchy, PageState};
use super::MappingAccessRights;
use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait,
                      mark_frame_bootstrap_allocated};
use crate::sync::{Mutex, MutexGuard};
use crate::error::KernelError;
use failure::Backtrace;

/// A struct that acts on KernelLand and RecursiveTablesLand.
///
/// Always modifies the ACTIVE_PAGE_TABLES.
/// When switching to a new set of page tables in a process switch, the modifications will be copied
/// to the set just before switching to it.
///
/// Because of this mechanism we do not permit modifying KernelLand in other tables
/// than the currently active ones.
#[derive(Debug)]
pub struct KernelMemory {
    /// The currently active page tables.
    tables: ActiveHierarchy
}

/// A mutex protecting the KernelMemory manager.
///
/// This mutex is independent from the one protecting
/// UserLand memory, and both lands can be modified concurrently thanks to each manager
/// not observing the other lands.
pub static KERNEL_MEMORY: Mutex<KernelMemory> = Mutex::new(KernelMemory { tables: ActiveHierarchy });

/// Locks the KERNEL_MEMORY
pub fn get_kernel_memory() -> MutexGuard<'static, KernelMemory> { KERNEL_MEMORY.lock() }

impl KernelMemory {

    /// Finds a hole in the virtual space at least 'length' long, and respecting alignment.
    pub fn find_virtual_space_aligned(&mut self, length: usize, alignment: usize) -> Result<VirtualAddress, KernelError> {
        match self.tables.find_available_virtual_space_aligned(length, KernelLand::start_addr(), KernelLand::end_addr(), alignment) {
            Some(addr) => Ok(addr),
            None => Err(KernelError::VirtualMemoryExhaustion { backtrace: Backtrace::new() })
        }
    }

    /// Finds a hole in the virtual space at least 'length' long.
    pub fn find_virtual_space(&mut self, length: usize) -> Result<VirtualAddress, KernelError> {
        self.find_virtual_space_aligned(length, PAGE_SIZE)
    }

    /// Maps a single physical regions to a given virtual address.
    ///
    /// # Panics
    ///
    /// Panics if virtual region is not in KernelLand.
    // todo check va alignment
    pub fn map_phys_region_to(&mut self, phys: PhysicalMemRegion, address: VirtualAddress, flags: MappingAccessRights) {
        assert!(KernelLand::contains_region(address, phys.size()));
        self.tables.map_to_from_iterator(phys.into_iter(), address, flags);
        // physical region must not be deallocated while it is mapped
        ::core::mem::forget(phys);
    }

    /// Maps a single physical region anywhere.
    ///
    /// # Panics
    ///
    /// Panics if encounters virtual space exhaustion.
    pub fn map_phys_region(&mut self, phys: PhysicalMemRegion, flags: MappingAccessRights) -> VirtualAddress {
        let va = self.find_virtual_space(phys.size()).unwrap();
        self.map_phys_region_to(phys, va, flags);
        va
    }

    /// Maps a list of physical region anywhere.
    ///
    /// # Unsafe
    ///
    /// This function cannot ensure that the frames won't be dropped while still mapped.
    ///
    /// # Panics
    ///
    /// Panics if encounters virtual space exhaustion.
    pub(super) unsafe fn map_phys_regions(&mut self, phys: &[PhysicalMemRegion], flags: MappingAccessRights) -> VirtualAddress {
        let length = phys.iter().flatten().count() * PAGE_SIZE;
        let va = self.find_virtual_space(length).unwrap();
        self.tables.map_to_from_iterator(phys.iter().flatten(), va, flags);
        va
    }

    /// Maps a list of physical region yielded by an iterator.
    ///
    /// # Unsafe
    ///
    /// This function cannot ensure that the frames won't be dropped while still mapped.
    ///
    /// # Panics
    ///
    /// Panics if virtual region is not in KernelLand.
    /// Panics if encounters virtual space exhaustion.
    // todo check va alignment
    pub(super) unsafe fn map_frame_iterator_to<I>(&mut self, iterator: I, address: VirtualAddress, flags: MappingAccessRights)
    where I: Iterator<Item=PhysicalAddress> + Clone
    {
        assert!(KernelLand::contains_region(address,
                                            iterator.clone().count() * PAGE_SIZE));
        self.tables.map_to_from_iterator(iterator, address, flags);
    }

    /// Maps a list of physical region yielded by the iterator.
    /// Chooses the address.
    ///
    /// # Unsafe
    ///
    /// This function cannot ensure that the frames won't be dropped while still mapped.
    ///
    /// # Panics
    ///
    /// Panics if encounters virtual space exhaustion.
    pub(super) unsafe fn map_frame_iterator<I>(&mut self, iterator: I, flags: MappingAccessRights) -> VirtualAddress
    where I: Iterator<Item=PhysicalAddress> + Clone
    {
        let length = iterator.clone().count() * PAGE_SIZE;
        // TODO: Don't unwrap on OOM in map_frame_iterator.
        // BODY: map_frame_iterator should return an error on OOM instead of
        // BODY: making the whole kernel panic...
        let va = self.find_virtual_space(length).unwrap();
        self.tables.map_to_from_iterator(iterator, va, flags);
        va
    }

    /// Allocates and maps a single page, choosing a spot in VMEM for it.
    ///
    /// # Panics
    ///
    /// Panics if encounters physical memory exhaustion.
    /// Panics if encounters virtual space exhaustion.
    pub fn get_page(&mut self) -> VirtualAddress {
        let pr = FrameAllocator::allocate_frame().unwrap();
        self.map_phys_region(pr, MappingAccessRights::k_rw())
    }

    /// Allocates non-contiguous frames, and map them at the given address.
    ///
    /// # Panics
    ///
    /// Panics if encounters physical memory exhaustion.
    /// Panics if encounters virtual space exhaustion.
    /// Panics if destination was already mapped.
    /// Panics if `length` is not a multiple of PAGE_SIZE.
    // todo check va alignment
    pub fn map_allocate_to(&mut self, va: VirtualAddress, length: usize, flags: MappingAccessRights) {
        assert!(KernelLand::contains_region(va, length));
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        let mut prs = FrameAllocator::allocate_frames_fragmented(length).unwrap();
        self.tables.map_to_from_iterator(prs.iter().flatten(), va, flags);

        // do not drop the frames, they are mapped in the page tables !
        while let Some(region) = prs.pop() {
            ::core::mem::forget(region);
        }
    }

    /// Allocates and maps the given length, chosing a spot in VMEM for it.
    ///
    /// # Panics
    ///
    /// Panics if encounters physical memory exhaustion.
    /// Panics if encounters virtual space exhaustion.
    /// Panics if `length` is not a multiple of PAGE_SIZE.
    pub fn get_pages(&mut self, length: usize) -> VirtualAddress {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        let va = self.find_virtual_space(length).unwrap();
        self.map_allocate_to(va, length, MappingAccessRights::k_rw());
        va
    }

    /// Guards a range of addresses.
    ///
    /// # Panics
    ///
    /// Panics if destination was already mapped.
    /// Panics if `length` is not a multiple of PAGE_SIZE.
    // todo check va alignment
    pub fn guard(&mut self, address: VirtualAddress, length: usize) {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.get_hierarchy().guard(address, length);
    }

    /// Reads the state of the mapping at a given address.
    ///
    /// # Panics
    ///
    /// If `address` is not in KernelLand.
    pub fn mapping_state(&mut self, addr: VirtualAddress) -> PageState<PhysicalAddress> {
        let mut mapping= None;
        let addr_aligned = VirtualAddress(crate::utils::align_down(addr.addr(), PAGE_SIZE));
        assert!(KernelLand::contains_address(addr));
        // use for_every_entry with length of just one page
        self.tables.for_every_entry(addr_aligned, PAGE_SIZE,
        | state, _ | mapping = Some(state));
        mapping.unwrap()
    }

    /// Deletes a mapping in the page tables.
    /// This functions assumes the frames were not tracked anywhere else, and drops them.
    ///
    /// # Panics
    ///
    ///
    /// Panics if encounters any entry that was not mapped.
    /// Panics if virtual region is not in KernelLand.
    /// Panics if `length` is not page aligned.
    // todo check va alignment
    pub fn unmap(&mut self, address: VirtualAddress, length: usize) {
        assert!(KernelLand::contains_region(address, length));
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.tables.unmap(address, length, |paddr| {
            let pr = unsafe {
                // safe, they were only tracked by the page tables
                PhysicalMemRegion::reconstruct(paddr, PAGE_SIZE)
            };
            drop(pr)
        });
    }

    /// Deletes a mapping in the page tables, but does not free the underlying physical memory.
    ///
    /// # Panics
    ///
    /// Panics if encounters any entry that was not mapped.
    /// Panics if virtual region is not in KernelLand.
    /// Panics if `length` is not page aligned.
    // todo check va alignment
    pub fn unmap_no_dealloc(&mut self, address: VirtualAddress, length: usize) {
        assert!(KernelLand::contains_region(address, length));
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.tables.unmap(address, length, |_paddr| { /* leak the frame */ });
    }

    /// Marks all frames mapped in KernelLand as reserve
    /// This is used at startup to reserve frames mapped by the bootstrap
    ///
    /// # Panic
    ///
    /// Panics if it tries to overwrite an existing reservation
    pub fn reserve_kernel_land_frames(&mut self) {
        self.tables.for_every_entry(KernelLand::start_addr(),
                                    KernelLand::length() + RecursiveTablesLand::length(),
        |entry_state, length| {
            if let PageState::Present(mapped_frame) = entry_state {
                for offset in (0..length).step_by(PAGE_SIZE) {
                    mark_frame_bootstrap_allocated(mapped_frame + offset)
                }
            }
        });
    }

    /// Safe access to the active page tables.
    pub(super) fn get_hierarchy(&mut self) -> &mut ActiveHierarchy {
        &mut self.tables
    }

    /// Prints the state of the KernelLand by parsing the page tables. Used for debugging purposes.
    #[allow(clippy::missing_docs_in_private_items)]
    pub fn dump_kernelland_state(&mut self) {
        #[derive(Debug, Clone, Copy)]
        enum State { Present(VirtualAddress, PhysicalAddress), Guarded(VirtualAddress), Available(VirtualAddress) }
        impl State {
            fn get_vaddr(&self) -> VirtualAddress {
                match *self {
                    State::Present(addr, _) => addr,
                    State::Guarded(addr) => addr,
                    State::Available(addr) => addr,
                }
            }

            fn update(&mut self, newstate: State) {
                //let old_self = ::core::mem::replace(self, State::Present(VirtualAddress(0), PhysicalAddress(0)));
                let old_self = *self;
                let real_newstate = match (old_self, newstate) {
                    // fuse guarded states
                    (State::Guarded(addr), State::Guarded(_)) => State::Guarded(addr),
                    // fuse available states
                    (State::Available(addr), State::Available(_)) => State::Available(addr),
                    // fuse present states only if physical frames are contiguous
                    (State::Present(addr, phys), State::Present(newaddr, newphys))
                        if newphys.addr().wrapping_sub(phys.addr()) == newaddr - addr
                            => State::Present(addr, phys),
                    // otherwise print the old mapping, and start a new one
                    (old, new) => {
                        old.print(new.get_vaddr() - 1);
                        new
                    }
                };
                *self = real_newstate;
            }

            fn from(state: PageState<PhysicalAddress>, addr: VirtualAddress) -> State {
                match state {
                    PageState::Present(table) => State::Present(addr, table),
                    PageState::Guarded => State::Guarded(addr),
                    PageState::Available => State::Available(addr)
                }
            }

            fn print(&self, end_addr: VirtualAddress) {
                match *self {
                    State::Guarded(addr) => info!("{:#010x} - {:#010x} - GUARDED", addr, end_addr),
                    State::Available(addr) => info!("{:#010x} - {:#010x} - AVAILABLE", addr, end_addr),
                    State::Present(addr, phys) => info!("{:#010x} - {:#010x} - MAPS {:#010x} - {:#010x} ({} frames)",
                                                        addr, end_addr, phys, (phys + (end_addr - addr)), ((end_addr + 1) - addr) / PAGE_SIZE),
                };
            }
        }

        let mut address: VirtualAddress = KernelLand::start_addr();
        let mut state = None;
        self.tables.for_every_entry(KernelLand::start_addr(), KernelLand::length(), |entry, length| {
            match state {
                // the first run
                None => { state = Some(State::from(entry, address)) },
                // all others
                Some(ref mut state) => state.update(State::from(entry, address))
            }
            address += length;
        });

        // print the last state
        match state {
            Some(state) => state.print(RecursiveTablesLand::start_addr() - 1),
            None => info!("Tables are empty")
        }
    }
}
