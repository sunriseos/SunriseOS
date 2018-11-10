//! The management of kernel memory
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
use super::MappingFlags;
use mem::{VirtualAddress, PhysicalAddress};
use frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait,
                      mark_frame_bootstrap_allocated};
use sync::{Mutex, MutexGuard};
use error::KernelError;
use failure::Backtrace;

/// A struct that acts on KernelLand and RecursiveTablesLand.
///
/// Always modifies the ACTIVE_PAGE_TABLES.
/// When switching to a new set of page tables in a process switch, the modifications will be copied
/// to the set just before switching to it.
///
/// Because of this mechanism we do not permit modifying KernelLand in other tables
/// than the currently active ones.
pub struct KernelMemory {
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

    /// Finds a hole in the virtual space at least 'length' long, and respecting alignment
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

    /// Maps a single physical regions to a given virtual address
    pub fn map_phys_region_to(&mut self, phys: PhysicalMemRegion, address: VirtualAddress, flags: MappingFlags) {
        assert!(KernelLand::contains_region(address, phys.size()));
        // convert region as a slice of 1 region
        let region_as_slice = unsafe {
            ::core::slice::from_raw_parts(&phys as *const PhysicalMemRegion, 1)
        };
        self.tables.map_to(region_as_slice, address, flags);
        // physical region must not be deallocated while it is mapped
        ::core::mem::forget(phys);
    }

    /// Maps a single physical region anywhere
    pub fn map_phys_region(&mut self, phys: PhysicalMemRegion, flags: MappingFlags) -> VirtualAddress {
        let va = self.find_virtual_space(phys.size()).unwrap();
        self.map_phys_region_to(phys, va, flags);
        va
    }

    /// Allocates and maps a single page, choosing a spot in VMEM for it.
    pub fn get_page(&mut self) -> VirtualAddress {
        let pr = FrameAllocator::allocate_frame().unwrap();
        self.map_phys_region(pr, MappingFlags::WRITABLE)
    }

    /// Allocates non-contiguous frames, and map them at the given address
    pub fn map_allocate_to(&mut self, va: VirtualAddress, length: usize, flags: MappingFlags) {
        assert!(KernelLand::contains_region(va, length));
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        let mut prs = FrameAllocator::allocate_frames_fragmented(length / PAGE_SIZE).unwrap();
        self.tables.map_to(&prs, va, flags);

        // do not drop the frames, they are mapped in the page tables !
        while let Some(region) = prs.pop() {
            ::core::mem::forget(region);
        }
    }

    /// Allocates and maps the given length, chosing a spot in VMEM for it.
    ///
    /// # Panics
    ///
    /// Panics if we are out of memory.
    /// Panics if length is not a multiple of PAGE_SIZE.
    pub fn get_pages(&mut self, length: usize) -> VirtualAddress {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        let va = self.find_virtual_space(length).unwrap();
        self.map_allocate_to(va, length, MappingFlags::WRITABLE);
        va
    }

    /// Guards a range of addresses
    pub fn guard(&mut self, address: VirtualAddress, length: usize) {
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.get_hierarchy().guard(address, length);
    }

    /// Reads the state of the mapping at a given address
    pub fn mapping_state(&mut self, addr: VirtualAddress) -> PageState<PhysicalAddress> {
        let mut mapping= None;
        let addr_aligned = VirtualAddress(::utils::align_down(addr.addr(), PAGE_SIZE));
        assert!(KernelLand::contains_address(addr));
        // use for_every_entry with length of just one page
        self.tables.for_every_entry(addr_aligned, PAGE_SIZE,
        | state, _ | mapping = Some(state));
        mapping.unwrap()
    }

    /// Deletes a mapping in the page tables.
    /// This functions assumes the frames were not tracked anywhere else, and drops them.
    pub fn unmap(&mut self, address: VirtualAddress, length: usize) {
        assert!(KernelLand::contains_region(address, length));
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.tables.unmap(address, length, |paddr| {
            let pr = unsafe {
                // safe, they were only tracked by the page tables
                PhysicalMemRegion::reconstruct(paddr, PAGE_SIZE);
            };
            drop(pr)
        });
    }

    /// Deletes a mapping in the page tables, but does not free the underlying physical memory.
    pub fn unmap_no_dealloc(&mut self, address: VirtualAddress, length: usize) {
        assert!(KernelLand::contains_region(address, length));
        assert!(length % PAGE_SIZE == 0, "length must be a multiple of PAGE_SIZE");
        self.tables.unmap(address, length, |paddr| { /* leak the frame */ });
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
                mark_frame_bootstrap_allocated(mapped_frame)
            }
        });
    }

    /// Safe access to the active page tables.
    pub(super) fn get_hierarchy(&mut self) -> &mut ActiveHierarchy {
        &mut self.tables
    }

    /// Prints the current mapping.
    pub fn print_mapping(&mut self) {
        #[derive(Debug, Clone, Copy)]
        enum State { Present(usize, usize), Guarded(usize), Available(usize) }
        impl State {
            fn get_vaddr(&self) -> usize {
                match self {
                    &State::Present(addr, _) => addr,
                    &State::Guarded(addr) => addr,
                    &State::Available(addr) => addr,
                }
            }

            fn update(&mut self, newstate: State) {
                let old_self = ::core::mem::replace(self, State::Present(0, 0));
                let mut real_newstate = match (old_self, newstate) {
                    (State::Present(addr, phys), State::Present(newaddr, newphys)) if newphys.wrapping_sub(phys) == newaddr - addr => State::Present(addr, phys),
                    (State::Present(addr, phys), State::Present(newaddr, newphys)) => State::Present(addr, phys),
                    (State::Guarded(addr), State::Guarded(newaddr)) => State::Guarded(addr),
                    (State::Available(addr), State::Available(newaddr)) => State::Available(addr),
                    (old, new) => {
                        old.print(new);
                        new
                    }
                };
                *self = real_newstate;
            }

            fn from(set: &mut KernelMemory, addr: VirtualAddress) -> State {
                match set.mapping_state(addr) {
                    PageState::Present(table) => State::Present(addr.addr(), table.addr()),
                    PageState::Guarded => State::Guarded(addr.addr()),
                    _ => State::Available(addr.addr())
                }
            }

            fn print(&self, newstate: State) {
                let new_vaddr = newstate.get_vaddr();
                match *self {
                    State::Present(addr, phys) => info!("{:#010x} - {:#010x} - MAPS {:#010x}-{:#010x}", addr, new_vaddr, phys, (phys + (new_vaddr - addr))),
                    State::Guarded(addr) => info!("{:#010x} - {:#010x} - GUARDED", addr, new_vaddr),
                    State::Available(addr) => info!("{:#010x} - {:#010x} - AVAILABLE", addr, new_vaddr),
                };
            }
        }

        let mut iter = (KernelLand::start_addr().addr()..=KernelLand::end_addr().addr()).step_by(PAGE_SIZE);
        let mut state = State::from(self, VirtualAddress(iter.next().unwrap()));

        // Don't print last entry because it's just the recursive entry.
        for vaddr in iter {
            state.update(State::from(self, VirtualAddress(vaddr)));
        }

        state.print(State::Available(RecursiveTablesLand::start_addr().addr()));
    }
}
