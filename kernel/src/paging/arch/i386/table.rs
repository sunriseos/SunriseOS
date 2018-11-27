//! i386 Page Tables hierarchy

use super::{PAGE_SIZE, ENTRY_COUNT};
use super::entry::{I386Entry, I386EntryFlags};
use super::super::super::hierarchical_table::{HierarchicalTable, SmartHierarchicalTable,
                                              TableHierarchy, InactiveHierarchyTrait,
                                              PagingCacheFlusher, PageState, NoFlush,
                                              HierarchicalEntry};
use super::super::super::lands::{KernelLand, UserLand, VirtualSpaceLand};
use super::super::super::kernel_memory::get_kernel_memory;
use super::super::super::MappingFlags;
use mem::{VirtualAddress, PhysicalAddress};
use frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait};

/// When paging is on, accessing this address loops back to the directory itself thanks to
/// recursive mapping on directory's last entry
pub const DIRECTORY_RECURSIVE_ADDRESS: VirtualAddress = VirtualAddress(0xffff_f000);

/// A page table in memory
struct Table {
    entries: [I386Entry; ENTRY_COUNT]
}

/* ********************************************************************************************** */

pub struct ActivePageTable(Table);
pub struct ActivePageDirectory(Table);
pub struct ActiveHierarchy;

impl HierarchicalTable for ActivePageTable {
    type EntryType = I386Entry;
    type CacheFlusherType = TlbFlush;
    type ChildTableType = Self; // unused since we panic

    fn entries(&mut self) -> &mut [I386Entry] { &mut self.0.entries }

    fn table_level() -> usize { 0 }

    fn get_child_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType>> {
        panic!("An active page table has no children");
    }

    fn create_child_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType> {
        panic!("An active page table has no children");
    }
}

impl ActivePageDirectory {
    /// reduce recursive mapping by one time to get further down in table hierarchy
    fn get_table_address(&mut self, index: usize) -> PageState<usize> {
        match self.entries()[index].pointed_frame() {
            PageState::Present(_) => {
                let table_address = self as *const _ as usize;
                PageState::Present((table_address << 10) | (index << 12))
            },
            PageState::Available => PageState::Available,
            PageState::Guarded => PageState::Guarded
        }
    }
}

impl HierarchicalTable for ActivePageDirectory {
    type EntryType = I386Entry;
    type CacheFlusherType = TlbFlush;
    type ChildTableType = ActivePageTable;

    fn entries(&mut self) -> &mut [I386Entry] { &mut self.0.entries }

    fn table_level() -> usize { 1 }

    fn get_child_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, ActivePageTable>> {
        // use recurive mapping to get the child table
        self.get_table_address(index)
            .map(|addr| SmartHierarchicalTable::new(unsafe { &mut * (addr as *mut _) }))
    }

    fn create_child_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, ActivePageTable> {
        assert!(self.entries()[index].is_unused(), "called create_child_table on a non available entry");
        let table_frame = FrameAllocator::allocate_frame().unwrap();

        // A directory entry is always WRITABLE, write permission is handled at table level.
        let mut flags = I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE;
        // If we're in user land, we should create the table as USER_ACCESSIBLE.
        if UserLand::start_table() <= index && index <= UserLand::end_table() {
            flags |= I386EntryFlags::USER_ACCESSIBLE;
        }

        self.map_nth_entry(index, table_frame.address(), flags);
        // frame is mapped in RecursiveTablesLand
        ::core::mem::forget(table_frame);

        // Now that table is mapped in page directory we can write to it through recursive mapping
        let mut table = self.get_child_table(index).unwrap();
        table.zero();
        table
    }
}

impl TableHierarchy for ActiveHierarchy {
    type TopLevelTableType = ActivePageDirectory;

    fn get_top_level_table<'a>(&'a mut self) -> SmartHierarchicalTable<'a, ActivePageDirectory> {
        assert!(super::is_paging_on(), "Paging is disabled");
        SmartHierarchicalTable::new(DIRECTORY_RECURSIVE_ADDRESS.addr() as *mut ActivePageDirectory)
    }
}

/* ********************************************************************************************** */

pub struct InactivePageTable(Table);
pub struct InactivePageDirectory(Table);
#[derive(Debug)]
pub struct InactiveHierarchy {
    // The address we must put in cr3 to switch to these pages
    directory_physical_address: PhysicalAddress,
}

impl HierarchicalTable for InactivePageTable {
    type EntryType = I386Entry;
    type CacheFlusherType = NoFlush;
    type ChildTableType = Self; // ignored since we panic

    fn entries(&mut self) -> &mut [I386Entry] { &mut self.0.entries }

    fn table_level() -> usize { 0 }

    fn get_child_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType>> {
        panic!("An inactive page table has no children");
    }

    fn create_child_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, <Self as HierarchicalTable>::ChildTableType> {
        panic!("An inactive page table has no children");
    }
}

impl HierarchicalTable for InactivePageDirectory {
    type EntryType = I386Entry;
    type CacheFlusherType = NoFlush;
    type ChildTableType = InactivePageTable;

    fn entries(&mut self) -> &mut [I386Entry] { &mut self.0.entries }

    fn table_level() -> usize { 1 }

    fn get_child_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, InactivePageTable>> {
        self.entries()[index].pointed_frame().map(|frame| {
            let mut active_pages = get_kernel_memory();
            let phys_region = unsafe {
                // safe: we're only remapping an existing frame, and we hold the locks on both
                // the active and inactive hierarchies. It will be gone before we free those locks.
                PhysicalMemRegion::reconstruct_no_dealloc(frame, PAGE_SIZE)
            };
            let va = active_pages.find_virtual_space(PAGE_SIZE).unwrap();
            active_pages.map_phys_region_to(phys_region, va, MappingFlags::k_w());
            SmartHierarchicalTable::new(unsafe {va.addr() as *mut InactivePageTable})
        })
    }

    fn create_child_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, InactivePageTable> {
        assert!(self.entries()[index].is_unused());
        let table_frame = FrameAllocator::allocate_frame().unwrap();
        let mut active_pages = get_kernel_memory();

        let dup = unsafe {
            // safe: we locally need a duplicate, it won't live past this function
            PhysicalMemRegion::reconstruct_no_dealloc(table_frame.address(), PAGE_SIZE)
        };
        // 1: Map it in our page tables
        let va = active_pages.find_virtual_space(PAGE_SIZE).unwrap();
        active_pages.map_phys_region_to(table_frame, va, MappingFlags::k_w());
        let mut mapped_table = SmartHierarchicalTable::new(unsafe {va.addr() as *mut InactivePageTable});
        mapped_table.zero();


        // A directory entry is always WRITABLE, write permission is handled at table level.
        let mut flags = I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE;
        // If we're in user land, we should create the table as USER_ACCESSIBLE.
        if UserLand::start_table() <= index && index <= UserLand::end_table() {
            flags |= I386EntryFlags::USER_ACCESSIBLE;
        }

        // 2: Map it in other's page tables
        self.map_nth_entry(index, dup.address(), flags);

        mapped_table
    }
}

/// When the temporary inactive directory is drop, we unmap it
impl Drop for InactivePageDirectory {
    fn drop(&mut self) {
        get_kernel_memory().unmap_no_dealloc(VirtualAddress(self as *mut _ as usize), PAGE_SIZE);
    }
}

/// When the temporary inactive table is drop, we unmap it
impl Drop for InactivePageTable {
    fn drop(&mut self) {
        get_kernel_memory().unmap_no_dealloc(VirtualAddress(self as *mut _ as usize), PAGE_SIZE);
    }
}

impl TableHierarchy for InactiveHierarchy {
    type TopLevelTableType = InactivePageDirectory;

    fn get_top_level_table<'a>(&'a mut self) -> SmartHierarchicalTable<'a, InactivePageDirectory> {
        let frame = unsafe {
            // we're reconstructing a non-tracked RecursiveTableLand frame.
            PhysicalMemRegion::reconstruct_no_dealloc(self.directory_physical_address, PAGE_SIZE)
        };
        let mut active_pages = get_kernel_memory();
        let va = active_pages.find_virtual_space(PAGE_SIZE).unwrap();
        active_pages.map_phys_region_to(frame, va, MappingFlags::READABLE | MappingFlags::WRITABLE);
        SmartHierarchicalTable::new(va.addr() as *mut InactivePageDirectory)
    }
}

impl InactiveHierarchyTrait for InactiveHierarchy {
    fn new() -> Self {
        let directory_frame = FrameAllocator::allocate_frame().unwrap();
        let mut pageset = InactiveHierarchy {
            directory_physical_address: directory_frame.address()
        };
        {
            let mut dir = pageset.get_top_level_table();
            dir.zero();
            dir.map_nth_entry(ENTRY_COUNT - 1, directory_frame.address(), I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE);
        };
        // don't deallocate it, it is mapped now.
        ::core::mem::forget(directory_frame);

        pageset
    }


    fn switch_to(&mut self) {
        // Copy the kernel space tables
        self.copy_active_kernel_space();
        super::swap_cr3(self.directory_physical_address);
    }

    fn copy_active_kernel_space(&mut self) {
        let mut dir = self.get_top_level_table();
        let mut memory = get_kernel_memory();
        let mut active_dir = memory.get_hierarchy().get_top_level_table();
        for entry_index in KernelLand::start_table()..=KernelLand::end_table() {
            dir.entries()[entry_index] = active_dir.entries()[entry_index];
        }
    }

    fn is_currently_active(&self) -> bool {
        super::read_cr3() == self.directory_physical_address
    }

    unsafe fn from_currently_active() -> Self {
        InactiveHierarchy {
            directory_physical_address: super::read_cr3(),
        }
    }
}

/* ********************************************************************************************** */

/// When passing this struct the TLB will be flushed. Used by ActivePageTables
pub struct TlbFlush;
impl PagingCacheFlusher for TlbFlush { fn flush_whole_cache() { super::flush_tlb(); } }
