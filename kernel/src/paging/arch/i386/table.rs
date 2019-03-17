//! i386 Page Tables hierarchy

use super::{PAGE_SIZE, ENTRY_COUNT};
use super::lands::{USERLAND_START_TABLE, USERLAND_END_TABLE, KERNELLAND_START_TABLE, KERNELLAND_END_TABLE, DIRECTORY_RECURSIVE_ADDRESS};
use super::entry::{I386Entry, I386EntryFlags};
use super::super::super::hierarchical_table::{HierarchicalTable, SmartHierarchicalTable,
                                              TableHierarchy, InactiveHierarchyTrait,
                                              PagingCacheFlusher, PageState, NoFlush,
                                              HierarchicalEntry};
use super::super::super::kernel_memory::get_kernel_memory;
use super::super::super::MappingAccessRights;
use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait};
use core::fmt::{Debug, Formatter, Error};

/// A page table or directory in memory.
///
/// A page table/directory is just an array of 1024 [I386Entry].
struct Table {
    /// The array of entries making up this table.
    entries: [I386Entry; ENTRY_COUNT]
}

impl Debug for Table {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        Debug::fmt(&&self.entries[..], f)
    }
}

/* ********************************************************************************************** */

/// A currently active page table.
///
/// A [Table] with associated functions.
#[derive(Debug)]
pub struct ActivePageTable(Table);

/// A currently active page directory.
///
/// A [Table] with associated functions, which gets its children [ActivePageTable]
/// through recursive mapping.
#[derive(Debug)]
pub struct ActivePageDirectory(Table);

/// The currently active hierarchy of directory and tables. Gets its [ActivePageDirectory]
/// through recursive mapping.
#[derive(Debug)]
pub struct ActiveHierarchy;

impl HierarchicalTable for ActivePageTable {
    type EntryType = I386Entry;
    type CacheFlusherType = TlbFlush;
    type ChildTableType = Self; // unused since we panic

    fn entries(&mut self) -> &mut [I386Entry] { &mut self.0.entries }

    fn table_level() -> usize { 0 }

    /// Panics, a page table has no children.
    fn get_child_table(&mut self, _index: usize) -> PageState<SmartHierarchicalTable<<Self as HierarchicalTable>::ChildTableType>> {
        panic!("An active page table has no children");
    }

    /// Panics, a page table has no children.
    fn create_child_table(&mut self, _index: usize) -> SmartHierarchicalTable<<Self as HierarchicalTable>::ChildTableType> {
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

    /// Gets a child [ActivePageTable] through recursive mapping.
    fn get_child_table(&mut self, index: usize) -> PageState<SmartHierarchicalTable<ActivePageTable>> {
        // use recursive mapping to get the child table
        self.get_table_address(index)
            .map(|addr| SmartHierarchicalTable::new(unsafe { &mut * (addr as *mut _) }))
    }

    /// Creates a child [ActivePageTable], maps it at the given index, and returns it.
    ///
    /// # Panics
    ///
    /// Panics if the entry was not available.
    #[allow(clippy::absurd_extreme_comparisons)] // USERLAND_START_TABLE <= index is more readable
    fn create_child_table(&mut self, index: usize) -> SmartHierarchicalTable<ActivePageTable> {
        assert!(self.entries()[index].is_unused(), "called create_child_table on a non available entry");
        let table_frame = FrameAllocator::allocate_frame().unwrap();

        // A directory entry is always WRITABLE, write permission is handled at table level.
        let mut flags = I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE;
        // If we're in user land, we should create the table as USER_ACCESSIBLE.
        if USERLAND_START_TABLE <= index && index <= USERLAND_END_TABLE {
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

    /// Gets the [ActivePageDirectory] through recursive mapping.
    ///
    /// # Panics
    ///
    /// Panics if paging is not enabled.
    fn get_top_level_table(&mut self) -> SmartHierarchicalTable<ActivePageDirectory> {
        assert!(super::is_paging_on(), "Paging is disabled");
        SmartHierarchicalTable::new(DIRECTORY_RECURSIVE_ADDRESS.addr() as *mut ActivePageDirectory)
    }
}

/* ********************************************************************************************** */

/// A currently inactive page table.
///
/// A [Table] with associated functions. Must be temporarily mapped to be read and modified.
/// See [SmartHierarchicalTable].
#[derive(Debug)]
pub struct InactivePageTable(Table);

/// A currently inactive page directory.
///
/// A [Table] with associated functions. Must be temporarily mapped to be read and modified.
///
/// Gets its children [InactivePageTable] by temporarily mapping them.
///
/// See [SmartHierarchicalTable].
#[derive(Debug)]
pub struct InactivePageDirectory(Table);

/// A currently inactive hierarchy of directory and tables.
///
/// Can be read and modified by temporarily mapping its [InactivePageDirectory].
#[derive(Debug)]
pub struct InactiveHierarchy {
    /// The address we must put in cr3 to switch to these pages.
    directory_physical_address: PhysicalAddress,
}

impl HierarchicalTable for InactivePageTable {
    type EntryType = I386Entry;
    type CacheFlusherType = NoFlush;
    type ChildTableType = Self; // ignored since we panic

    fn entries(&mut self) -> &mut [I386Entry] { &mut self.0.entries }

    fn table_level() -> usize { 0 }

    /// Panics, a page table has no children.
    fn get_child_table(&mut self, _index: usize) -> PageState<SmartHierarchicalTable<<Self as HierarchicalTable>::ChildTableType>> {
        panic!("An inactive page table has no children");
    }

    /// Panics, a page table has no children.
    fn create_child_table(&mut self, _index: usize) -> SmartHierarchicalTable<<Self as HierarchicalTable>::ChildTableType> {
        panic!("An inactive page table has no children");
    }
}

impl HierarchicalTable for InactivePageDirectory {
    type EntryType = I386Entry;
    type CacheFlusherType = NoFlush;
    type ChildTableType = InactivePageTable;

    fn entries(&mut self) -> &mut [I386Entry] { &mut self.0.entries }

    fn table_level() -> usize { 1 }

    /// Gets the child [InactivePageTable] at the given index. Temporarily maps it if it is present.
    fn get_child_table(&mut self, index: usize) -> PageState<SmartHierarchicalTable<InactivePageTable>> {
        self.entries()[index].pointed_frame().map(|frame| {
            let mut active_pages = get_kernel_memory();
            let phys_region = unsafe {
                // safe: we're only remapping an existing frame, and we hold the locks on both
                // the active and inactive hierarchies. It will be gone before we free those locks.
                PhysicalMemRegion::reconstruct_no_dealloc(frame, PAGE_SIZE)
            };
            let va = active_pages.find_virtual_space(PAGE_SIZE).unwrap();
            active_pages.map_phys_region_to(phys_region, va, MappingAccessRights::k_w());
            SmartHierarchicalTable::new(unsafe {va.addr() as *mut InactivePageTable})
        })
    }

    /// Creates a child [InactivePageTable] at the given index, temporarily maps it, and returns it.
    ///
    /// # Panics
    ///
    /// Panics if the entry was not available.
    #[allow(clippy::absurd_extreme_comparisons)] // USERLAND_START_TABLE <= index is more readable
    fn create_child_table(&mut self, index: usize) -> SmartHierarchicalTable<InactivePageTable> {
        assert!(self.entries()[index].is_unused());
        let table_frame = FrameAllocator::allocate_frame().unwrap();
        let mut active_pages = get_kernel_memory();

        let dup = unsafe {
            // safe: we locally need a duplicate, it won't live past this function
            PhysicalMemRegion::reconstruct_no_dealloc(table_frame.address(), PAGE_SIZE)
        };
        // 1: Map it in our page tables
        let va = active_pages.find_virtual_space(PAGE_SIZE).unwrap();
        active_pages.map_phys_region_to(table_frame, va, MappingAccessRights::k_w());
        let mut mapped_table = SmartHierarchicalTable::new(unsafe {va.addr() as *mut InactivePageTable});
        mapped_table.zero();


        // A directory entry is always WRITABLE, write permission is handled at table level.
        let mut flags = I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE;
        // If we're in user land, we should create the table as USER_ACCESSIBLE.
        if USERLAND_START_TABLE <= index && index <= USERLAND_END_TABLE {
            flags |= I386EntryFlags::USER_ACCESSIBLE;
        }

        // 2: Map it in other's page tables
        self.map_nth_entry(index, dup.address(), flags);

        mapped_table
    }
}

impl Drop for InactivePageDirectory {
    /// When the temporary inactive directory is drop, we unmap it.
    fn drop(&mut self) {
        get_kernel_memory().unmap_no_dealloc(VirtualAddress(self as *mut _ as usize), PAGE_SIZE);
    }
}

impl Drop for InactivePageTable {
    /// When the temporary inactive table is drop, we unmap it.
    fn drop(&mut self) {
        get_kernel_memory().unmap_no_dealloc(VirtualAddress(self as *mut _ as usize), PAGE_SIZE);
    }
}

impl TableHierarchy for InactiveHierarchy {
    type TopLevelTableType = InactivePageDirectory;

    /// Gets the [InactivePageDirectory] by temporarily mapping it.
    fn get_top_level_table(&mut self) -> SmartHierarchicalTable<InactivePageDirectory> {
        let frame = unsafe {
            // we're reconstructing a non-tracked RecursiveTableLand frame.
            PhysicalMemRegion::reconstruct_no_dealloc(self.directory_physical_address, PAGE_SIZE)
        };
        let mut active_pages = get_kernel_memory();
        let va = active_pages.find_virtual_space(PAGE_SIZE).unwrap();
        active_pages.map_phys_region_to(frame, va, MappingAccessRights::READABLE | MappingAccessRights::WRITABLE);
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
        dir.entries()[KERNELLAND_START_TABLE..=KERNELLAND_END_TABLE]
            .clone_from_slice(&active_dir.entries()[KERNELLAND_START_TABLE..=KERNELLAND_END_TABLE]);
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

/// When passing this struct the TLB will be flushed. Used by [ActivePageTable].
pub struct TlbFlush;
impl PagingCacheFlusher for TlbFlush { fn flush_whole_cache() { super::flush_tlb(); } }
