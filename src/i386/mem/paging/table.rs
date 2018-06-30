//! i386 page table / directory

use core::ops::{Index, IndexMut, Bound, RangeBounds};

// Yeah, I'm ugly. Screw you.
#[path = "entry.rs"]
pub mod entry;

use logger::Loggers;
use self::entry::{EntryFlags as I386EntryFlags, PageState};
use super::*;
use i386::mem::frame_alloc::{Frame, FrameAllocator, MEMORY_FRAME_SIZE};
use i386::mem::{VirtualAddress, PhysicalAddress};
use core::ops::Deref;
use core::ops::DerefMut;
use core::marker::PhantomData;

/// A page table
pub struct PageTable {
    entries: [Entry; ENTRY_COUNT]
}

/// A page directory
pub struct PageDirectory(PageTable);

// Assertions
fn __assertions() {
    const_assert!(::core::mem::size_of::<PageDirectory>() >= MEMORY_FRAME_SIZE);
    const_assert!(::core::mem::size_of::<PageTable>() >= MEMORY_FRAME_SIZE);
    const_assert!(::core::mem::size_of::<PageTable>() == ::core::mem::size_of::<PageDirectory>());
}

/// When paging is on, accessing this address loops back to the directory itself thanks to
/// recursive mapping on directory's last entry
pub const DIRECTORY_RECURSIVE_ADDRESS: VirtualAddress = VirtualAddress(0xffff_f000);

/// Implementing Index so we can do `table[42]` to get the 42nd entry easily
impl Index<usize> for PageDirectory {
    type Output = Entry;

    fn index (&self, index: usize) -> &Entry { &self.entries()[index] }
}

impl Index<usize> for PageTable {
    type Output = Entry;

    fn index (&self, index: usize) -> &Entry { &self.entries()[index] }
}

impl IndexMut<usize> for PageDirectory {
    fn index_mut(&mut self, index: usize) -> &mut Entry { &mut self.entries_mut()[index] }
}

impl IndexMut<usize> for PageTable {
    fn index_mut(&mut self, index: usize) -> &mut Entry { &mut self.entries_mut()[index] }
}

/// A table of entries, either the directory or one of the page tables
pub trait HierarchicalTable {

    fn entries(&self) -> &[Entry; ENTRY_COUNT];
    fn entries_mut(&mut self) -> &mut [Entry; ENTRY_COUNT];

    /// zero out the whole table
    fn zero(&mut self) {
        for entry in self.entries_mut().iter_mut() {
            entry.set(Frame::from_physical_addr(PhysicalAddress(0)), I386EntryFlags::empty());
        }
    }

    /// Creates a mapping on the nth entry of a table
    /// T is a flusher describing if we should flush the TLB or not
    fn map_nth_entry<T: Flusher>(&mut self, entry: usize, frame: Frame, flags: I386EntryFlags) {
        self.entries_mut()[entry].set(frame, flags);
        T::flush_cache();
    }

    /// Marks the nth entry as guard page
    /// T is a flusher describing if we should flush the TLB or not
    fn guard_nth_entry<T: Flusher>(&mut self, entry: usize) {
        self.entries_mut()[entry].set_guard();
        T::flush_cache();
    }

    fn flush_cache() {
        // Don't do anything by default
    }
}

impl HierarchicalTable for PageTable {
    fn entries(&self) -> &[Entry; ENTRY_COUNT] { &self.entries }
    fn entries_mut(&mut self) -> &mut [Entry; ENTRY_COUNT] { &mut self.entries }
}
impl HierarchicalTable for PageDirectory {
    fn entries(&self) -> &[Entry; ENTRY_COUNT] { &self.0.entries }
    fn entries_mut(&mut self) -> &mut [Entry; ENTRY_COUNT] { &mut self.0.entries }
}


/* ********************************************************************************************** */

pub trait PageTableTrait : HierarchicalTable {
    type FlusherType : Flusher;
    /// Used at startup when creating the first page tables.
    ///
    // TODO: deleteme
    #[deprecated]
    fn map_whole_table(&mut self, start_address: PhysicalAddress, flags: I386EntryFlags) {
        let mut addr = start_address.addr();
        for entry in &mut self.entries_mut()[..] {
            entry.set(Frame::from_physical_addr(PhysicalAddress(addr)), flags);
            addr += PAGE_SIZE;
        }
        Self::FlusherType::flush_cache();
    }

    /// Used at startup when creating the first page tables.
    fn map_guard_whole_table(&mut self) {
        for entry in &mut self.entries_mut()[..] {
            entry.set(Frame::from_physical_addr(PhysicalAddress(0)), I386EntryFlags::GUARD_PAGE);
        }
        Self::FlusherType::flush_cache();
    }
}

/// A trait describing all the things that a PageDirectory can do.
///
/// Implementer only has to provide functions to map a table and create one,
/// and the trait does the rest.
///
/// Thanks to this we can have the same api for every kind of directories, the only difference is
/// the way we access the page tables for writing :
///
/// * an ActivePageDirectory will want to use recursive mapping
/// * an InactivePageDirectory will want to temporarily map the table
/// * a  PagingOffPageDirectory will point to physical memory
pub trait PageDirectoryTrait : HierarchicalTable {
    type PageTableType : PageTableTrait;
    type FlusherType : Flusher;

    /// Gets a reference to a page table
    fn get_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, Self::PageTableType>>;

    /// Allocates a page table, zero it and add an entry to the directory pointing to it
    fn create_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, Self::PageTableType>;

    /// Gets the page table at given index, or creates it if it does not exist
    ///
    /// # Panics
    ///
    /// Panics if the whole page table is guarded.
    fn get_table_or_create<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, Self::PageTableType> {
        if !self.entries()[index].is_unused() {
            assert!(!self.entries()[index].is_guard(), "Table is guarded");
            self.get_table(index).unwrap()
        } else {
            self.create_table(index)
        }
    }

    /// Creates a mapping in the page tables with the given flags
    ///
    /// # Panics
    ///
    /// Panics if entry was already in use
    /// Panics if address is not page-aligned.
    fn map_to(&mut self, page:    Frame,
                         address: VirtualAddress,
                         flags:   I386EntryFlags) {
        assert_eq!(address.addr() % PAGE_SIZE, 0, "Address is not page aligned");
        let table_nbr = address.addr() / (ENTRY_COUNT * PAGE_SIZE);
        let table_off = address.addr() % (ENTRY_COUNT * PAGE_SIZE) / PAGE_SIZE;
        debug!("Mapping {} to {} ({}/{})", page.address(), address, table_nbr, table_off);
        let mut table = self.get_table_or_create(table_nbr);
        assert!(table.entries()[table_off].is_unused(), "Tried to map an already mapped entry: {:?}", table.entries()[table_off]);
        table.map_nth_entry::<Self::FlusherType>(table_off, page, flags);
    }

    /// Creates a guard page
    ///
    /// # Panics
    ///
    /// Panics if entry was already in use
    /// Panics if address is not page-aligned.
    fn guard(&mut self, address: VirtualAddress) {
        assert_eq!(address.addr() % PAGE_SIZE, 0, "Address is not page aligned");
        let table_nbr = address.addr() / (ENTRY_COUNT * PAGE_SIZE);
        let table_off = address.addr() % (ENTRY_COUNT * PAGE_SIZE) / PAGE_SIZE;
        let mut table = self.get_table_or_create(table_nbr);
        assert!(table.entries()[table_off].is_unused(), "Tried to guard an already mapped entry {:#010x}: {:?}", address.addr(), table.entries()[table_off]);
        table.guard_nth_entry::<Self::FlusherType>(table_off);
    }

    /// Deletes a mapping in the page tables, returning the frame if it existed.
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    fn __unmap(&mut self, page: VirtualAddress) -> PageState<Frame> {
        assert_eq!(page.addr() % PAGE_SIZE, 0, "Address is not page aligned");
        let table_nbr = page.addr() / (ENTRY_COUNT * PAGE_SIZE);
        let table_off = page.addr() % (ENTRY_COUNT * PAGE_SIZE) / PAGE_SIZE;

        // First, handle big page guards.
        let mut table = if self.entries()[table_nbr].is_guard() {
            // Split the guard.
            self.entries_mut()[table_nbr].set_unused();
            let mut table = self.create_table(table_nbr);
            table.map_guard_whole_table();
            table
        } else {
            self.get_table(table_nbr)
            // TODO: Return an Error if the table was not present
                .unwrap()
            // TODO: Return an Error if the address was not mapped
        };

        let entry= &mut table.entries_mut()[table_off];
        assert_eq!(entry.is_unused(), false);
        let ret = entry.set_unused();
        Self::FlusherType::flush_cache();
        ret
    }

    /// Finds a virtual space hole that can contain page_nb consecutive pages
    /// Alignment is the bitshift of a mask that the first page address must satisfy (ex: 24 for 0x**000000)
    fn find_available_virtual_space_aligned<Land: VirtualSpaceLand>(&mut self,
                                                            page_nb: usize,
                                                            alignement: usize) -> Option<VirtualAddress> {
        fn compute_address(table: usize, page: usize) -> VirtualAddress {
            VirtualAddress(table * ENTRY_COUNT * PAGE_SIZE + page * PAGE_SIZE)
        }
        fn satisfies_alignement(table: usize, page: usize, alignment: usize) -> bool {
            let mask : usize = (1 << alignment) - 1;
            compute_address(table, page).addr() & mask == 0
        }
        let mut considering_hole: bool = false;
        let mut hole_size: usize = 0;
        let mut hole_start_table: usize = 0;
        let mut hole_start_page:  usize = 0;
        let mut counter_curr_table:  usize = Land::start_table();
        let mut counter_curr_page:   usize = 0;
        while counter_curr_table < Land::end_table() && (!considering_hole || hole_size < page_nb) {
            counter_curr_page = 0;
            match self.get_table(counter_curr_table) {
                PageState::Available => { // The whole page table is free, so add it to our hole_size
                    if !considering_hole
                        && satisfies_alignement(counter_curr_page, 0, alignement) {
                        // This is the start of a hole
                        considering_hole = true;
                        hole_start_table = counter_curr_table;
                        hole_start_page = 0;
                        hole_size = 0;
                    }
                    hole_size += ENTRY_COUNT;
                },
                PageState::Guarded => {
                    considering_hole = false;
                },
                PageState::Present(curr_table) => {
                    while counter_curr_page < ENTRY_COUNT && (!considering_hole || hole_size < page_nb) {
                        if curr_table.entries()[counter_curr_page].is_unused() {
                            if !considering_hole
                                && satisfies_alignement(counter_curr_table, counter_curr_page, alignement) {
                                // This is the start of a hole
                                considering_hole = true;
                                hole_start_table = counter_curr_table;
                                hole_start_page = counter_curr_page;
                                hole_size = 0;
                            }
                            hole_size += 1;
                        } else {
                            // The current hole was not big enough, so reset counter
                            considering_hole = false;
                        }
                        counter_curr_page += 1;
                    }
                }
            }
            counter_curr_table += 1;
        };
        if considering_hole && hole_size >= page_nb { // The last tested hole was big enough
            Some(compute_address(hole_start_table, hole_start_page))
        } else { // No hole was big enough
            None
        }
    }
}

bitflags! {
    /// The flags of a table entry
    pub struct EntryFlags : u32 {
        const WRITABLE =        1 << 0;
        const USER_ACCESSIBLE = 1 << 1;
    }
}

/// The type of a Virtual Memory mapping. Can either be Present, in which case
/// it is linked to a Frame and some flags, or Guard.
pub enum MappingType {
    Present(Frame, EntryFlags),
    Guard
}

pub trait PageTablesSet {
    /// Creates a mapping in the page tables with the given flags
    fn map_to(&mut self, mapping: MappingType, address: VirtualAddress);

    /// Gets the current mapping state of this Virtual Address.
    fn get_phys(&mut self, address: VirtualAddress) -> PageState<PhysicalAddress>;

    /// Finds a virtual space hole that can contain page_nb consecutive pages
    fn find_available_virtual_space_aligned<Land: VirtualSpaceLand>(&mut self, page_nb: usize, alignement: usize) -> Option<VirtualAddress>;


    /// Deletes a mapping in the page tables, returning the Frame if one was
    /// mapped.
    ///
    /// # Panics
    ///
    /// Panics if page is not page-aligned.
    fn unmap(&mut self, page: VirtualAddress) -> PageState<Frame>;

    /// Creates a mapping in the page tables with the given flags.
    /// Allocates the pointed page
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    fn map_allocate_to(&mut self, address: VirtualAddress, flags: EntryFlags) {
        let page = FrameAllocator::alloc_frame();
        self.map_to(MappingType::Present(page, flags), address);
    }


    /// Maps a given frame in the page tables. Takes care of choosing the virtual address
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    fn map_frame<Land: VirtualSpaceLand>(&mut self, frame: Frame, flags: EntryFlags) -> VirtualAddress {
        let va = self.find_available_virtual_space::<Land>(1).unwrap();
        self.map_to(MappingType::Present(frame, flags), va);
        va
    }

    /// Creates a mapping in the page tables with the given flags.
    /// Allocates the pointed page and chooses the virtual address.
    ///
    /// # Panics
    ///
    /// Panics if we are out of memory.
    fn get_page<Land: VirtualSpaceLand>(&mut self) -> VirtualAddress {
        let va = self.find_available_virtual_space::<Land>(1).unwrap();
        self.map_allocate_to(va, EntryFlags::WRITABLE);
        va
    }

    /// Reserves a given page as guard page.
    /// This affects only virtual memory and doesn't take any actual physical frame.
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    fn map_page_guard(&mut self, address: VirtualAddress) {
        // Just map to frame 0, it will page fault anyway since PRESENT is missing
        debug!("Guarding {}", address);
        self.map_to(MappingType::Guard, address);
    }

    /// Reserve a given region as guard pages.
    /// If the region spans more than ENTRY_COUNT pages, then the whole page
    /// table will be page-guarded.
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    fn map_range_page_guard(&mut self, address: VirtualAddress, page_nb: usize) {
        for current_address in (address.addr()..address.addr() + (page_nb * PAGE_SIZE)).step_by(PAGE_SIZE) {
            self.map_page_guard(VirtualAddress(current_address))
        }
    }

    /// Maps the given physical address range to the given virtual address
    ///
    /// Note that those physical addresses must **not** be allocated through the
    /// Frame Allocator.
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    // TODO: Do something about allocated frames going through this interface.
    fn map_range(&mut self, phys_addr: PhysicalAddress, address: VirtualAddress, page_nb: usize, flags: EntryFlags) {
        let address_end = VirtualAddress(address.addr() + (page_nb * PAGE_SIZE));
        for addr_offset in (0..page_nb * PAGE_SIZE).step_by(PAGE_SIZE) {
            self.map_to(MappingType::Present(Frame::from_physical_addr(phys_addr + addr_offset), flags), address + addr_offset);
        }
    }

    /// Maps a given number of consecutive pages at a given address
    /// Allocates the frames
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    fn map_range_allocate(&mut self, address: VirtualAddress, page_nb: usize, flags: EntryFlags) {
        let address_end = VirtualAddress(address.addr() + (page_nb * PAGE_SIZE));
        for current_address in (address.addr()..address_end.addr()).step_by(PAGE_SIZE) {
            self.map_allocate_to(VirtualAddress(current_address), flags);
        }
    }

    /// Maps a memory frame to the same virtual address
    fn identity_map(&mut self, frame: Frame, flags: EntryFlags) {
        let addr = frame.address().addr();
        self.map_to(MappingType::Present(frame, flags), VirtualAddress(addr));
    }

    /// Identity maps a range of frames
    ///
    /// Note that those physical addresses must **not** be allocated through the
    /// Frame Allocator.
    // TODO: ^
    fn identity_map_region(&mut self, start_address: PhysicalAddress, region_size: usize, flags: EntryFlags) {
        assert_eq!(start_address.addr() % PAGE_SIZE, 0, "Tried to map a non paged-aligned region");
        let start = round_to_page(start_address.addr());
        let end = round_to_page_upper(start_address.addr() + region_size);
        for frame_addr in (start..end).step_by(PAGE_SIZE) {
            let frame = Frame::from_physical_addr(PhysicalAddress(frame_addr));
            self.identity_map(frame, flags);
        }
    }

    /// Finds a virtual space hole that can contain page_nb consecutive pages
    fn find_available_virtual_space<Land: VirtualSpaceLand>(&mut self, page_nb: usize) -> Option<VirtualAddress> {
        // find_available_available_virtual_space_aligned with any alignement
        self.find_available_virtual_space_aligned::<Land>(page_nb, 0)
    }

}

/* ********************************************************************************************** */

mod detail {
    /// A trait describing the interface of a PageTable hierarchy.
    ///
    /// Implemented by ActivePageTables, InactivePageTables and PagingOffPageSet
    ///
    /// Implementer only has to provide the type of the directory it will provide, and a function
    /// to map it.
    ///
    /// Thanks to this we can have the same api for every kind of page tables, the only difference is
    /// the way we access the page directory :
    ///
    /// * an ActivePageDirectory will want to use recursive mapping
    /// * an InactivePageDirectory will want to temporarily map the directory
    /// * a  PagingOffPageDirectory will point to physical memory
    pub trait I386PageTablesSet {
        type PageDirectoryType: super::PageDirectoryTrait;
        /// Gets a reference to the directory
        fn get_directory<'a>(&'a mut self) -> super::SmartHierarchicalTable<'a, Self::PageDirectoryType>;
    }
}

use self::detail::I386PageTablesSet;

impl<T: I386PageTablesSet> PageTablesSet for T {
    /// Creates a mapping in the page tables with the given flags
    fn map_to(&mut self, mapping: MappingType, address: VirtualAddress) {
        let mut dir = self.get_directory();
        match mapping {
            MappingType::Present(frame, flags) => dir.map_to(frame, address, flags.into()),
            MappingType::Guard => dir.guard(address)
        }
    }

    fn get_phys(&mut self, address: VirtualAddress) -> PageState<PhysicalAddress> {
        let table_nbr = address.addr() / (ENTRY_COUNT * PAGE_SIZE);
        let table_off = address.addr() % (ENTRY_COUNT * PAGE_SIZE) / PAGE_SIZE;
        let mut directory = self.get_directory();
        let table = match directory.get_table(table_nbr) {
            PageState::Available => return PageState::Available,
            PageState::Guarded => return PageState::Guarded,
            PageState::Present(table) => table
        };
        table.entries()[table_off].pointed_frame()
    }

    /// Finds a virtual space hole that can contain page_nb consecutive pages
    fn find_available_virtual_space_aligned<Land: VirtualSpaceLand>(&mut self, page_nb: usize, alignement: usize) -> Option<VirtualAddress> {
         self.get_directory().find_available_virtual_space_aligned::<Land>(page_nb, alignement)
    }


    /// Deletes a mapping in the page tables, returning the Frame if one was
    /// mapped.
    ///
    /// # Panics
    ///
    /// Panics if page is not page-aligned.
    fn unmap(&mut self, page: VirtualAddress) -> PageState<Frame> {
        debug!("Unmapping {}", page);
        self.get_directory().__unmap(page)
    }
}

/// A macro to easily implement Index and Deref traits on our PageTableSets
macro_rules! inherit_deref_index {
    ($ty:ty, $sub_ty:ty) => {
        impl Deref for $ty {
            type Target = $sub_ty;
            fn deref(&self) -> &<Self as Deref>::Target { &self.0 }
        }
        impl DerefMut for $ty {
            fn deref_mut(&mut self) -> &mut <Self as Deref>::Target { &mut self.0 }
        }
        impl Index<usize> for $ty {
            type Output = <$sub_ty as Index<usize>>::Output;
            fn index (&self, index: usize) -> &Entry { &self.0[index] }
        }
        impl IndexMut<usize> for $ty {
            fn index_mut (&mut self, index: usize) -> &mut Entry { &mut self.0[index] }
        }
    }
}

macro_rules! impl_hierachical_table {
    ($ty: ty) => {
        impl HierarchicalTable for $ty {
            fn entries(&self) -> &[Entry; ENTRY_COUNT] { self.0.entries() }
            fn entries_mut(&mut self) -> &mut [Entry; ENTRY_COUNT] { self.0.entries_mut() }
        }
    };
}

/* ********************************************************************************************** */

/// The page tables set currently in use.
///
/// Used when paging is on.
/// Uses recursive mapping to map the directory for modifying
pub struct ActivePageTables ();

impl I386PageTablesSet for ActivePageTables {
    type PageDirectoryType = ActivePageDirectory;
    fn get_directory<'a>(&'a mut self) -> SmartHierarchicalTable<'a, ActivePageDirectory> {
        assert!(is_paging_on(), "Paging is disabled");
        SmartHierarchicalTable::new(DIRECTORY_RECURSIVE_ADDRESS.addr() as *mut ActivePageDirectory)
    }
}

/// The page directory currently in use.
///
/// Its last entry enables recursive mapping, which we use to access and modify it
pub struct ActivePageDirectory(PageDirectory);
inherit_deref_index!(ActivePageDirectory, PageDirectory);
impl_hierachical_table!(ActivePageDirectory);

impl PageDirectoryTrait for ActivePageDirectory {
    type PageTableType = ActivePageTable;
    type FlusherType = TlbFlush;

    /// Gets a reference to a page table through recursive mapping
    fn get_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, Self::PageTableType>> {
        self.get_table_address(index)
            .map(|addr| SmartHierarchicalTable::new(unsafe { &mut * (addr as *mut _) }))
    }

    /// Allocates a page table, zero it and add an entry to the directory pointing to it
    fn create_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, Self::PageTableType> {
        assert!(self.entries()[index].is_unused());
        let table_frame = FrameAllocator::alloc_frame();

        self.map_nth_entry::<Self::FlusherType>(index, table_frame, I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE);

        // Now that table is mapped in page directory we can write to it through recursive mapping
        let mut table= self.get_table(index).unwrap();
        table.zero();
        table
    }
}

impl ActivePageDirectory {
    /// reduce recursive mapping by one time to get further down in table hierarchy
    fn get_table_address(&self, index: usize) -> PageState<usize> {
        let entry_flags = self[index].flags();
        if entry_flags.contains(I386EntryFlags::PRESENT) {
            let table_address = self as *const _ as usize;
            PageState::Present((table_address << 10) | (index << 12))
        } else if entry_flags.contains(I386EntryFlags::GUARD_PAGE) {
            PageState::Guarded
        } else {
            PageState::Available
        }
    }
}

/// A page table currently in use.
pub struct ActivePageTable(PageTable);
inherit_deref_index!(ActivePageTable, PageTable);
impl_hierachical_table!(ActivePageTable);

impl PageTableTrait for ActivePageTable { type FlusherType = TlbFlush; }

/* ********************************************************************************************** */

/// This is just a wrapper for a pointer to a Table or a Directory.
/// It enables us to do handle when it is dropped
pub struct SmartHierarchicalTable<'a, T: HierarchicalTable>(*mut T, PhantomData<&'a ()>);

impl<'a, T: HierarchicalTable> SmartHierarchicalTable<'a, T> {
    fn new(inner: *mut T) -> SmartHierarchicalTable<'a, T> {
        SmartHierarchicalTable(inner, PhantomData)
    }
}

impl<'a, T: HierarchicalTable> Deref for SmartHierarchicalTable<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe {
            self.0.as_ref().unwrap()
        }
    }
}

impl<'a, T: HierarchicalTable> DerefMut for SmartHierarchicalTable<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe {
            self.0.as_mut().unwrap()
        }
    }
}

impl<'a, T: HierarchicalTable> Drop for SmartHierarchicalTable<'a, T> {
    fn drop(&mut self) {
        unsafe {
            ::core::ptr::drop_in_place(self.0);
        }
    }
}

/// A set of PageTables that are not the ones currently in use.
/// We can't use recursive mapping to modify them, so instead we have to temporarily
/// map the directory and tables to make changes to them.
pub struct InactivePageTables {
    // The address we must put in cr3 to switch to these pages
    directory_physical_address: Frame,
}

impl I386PageTablesSet for InactivePageTables {
    type PageDirectoryType = InactivePageDirectory;

    /// Temporary map the directory
    fn get_directory<'a>(&'a mut self) -> SmartHierarchicalTable<'a, InactivePageDirectory> {
        let frame = Frame::from_physical_addr(self.directory_physical_address.address());
        let mut active_pages = ACTIVE_PAGE_TABLES.lock();
        let va = active_pages.map_frame::<KernelLand>(frame, EntryFlags::WRITABLE);
        SmartHierarchicalTable::new(va.addr() as *mut InactivePageDirectory)
    }
}

impl InactivePageTables {
    /// Creates a new set of inactive page tables
    pub fn new() -> InactivePageTables {
        let mut directory_frame = FrameAllocator::alloc_frame();
        let mut directory_frame_dup = Frame::from_physical_addr(directory_frame.address());
        let mut pageset = InactivePageTables {
            directory_physical_address: directory_frame
        };
        {
            let mut dir = pageset.get_directory();
            dir.zero();
            dir.map_nth_entry::<NoFlush>(ENTRY_COUNT - 1, directory_frame_dup, I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE);
        };
        pageset
    }

    /// Switch to this page tables set.
    /// Returns the old active page tables set after the switch
    ///
    /// Since all process are supposed to have the same view of kernelspace,
    /// this function will copy the part of the active directory that is mapping kernel space tables
    /// to the directory being switched to, and then performs the switch
    ///
    /// # Safety
    ///
    /// All reference to userspace memory will be invalidated
    ///
    /// The frame *must* have been alocated from the frame allocator.
    pub unsafe fn switch_to(mut self) -> InactivePageTables {
        // Copy the kernel space tables
        self.get_directory().copy_active_kernelspace();
        let old_pages = super::swap_cr3(self.directory_physical_address.address());
        ::core::mem::forget(self.directory_physical_address);
        InactivePageTables { directory_physical_address: Frame::from_allocated_addr(old_pages) }
    }

    /// * Frees the userspace pages mapped by this set.
    /// * Frees the userspace tables frames.
    /// * Frees directory's frame.
    ///
    /// Does not free pages mapped in kernelspace and kernel space tables
    pub fn delete(mut self) {
        self.get_directory().delete_userspace();
        // Self goes out of scope, so directory frame gets unallocated
    }
}

/// A temporary mapped page directory.
pub struct InactivePageDirectory(PageDirectory);
inherit_deref_index!(InactivePageDirectory, PageDirectory);
impl_hierachical_table!(InactivePageDirectory);

/// A temporary mapped page table.
pub struct InactivePageTable(PageTable);
inherit_deref_index!(InactivePageTable, PageTable);
impl_hierachical_table!(InactivePageTable);


impl PageDirectoryTrait for InactivePageDirectory {
    type PageTableType = InactivePageTable;
    type FlusherType = NoFlush;

    /// Temporary map the table
    fn get_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, Self::PageTableType>> {
        self.entries()[index].pointed_frame().map(|frame| {
            let mut active_pages = ACTIVE_PAGE_TABLES.lock();
            // TODO: Is this valid ? We're "borrowing" the frame here, but nothing guarantees it
            // might not get freed.
            let va = active_pages.map_frame::<KernelLand>(Frame::from_physical_addr(frame), EntryFlags::WRITABLE);
            SmartHierarchicalTable::new(unsafe {va.addr() as *mut InactivePageTable})
        })
    }

    /// Allocates a page table, temporarily map it,
    /// zero it and add an entry to the directory pointing to it
    fn create_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, Self::PageTableType> {
        assert!(self.entries()[index].is_unused());
        let mut table_frame = FrameAllocator::alloc_frame();
        let mut active_pages = ACTIVE_PAGE_TABLES.lock();

        // TODO: Fix this.
        let dup = Frame::from_physical_addr(table_frame.address());
        let va = active_pages.map_frame::<KernelLand>(dup, EntryFlags::WRITABLE);
        let mut mapped_table = SmartHierarchicalTable::new(unsafe {va.addr() as *mut InactivePageTable});
        mapped_table.zero();

        self.map_nth_entry::<Self::FlusherType>(index, table_frame, I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE);

        mapped_table
    }
}

impl InactivePageDirectory {
    /// * Frees the userspace pages mapped by this set
    /// * Frees the userspace tables frames
    ///
    /// Does not free pages mapped in kernelspace and kernel space tables
    fn delete_userspace(&mut self) {
        for table_index in UserLand::start_table()..UserLand::end_table() {
            if let PageState::Present(mut table) = self.get_table(table_index) {
                // Free all pages
                table.free_all_frames();
            }
            // Zero the directory entry, frees the frame.
            self.entries_mut()[table_index].set_unused();
        }
    }

    /// Copies all the entries in the directory mapping tables that fall in kernelspace
    /// from active page tables
    fn copy_active_kernelspace(&mut self) {
        let mut lock = ACTIVE_PAGE_TABLES.lock();
        let mut active_dir = lock.get_directory();
        for table in KernelLand::start_table()..=KernelLand::end_table() {
            self.entries_mut()[table] = active_dir.entries_mut()[table];
        }
    }
}

impl PageTableTrait for InactivePageTable { type FlusherType = NoFlush; }

impl InactivePageTable {
    /// Frees all pages mapped by this table, and mark the frames as deallocated
    fn free_all_frames(&mut self) {
        for entry in self.entries_mut().iter_mut() {
            entry.set_unused();
        }
    }
}

/// When the temporary inactive directory is drop, we unmap it
impl Drop for InactivePageDirectory {
    fn drop(&mut self) {
        let mut active_pages = ACTIVE_PAGE_TABLES.lock();
        active_pages.unmap(VirtualAddress(self as *mut _ as usize));
    }
}

/// When the temporary inactive table is drop, we unmap it
impl Drop for InactivePageTable {
    fn drop(&mut self) {
        let mut active_pages = ACTIVE_PAGE_TABLES.lock();
        active_pages.unmap(VirtualAddress(self as *mut _ as usize));
    }
}

/* ********************************************************************************************** */

/// Used at startup when paging is off to create and initialized the first page tables
///
/// # Safety
///
/// Manipulating this pages set must only be done when paging is off
pub struct PagingOffPageSet {
    // The address we must put in cr3 to switch to these pages
    // TODO: This should be a frame.
    pub directory_physical_address: Frame,
}

impl I386PageTablesSet for PagingOffPageSet {
    type PageDirectoryType = PagingOffDirectory;
    fn get_directory<'a>(&'a mut self) -> SmartHierarchicalTable<'a, <Self as I386PageTablesSet>::PageDirectoryType> {
        SmartHierarchicalTable::new(self.directory_physical_address.address().addr() as *mut PagingOffDirectory)
    }
}

impl PagingOffPageSet {
    /// Used at startup when the paging is disabled and creating the first page tables.
    ///
    /// # Safety
    ///
    /// Paging **must** be disabled when calling this function.
    pub unsafe fn paging_off_create_page_set() -> Self {
        // Creates a frame and leak it.
        let dir = FrameAllocator::alloc_frame();

        let dir_addr = dir.address().addr() as *mut PagingOffDirectory;
        (*dir_addr).init_directory();
        Self { directory_physical_address : dir }
    }

    /// Enables paging with this tables as active tables
    ///
    /// # Safety
    ///
    /// Paging **must** be disabled when calling this function.
    pub unsafe fn enable_paging(self) {
        enable_paging(self.directory_physical_address.address());
        ::core::mem::forget(self.directory_physical_address);
    }
}

/// A directory we can modify by directly accessing physical memory because paging is off
pub struct PagingOffDirectory(PageDirectory);
inherit_deref_index!(PagingOffDirectory, PageDirectory);
impl_hierachical_table!(PagingOffDirectory);

impl PageDirectoryTrait for PagingOffDirectory {
    type PageTableType = PagingOffTable;
    type FlusherType = NoFlush;

    /// Simply cast pointed frame as PageTable
    fn get_table<'a>(&'a mut self, index: usize) -> PageState<SmartHierarchicalTable<'a, Self::PageTableType>> {
        self.entries()[index].pointed_frame().map(|addr| {
            SmartHierarchicalTable::new(unsafe {(addr.addr() as *mut PagingOffTable)})
        })
    }
    /// Allocates a page table, zero it and add an entry to the directory pointing to it
    fn create_table<'a>(&'a mut self, index: usize) -> SmartHierarchicalTable<'a, Self::PageTableType> {
        let mut frame = FrameAllocator::alloc_frame();
        let mut table = SmartHierarchicalTable::new(
            unsafe {(frame.address().addr() as *mut PagingOffTable)}
        );
        table.zero();
        self.map_nth_entry::<Self::FlusherType>(index, frame, I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE);
        table
    }
}

impl PagingOffDirectory {
    /// Initializes the directory.
    /// This function does two things:
    ///
    /// * zero out the whole directory
    /// * make its last entry point to itself to enable recursive mapping
    ///
    /// # Safety
    ///
    /// Paging **must** be disabled when calling this function.
    unsafe fn init_directory(&mut self) {
        self.zero();
        let self_frame = Frame::from_physical_addr(PhysicalAddress(self as *mut _ as usize));
        // Make last entry of the directory point to the directory itself
        self.entries_mut()[ENTRY_COUNT - 1].set(self_frame, I386EntryFlags::PRESENT | I386EntryFlags::WRITABLE);
    }
}

/// A table we can modify by directly accessing physical memory because paging is off
pub struct PagingOffTable(PageTable);
inherit_deref_index!(PagingOffTable, PageTable);
impl_hierachical_table!(PagingOffTable);

impl PageTableTrait for PagingOffTable { type FlusherType = NoFlush; }

/* ********************************************************************************************** */

/// A trait used to decide if the TLB cache should be flushed or not
pub trait Flusher {
    fn flush_cache() {}
}

/// When passing this struct the TLB will be flushed. Used by ActivePageTables
pub struct TlbFlush;
impl Flusher for TlbFlush { fn flush_cache() { flush_tlb(); } }

/// When passing this struct the TLB will **not** be flushed. Used by Inactive/PagingOff page tables
pub struct NoFlush;
impl Flusher for NoFlush { fn flush_cache() { } }
