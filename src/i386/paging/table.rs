///! # Page table / directory

use core::ops::{Index, IndexMut};

// Yeah, I'm ugly. Screw you.
#[path = "entry.rs"]
pub mod entry;

use self::entry::{EntryFlags, Entry};
use super::{PAGE_SIZE, ENTRY_COUNT, PhysicalAddress, VirtualAddress, flush_tlb, VirtualSpaceLand};
use ::frame_alloc::{Frame, FrameAllocator, MEMORY_FRAME_SIZE};

/// A page table
pub struct PageTable {
    entries: [Entry; ENTRY_COUNT]
}

/// The page directory
pub struct PageDirectory(PageTable);

// Assertions
fn __assertions() {
    const_assert!(::core::mem::size_of::<PageDirectory>() >= MEMORY_FRAME_SIZE);
    const_assert!(::core::mem::size_of::<PageTable>() >= MEMORY_FRAME_SIZE);
    const_assert!(::core::mem::size_of::<PageTable>() == ::core::mem::size_of::<PageDirectory>());
}

/// When paging is on, accessing this address loops back to the directory itself thanks to
/// recursive mapping on directory's last entry
pub const DIRECTORY_RECURSIVE_ADDRESS: *mut PageDirectory = 0xffff_f000 as *mut _;

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
trait HierarchicalTable {

    fn entries(&self) -> &[Entry; ENTRY_COUNT];
    fn entries_mut(&mut self) -> &mut [Entry; ENTRY_COUNT];

    /// zero out the whole table
    fn zero(&mut self) {
        for entry in self.entries_mut().iter_mut() {
            entry.set_unused();
        }
    }

    /// Creates a mapping on the nth entry of a table
    fn map_nth_entry(&mut self, entry: usize, frame: Frame, flags: EntryFlags) {
        self.entries_mut()[entry].set(frame, flags);
        flush_tlb();
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

impl PageTable {
    /// Used at startup when creating the first page tables.
    fn map_whole_table(&mut self, start_address: PhysicalAddress, flags: EntryFlags) {
        let mut addr = start_address;
        for entry in &mut self.entries[..] {
            entry.set(Frame { physical_addr: addr }, flags);
            addr += PAGE_SIZE;
        }
    }
}

impl PageDirectory {
    /// reduce recursive mapping by one time to get further down in table hierarchy
    fn get_table_address(&self, index: usize) -> Option<usize> {
        let entry_flags = self[index].flags();
        if entry_flags.contains(EntryFlags::PRESENT) {
            let table_address = self as *const _ as usize;
            Some((table_address << 10) | (index << 12))
        }
        else {
            None
        }
    }

    /// Gets a reference to a page table through recursive mapping
    pub fn get_table(&self, index: usize) -> Option<&PageTable> {
        self.get_table_address(index)
            .map(|addr| unsafe { &*(addr as *const _) })
    }

    /// Gets a reference to a page table through recursive mapping
    pub fn get_table_mut(&mut self, index: usize) -> Option<&mut PageTable> {
        self.get_table_address(index)
            .map(|addr| unsafe { &mut *(addr as *mut _) })
    }

    /// Allocates a page table, zero it and add an entry to the directory pointing to it
    fn create_table(&mut self, index: usize) -> &mut PageTable {
        assert!(self.entries()[index].is_unused());
        let table_frame = FrameAllocator::alloc_frame();

        self.map_nth_entry(index, table_frame, EntryFlags::PRESENT | EntryFlags::WRITABLE);

        // Now that table is mapped in page directory we can write to it through recursive mapping
        let table= self.get_table_mut(index).unwrap();
        table.zero();
        table
    }

    /// Gets the page table at given index, or creates it if it does not exist
    pub fn get_table_or_create(&mut self, index: usize) -> &mut PageTable {
        if !self.entries()[index].is_unused() {
            self.get_table_mut(index).unwrap()
        } else {
            self.create_table(index)
        }
    }

    /// Creates a mapping in the page tables with the given flags
    pub fn map_to(&mut self, page:    Frame,
                             address: VirtualAddress,
                             flags:   EntryFlags) {
        let table_nbr = address / (ENTRY_COUNT * PAGE_SIZE);
        let table_off = address % (ENTRY_COUNT * PAGE_SIZE) / PAGE_SIZE;
        let table = self.get_table_or_create(table_nbr);
        table.map_nth_entry(table_off, page, flags);
    }

    /// Creates a mapping in the page tables with the given flags.
    /// Allocates the pointed page
    pub fn map_allocate_to(&mut self, address: VirtualAddress,
                                      flags:   EntryFlags) {
        let page = FrameAllocator::alloc_frame();
        self.map_to(page, address, flags);
    }

    /// Creates a mapping in the page tables with the given flags.
    /// Allocates the pointed page and chooses the virtual address.
    pub fn map<Land: VirtualSpaceLand>(&mut self, flags: EntryFlags) -> VirtualAddress {
        let va = self.find_avalaible_virtual_space::<Land>(1).unwrap();
        self.map_allocate_to(va, flags);
        va
    }

    /// Deletes a mapping in the page tables, optionally free the pointed frame
    fn __unmap(&mut self, page: VirtualAddress, free_frame: bool) {
        let table_nbr = page / (ENTRY_COUNT * PAGE_SIZE);
        let table_off = page % (ENTRY_COUNT * PAGE_SIZE);
        let table = self.get_table_mut(table_nbr)
        // TODO: Return an Error if the table was not present
            .unwrap();
        // TODO: Return an Error if the address was not mapped
        let entry= &mut table.entries_mut()[table_off];
        assert_eq!(entry.is_unused(), false);
        if free_frame {
           match entry.pointed_frame() {
               Some(frame_addr) => { FrameAllocator::free_frame(frame_addr as Frame); }
               None => {}
           };
        }
        entry.set_unused();
        flush_tlb();
    }

    /// Deletes a mapping in the page tables
    pub fn unmap(&mut self, page: VirtualAddress) {
       self.__unmap(page, false)
    }

    /// Deletes a mapping in the page tables
    /// Frees the pointed frame
    pub fn unmap_free(&mut self, page: VirtualAddress) {
        self.__unmap(page, true)
    }

    /// Finds a virtual space hole that can contain page_nb consecutive pages
    pub fn find_avalaible_virtual_space<Land: VirtualSpaceLand>(&self, page_nb: usize) -> Option<VirtualAddress> {
        let mut hole_size: usize = 0;
        let mut hole_start_table: usize = 0;
        let mut hole_start_page:  usize = 0;
        let mut counter_curr_table:  usize = Land::start_table();
        let mut counter_curr_page:   usize = 0;
        while counter_curr_table < Land::end_table() && hole_size < page_nb {
            match self.get_table(counter_curr_table) {
                None => { // The whole page table is free, so add it to our hole_size
                    if hole_size == 0 {
                        // This is the start of a hole
                        hole_start_table = counter_curr_table;
                        hole_start_page = counter_curr_page;
                    }
                    hole_size += ENTRY_COUNT;
                    counter_curr_table += 1;
                }
                Some(curr_table) => {
                    counter_curr_page = 0;
                    while counter_curr_page < ENTRY_COUNT && hole_size < page_nb {
                        if curr_table.entries()[counter_curr_page].is_unused() {
                            if hole_size == 0 {
                                // This is the start of a hole
                                hole_start_table = counter_curr_table;
                                hole_start_page = counter_curr_page;
                            }
                            hole_size += 1;
                        } else {
                            // The current hole was not big enough, so reset counter
                            hole_size = 0;
                        }
                        counter_curr_page += 1;
                    }
                }
            }
        };
        if hole_size >= page_nb { // The last tested hole was big enough
            Some(hole_start_table * ENTRY_COUNT * PAGE_SIZE +
                 hole_start_page * PAGE_SIZE
                    as VirtualAddress
            )
        } else { // No hole was big enough
            None
        }
    }

    /// Used at startup when creating the first page tables.
    /// This function does two things :
    ///     * simply allocates one child page table and fills it with identity mappings entries
    ///       therefore identity mapping the first 4Mb of memory
    ///     * makes the last directory entry a recursive mapping
    ///
    /// # Safety
    ///
    /// Paging **must** be disabled when calling this function.
    unsafe fn paging_off_init_page_directory(&mut self) {
        let first_table_frame = FrameAllocator::alloc_frame();
        let first_table = first_table_frame
                .dangerous_as_physical_ptr() as *mut PageTable;

        (*first_table).zero();
        (*first_table).map_whole_table(0x00000000, EntryFlags::PRESENT | EntryFlags::WRITABLE);

        self.zero();
        self.0.entries[0].set(first_table_frame, EntryFlags::PRESENT | EntryFlags::WRITABLE);

        let self_frame = Frame { physical_addr: self as *mut _ as PhysicalAddress };
        // Make last entry of the directory point to the directory itself
        self.0.entries[ENTRY_COUNT - 1].set(self_frame, EntryFlags::PRESENT | EntryFlags::WRITABLE);
    }

    /// Used at startup when the paging is disabled and creating the first page tables.
    ///
    /// # Safety
    ///
    /// Paging **must** be disabled when calling this function.
    pub unsafe fn paging_off_create_directory() -> *mut PageDirectory {
        let dir = FrameAllocator::alloc_frame()
            .dangerous_as_physical_ptr() as *mut PageDirectory;
        (*dir).paging_off_init_page_directory();
        dir
    }
}
