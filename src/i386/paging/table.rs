///! # Page table / directory

use core::ops::{Index, IndexMut};

// Yeah, I'm ugly. Screw you.
#[path = "entry.rs"]
pub mod entry;

use self::entry::{EntryFlags, Entry};
use super::{PAGE_SIZE, ENTRY_COUNT, PhysicalAddress};
use ::frame_alloc::{FrameAllocator, MEMORY_FRAME_SIZE};

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
    fn map_whole_table(&mut self, mut start_address: PhysicalAddress, flags: EntryFlags) {
        for entry in &mut self.entries[..] {
            entry.set(start_address, flags);
            start_address += PAGE_SIZE;
        }
    }
}

impl PageDirectory {
    /// reduce recursive mapping by one time to get further down in table hierarchy
    fn get_table_address(&self, index: usize) -> Option<usize> {
        let entry_flags = self[index].flags();
        if entry_flags.contains(EntryFlags::PRESENT) {
            let table_address = self as *const _ as usize;
            Some((table_address << 9) | (index << 12))
        }
        else {
            None
        }
    }

    pub fn get_table(&self, index: usize) -> Option<&PageTable> {
        self.get_table_address(index)
            .map(|addr| unsafe { &*(addr as *const _) })
    }

    pub fn get_table_mut(&mut self, index: usize) -> Option<&mut PageTable> {
        self.get_table_address(index)
            .map(|addr| unsafe { &mut *(addr as *mut _) })
    }

    /// Used at startup when creating the first page tables.
    /// This function does two things :
    ///     * simply allocates one child page table and fills it with identity mappings
    ///       therefore identity mapping the first 2Mb of memory
    ///     * makes the last directory entry a recursive mapping
    unsafe fn paging_off_init_page_directory(&mut self) {
        let first_table = FrameAllocator::alloc_frame()
                .dangerous_as_physical_ptr() as *mut PageTable;

        (*first_table).map_whole_table(0x00000000, EntryFlags::PRESENT | EntryFlags::WRITABLE);

        self.zero();
        self.0.entries[0].set(first_table as PhysicalAddress, EntryFlags::PRESENT | EntryFlags::WRITABLE);

        let self_addr = self as *mut _ as PhysicalAddress;
        // Make last entry of the directory point to the directory itself
        self.0.entries[ENTRY_COUNT - 1].set(self_addr, EntryFlags::PRESENT | EntryFlags::WRITABLE);
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
