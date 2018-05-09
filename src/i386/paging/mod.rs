///! # Paging on i386

mod table;

use self::table::{PageDirectory, DIRECTORY_RECURSIVE_ADDRESS};
use self::table::entry::Entry;

pub const PAGE_SIZE: usize = 4096;

const ENTRY_COUNT: usize = PAGE_SIZE / ::core::mem::size_of::<Entry>();

pub type PhysicalAddress = usize;
pub type VirtualAddress = usize;

/// The page directory currently in use.
/// This struct is used to manage rust ownership.
/// Used when paging is already on (recursive mapping of the directory)
pub struct ActivePageTable {
    dir: *mut PageDirectory,
}

impl ActivePageTable {
    pub unsafe fn new() -> ActivePageTable {
        ActivePageTable { dir: DIRECTORY_RECURSIVE_ADDRESS }
    }

    fn directory(&self) -> &PageDirectory {
        unsafe { &*self.dir }
    }

    fn directory_mut(&mut self) -> &mut PageDirectory {
        unsafe { &mut *self.dir }
    }
}

unsafe fn enable_paging(page_directory_address: usize) {
    asm!("mov eax, $0
          mov cr3, eax

          mov eax, cr0
          or eax, 0x80000001
          mov cr0, eax          "

            :
            : "r" (page_directory_address)
            : "eax"
            : "intel", "volatile");
}

/// Used at startup to create the page tables and mapping the kernel
pub unsafe fn init_paging() {
   let dir = PageDirectory::paging_off_create_directory();
   enable_paging(dir as *const _ as usize)
}
