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

/// Flush the Translation Lookaside Buffer [https://wiki.osdev.org/TLB]
fn flush_tlb() {
    unsafe {
        asm!("mov eax, cr3
          mov cr3, eax  "
          :
          :
          : "eax"
          : "intel", "volatile");
    }
}

/// Used at startup to create the page tables and mapping the kernel
pub unsafe fn init_paging() {
   let dir = PageDirectory::paging_off_create_directory();
   enable_paging(dir as *const _ as usize)
}

/// A trait describing the splitting of virtual memory between Kernel and User.
/// Implemented by UserLand and KernelLand
pub trait VirtualSpaceLand {
    fn start_addr() -> VirtualAddress;
    fn end_addr() -> VirtualAddress;

    /// The index in page directory of the first table of this land
    fn start_table() -> usize {
        Self::start_addr() / (PAGE_SIZE * ENTRY_COUNT) as usize
    }

    /// The index in page directory of the last table of this land
    fn end_table() -> usize {
        Self::end_addr() / (PAGE_SIZE * ENTRY_COUNT) as usize
    }
}

pub enum KernelLand {}
pub enum UserLand   {}

impl KernelLand {
    const fn start_addr() -> VirtualAddress { 0x00000000 }
    const fn end_addr()   -> VirtualAddress { 0x3fffffff }
}
impl UserLand {
    const fn start_addr() -> VirtualAddress { 0x40000000 }
    const fn end_addr()   -> VirtualAddress { 0xffffffff }
}

impl VirtualSpaceLand for KernelLand {
    fn start_addr() -> VirtualAddress { Self::start_addr() }
    fn end_addr()   -> VirtualAddress { Self::end_addr() }
}
impl VirtualSpaceLand for UserLand {
    fn start_addr() -> VirtualAddress { Self::start_addr() }
    fn end_addr()   -> VirtualAddress { Self::end_addr() }
}

// Assertions to check that Kernel/User pages falls on distinct page tables
// and also that they do not overlap
fn __land_assertions() {
    const_assert!(KernelLand::start_addr() < KernelLand::end_addr());
    const_assert!(UserLand::start_addr() < UserLand::end_addr());
    // TODO: Const FN sucks! Check that the kernelland and userland don't overlap.
    //const_assert!(::core::cmp::max(KernelLand::start_addr(), UserLand::start_addr()) >=
    //              ::core::cmp::min(KernelLand::end_addr(),   UserLand::end_addr()));

    const_assert!(KernelLand::start_addr() % (ENTRY_COUNT * PAGE_SIZE) == 0);
    const_assert!(UserLand::start_addr()   % (ENTRY_COUNT * PAGE_SIZE) == 0);
}

// TODO make this a lot safer
pub fn get_page<Land: VirtualSpaceLand>() -> VirtualAddress {
    let mut apt = unsafe { ActivePageTable::new() };
    apt.directory_mut().map::<Land>(table::entry::EntryFlags::PRESENT | table::entry::EntryFlags::WRITABLE)
}
