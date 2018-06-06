///! # Paging on i386

mod entry;
mod table;

use multiboot2::{BootInformation, ElfSectionFlags};

pub use self::table::{ActivePageTables, InactivePageTables};
pub use self::table::PageTablesSet;
pub use self::table::entry::EntryFlags;

use self::table::*;
use self::table::entry::Entry;
pub use frame_alloc::{round_to_page, round_to_page_upper};
use spin::Mutex;
use frame_alloc::Frame;
use ::print::{Printer, VGA_SCREEN_ADDRESS, VGA_SCREEN_MEMORY_SIZE};
use ::core::fmt::Write;

pub const PAGE_SIZE: usize = 4096;

const ENTRY_COUNT: usize = PAGE_SIZE / ::core::mem::size_of::<Entry>();

pub type PhysicalAddress = usize;
pub type VirtualAddress = usize;

pub static ACTIVE_PAGE_TABLES: Mutex<ActivePageTables> = Mutex::new(ActivePageTables());

unsafe fn enable_paging(page_directory_address: usize) {
    asm!("mov eax, $0
          mov cr3, eax

          mov eax, cr0
          or eax, 0x80000001
          mov cr0, eax          "

            :
            : "r" (page_directory_address)
            : "eax", "memory"
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

/// Changes the content of the cr3 register, and returns the value before the change was made
fn swap_cr3(page_directory_address: PhysicalAddress) -> PhysicalAddress {
    let old_value: PhysicalAddress;
    unsafe {
        asm!("mov $0, cr3
              mov cr3, $1"
              : "=&r"(old_value)
              : "r"(page_directory_address)
              : "memory"
              : "intel", "volatile");
    }
    old_value
}

/// Creates an InactivePageTables set mapping the kernel sections with correct rights,
/// and makes it active
pub unsafe fn remap_kernel(boot_info : &BootInformation) {
    let mut new_pages = InactivePageTables::new();

    // Map the elf sections
    let elf_sections_tag = boot_info.elf_sections_tag()
        .expect("GRUB, you're drunk. Give us our elf_sections_tag.");
    for section in elf_sections_tag.sections() {
        if !section.is_allocated() {
            continue; // section is not loaded to memory
        }
        assert_eq!(section.start_address() as usize % PAGE_SIZE, 0, "sections must be page aligned");

        let mut map_flags = EntryFlags::PRESENT;
        if section.flags().contains(ElfSectionFlags::WRITABLE) {
            map_flags |= EntryFlags::WRITABLE
        }

        new_pages.identity_map_region(section.start_address() as PhysicalAddress,
                                      section.size() as usize,
                                      map_flags);
    }

    // Map the vga screen memory
    new_pages.identity_map_region(VGA_SCREEN_ADDRESS, VGA_SCREEN_MEMORY_SIZE,
                                  EntryFlags::PRESENT | EntryFlags::WRITABLE);

    // Reserve the very first frame for null pointers
    new_pages.identity_map(Frame::from_physical_addr(0), EntryFlags::GUARD_PAGE);

    // Switch to the new tables set
    let old_pages = new_pages.switch_to();

    // Delete the page tables and directory of previous set
    old_pages.delete();

    // TODO do something for the stack
}

/// Used at startup to create the page tables and mapping the kernel
pub unsafe fn init_paging() {
    let tables = PagingOffPageSet::paging_off_create_page_set();
    enable_paging(tables.directory_physical_address)
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

pub fn get_page<Land: VirtualSpaceLand>() -> VirtualAddress {
    ACTIVE_PAGE_TABLES.lock().get_page::<Land>(table::entry::EntryFlags::PRESENT | table::entry::EntryFlags::WRITABLE)
}
