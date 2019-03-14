//! Paging on i386

mod entry;
mod table;

use multiboot2::{BootInformation, ElfSectionFlags};
use crate::address::{PhysicalAddress, VirtualAddress};
use crate::frame_alloc::{round_to_page, round_to_page_upper};

pub use self::table::{ActivePageTables, InactivePageTables, PagingOffPageSet, MappingType, EntryFlags};
pub use self::table::PageTablesSet;

use self::table::entry::Entry;
use spin::Mutex;
use core::fmt::Write;
use crate::bootstrap_logging::Serial;

/// The size of a single page.
pub const PAGE_SIZE: usize = 4096;

const ENTRY_COUNT: usize = PAGE_SIZE / ::core::mem::size_of::<Entry>();

/// Currently active page tables.
pub static ACTIVE_PAGE_TABLES: Mutex<ActivePageTables> = Mutex::new(ActivePageTables());

/// Check if the paging is currently active.
///
/// This is done by checking if we're in protected mode and if paging is
/// enabled.
fn is_paging_on() -> bool {
    let cr0: usize;
    unsafe {
        // Safety: this is just getting the CR0 register
        asm!("mov $0, cr0" : "=r"(cr0) ::: "intel" );
    }
    cr0 & 0x80000001 == 0x80000001 // PE | PG
}

unsafe fn enable_paging(page_directory_address: PhysicalAddress) {
    #[cfg(not(test))]
    asm!("mov eax, $0
          mov cr3, eax

          mov eax, cr0
          or eax, 0x80010001
          mov cr0, eax          "

            :
            : "r" (page_directory_address.addr())
            : "eax", "memory"
            : "intel", "volatile");
}

/// Flush the Translation Lookaside Buffer [https://wiki.osdev.org/TLB]
fn flush_tlb() {
    #[cfg(not(test))]
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

/// Creates a set of page tables identity mapping the Bootstrap.
///
/// Returns the newly created PageTable.
///
/// # Safety
///
/// Paging must be off to call this function
pub unsafe fn map_bootstrap(boot_info : &BootInformation) -> PagingOffPageSet {
    let mut new_pages = PagingOffPageSet::paging_off_create_page_set();

    // Reserve the very first frame for null pointers
    new_pages.map_page_guard(VirtualAddress(0x00000000));

    // Page guard the first frame of the kernel.
    new_pages.map_page_guard(VirtualAddress(0xc0000000));

    let _ = writeln!(Serial, "= Mapping the Bootstrap");
    let elf_sections_tag = boot_info.elf_sections_tag()
        .expect("GRUB, you're drunk. Give us our elf_sections_tag.");
    for section in elf_sections_tag.sections() {
        //writeln!(Serial, "= Found section {} at {:#010x} size {:#010x}", section.name(), section.start_address(), section.size());

        if !section.is_allocated() || section.name() == ".boot" || section.size() == 0 {
            continue; // section is not loaded to memory
        }

        assert_eq!(section.start_address() as usize % PAGE_SIZE, 0, "sections must be page aligned");

        let mut map_flags = EntryFlags::empty();
        if section.flags().contains(ElfSectionFlags::WRITABLE) {
            map_flags |= EntryFlags::WRITABLE
        }

        let from = section.start_address() as usize;
        let to = from + kfs_libutils::align_up(section.size() as usize, PAGE_SIZE);
        let _ = writeln!(Serial, "= Identity mapping {:#010x}-{:#010x}", from, to);

        new_pages.identity_map_region(PhysicalAddress(section.start_address() as usize),
                                      section.size() as usize,
                                      map_flags);
    }
    new_pages
}

/// A trait describing the splitting of virtual memory between Kernel and User.
/// Implemented by UserLand and KernelLand
pub trait VirtualSpaceLand {
    /// The first address in this land.
    fn start_addr() -> VirtualAddress;

    /// The last address in this land.
    fn end_addr() -> VirtualAddress;

    /// The index in page directory of the first table of this land
    fn start_table() -> usize {
        Self::start_addr().addr() / (PAGE_SIZE * ENTRY_COUNT) as usize
    }

    /// The index in page directory of the last table of this land
    fn end_table() -> usize {
        Self::end_addr().addr() / (PAGE_SIZE * ENTRY_COUNT) as usize
    }
}

/// The virtual memory belonging to kernel.
pub struct  KernelLand;
/// The virtual memory belonging to user.
pub struct UserLand;

impl KernelLand {
    const fn start_addr() -> VirtualAddress { VirtualAddress(0xc0000000) }
    const fn end_addr()   -> VirtualAddress { VirtualAddress(0xffffffff) }
}
impl UserLand {
    const fn start_addr() -> VirtualAddress { VirtualAddress(0x00000000) }
    const fn end_addr()   -> VirtualAddress { VirtualAddress(0xbfffffff) }
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
const_assert!(KernelLand::start_addr().0 < KernelLand::end_addr().0);
const_assert!(UserLand::start_addr().0 < UserLand::end_addr().0);
// TODO: Const FN sucks! Check that the kernelland and userland don't overlap.
//const_assert!(::core::cmp::max(KernelLand::start_addr(), UserLand::start_addr()) >=
//              ::core::cmp::min(KernelLand::end_addr(),   UserLand::end_addr()));

const_assert!(KernelLand::start_addr().0 % (ENTRY_COUNT * PAGE_SIZE) == 0);
const_assert!(UserLand::start_addr().0   % (ENTRY_COUNT * PAGE_SIZE) == 0);

/// Creates a mapping in the page tables with the given flags.
/// Allocates the pointed page and chooses the virtual address.
///
/// # Panics
///
/// Panics if we are out of memory.
pub fn get_page<Land: VirtualSpaceLand>() -> VirtualAddress {
    ACTIVE_PAGE_TABLES.lock().get_page::<Land>()
}
