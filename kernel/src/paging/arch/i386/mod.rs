//! Paging implementation on i386
//!
//! No PAE, no PSE, just regular 2-level paging, with simple 4kB tables and pages.

pub mod entry;
pub mod table;
pub mod lands;

use core::arch::asm;

use crate::mem::{VirtualAddress, PhysicalAddress};

/// The page size. Dictated by the MMU.
/// In simple, elegant, sane i386 paging, a page is 4kB.
pub const PAGE_SIZE: usize = 4096;

/// The number of entries a page table has.
/// On i386 a page table/directory is 1024 entries * 4 bytes per entry = 4kB, fits in 1 page.
pub const ENTRY_COUNT: usize = PAGE_SIZE / ::core::mem::size_of::<entry::I386Entry>();

//pub static mut ACTIVE_PAGE_TABLES: ActiveHierarchy = ActiveHierarchy;

/// Check if the paging is currently active.
///
/// This is done by checking if we're in protected mode and if paging is
/// enabled.
pub fn is_paging_on() -> bool {
    let cr0: usize;
    unsafe {
        // Safety: this is just getting the CR0 register
        asm!("mov {}, cr0", out(reg) cr0);
    }
    cr0 & 0x80000001 == 0x80000001 // PE | PG
}

/// Not used anymore, bootstrap's job
pub unsafe fn enable_paging(page_directory_address: PhysicalAddress) {
    asm!("mov eax, {}
          mov cr3, eax

          mov eax, cr0
          or eax, 0x80010001
          mov cr0, eax",

          in(reg) page_directory_address.addr(),
          out("eax") _);
}

/// Flush the Translation Lookaside Buffer [https://wiki.osdev.org/TLB]
fn flush_tlb() {
    #[cfg(not(test))]
    unsafe {
        asm!("mov eax, cr3
          mov cr3, eax",
          out("eax") _);
    }
}

/// Changes the content of the cr3 register, and returns the value before the change was made
fn swap_cr3(page_directory_address: PhysicalAddress) -> PhysicalAddress {
    let old_value: usize;
    unsafe {
        asm!("mov {}, cr3
              mov cr3, {}",
              out(reg) old_value,
              in(reg) page_directory_address.0);
    }
    PhysicalAddress(old_value)
}

/// Reads the value of cr3, retrieving the current page directory's physical address
pub fn read_cr3() -> PhysicalAddress {
    let cr3_value: usize;
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3_value);
    }
    PhysicalAddress(cr3_value)
}

/// Reads the value of cr2, retrieving the address that caused a page fault
pub fn read_cr2() -> VirtualAddress {
    let cr2_value: usize;
    unsafe {
        asm!("mov {}, cr2", out(reg) cr2_value);
    }
    VirtualAddress(cr2_value)
}
