//! Paging implementation on i386

pub mod entry;
pub mod table;

use self::table::{ActiveHierarchy, InactiveHierarchy};

use mem::{VirtualAddress, PhysicalAddress};

pub const PAGE_SIZE: usize = 4096;

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
        asm!("mov $0, cr0" : "=r"(cr0) ::: "intel" );
    }
    cr0 & 0x80000001 == 0x80000001 // PE | PG
}

/// Not used anymore, bootstrap's job
pub unsafe fn enable_paging(page_directory_address: PhysicalAddress) {
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

/// Reads the value of cr3, retrieving the current page directory's physical address
pub fn read_cr3() -> PhysicalAddress {
    let cr3_value: usize;
    unsafe {
        asm!( "mov $0, cr3" : "=r"(cr3_value) : : : "intel", "volatile");
    }
    PhysicalAddress(cr3_value)
}

/// Reads the value of cr2, retrieving the address that caused a page fault
pub fn read_cr2() -> VirtualAddress {
    let cr2_value : usize;
    unsafe {
        asm!( "mov $0, cr2" : "=r"(cr2_value) : : : "intel", "volatile");
    }
    VirtualAddress(cr2_value)
}
