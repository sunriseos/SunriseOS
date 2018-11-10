//! i386 page table entry

use mem::PhysicalAddress;
use core::fmt::{Debug, Formatter, Error};
use super::super::super::hierarchical_table::{HierarchicalEntry, PageState};
use super::super::super::MappingFlags;

bitflags! {
    /// The flags of a table entry
    pub struct I386EntryFlags: u32 {
        const PRESENT =         1 << 0;
        const WRITABLE =        1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH =   1 << 3;
        const NO_CACHE =        1 << 4;
        const ACCESSED =        1 << 5;
        const DIRTY =           1 << 6;
        const HUGE_PAGE =       1 << 7;
        const GLOBAL =          1 << 8;
        const GUARD_PAGE =      1 << 9;     // user_defined_1
        const USER_DEFINED_2 =  1 << 10;    // user_defined_2
        const USER_DEFINED_3 =  1 << 11;    // user_defined_3
    }
}

impl From<MappingFlags> for I386EntryFlags {
    fn from(flags: MappingFlags) -> I386EntryFlags {
        let mut newflags = I386EntryFlags::PRESENT;
        if flags.contains(MappingFlags::WRITABLE) {
            newflags |= I386EntryFlags::WRITABLE;
        }
        newflags
    }
}

const ENTRY_PHYS_ADDRESS_MASK: usize = 0xffff_f000;

/// An entry in a page table or page directory. An unused entry is 0
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct I386Entry(u32);

impl Debug for I386Entry {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.debug_struct("Entry")
            .field("flags", &self.flags())
            .field("frame", &self.pointed_frame().as_option())
            .finish()
    }
}

impl HierarchicalEntry for I386Entry {
    type EntryFlagsType = I386EntryFlags;

    /// Is the entry unused ?
    fn is_unused(&self) -> bool { self.0 == 0 }

    /// Clear the entry
    fn set_unused(&mut self) -> PageState<PhysicalAddress> {
        let ret = self.pointed_frame();
        self.0 = 0;
        ret
    }

    /// Is the entry a page guard ?
    fn is_guard(&self) -> bool { self.flags().contains(I386EntryFlags::GUARD_PAGE) }

    /// Get the current entry flags
    fn flags(&self) -> I386EntryFlags { I386EntryFlags::from_bits_truncate(self.0) }

    /// Get the associated physical address, if available
    fn pointed_frame(&self) -> PageState<PhysicalAddress> {
        if self.flags().contains(I386EntryFlags::PRESENT) {
            let frame_phys_addr = self.0 as usize & ENTRY_PHYS_ADDRESS_MASK;
            PageState::Present(PhysicalAddress(frame_phys_addr))
        } else if self.flags().contains(I386EntryFlags::GUARD_PAGE) {
            PageState::Guarded
        } else {
            PageState::Available
        }
    }

    /// Sets the entry
    fn set(&mut self, frame_phys_addr: PhysicalAddress, mut flags: I386EntryFlags) {
        assert_eq!(flags.contains(I386EntryFlags::PRESENT)
                && flags.contains(I386EntryFlags::GUARD_PAGE), false,
                "a GUARD_PAGE cannot also be PRESENT");
        assert_eq!(frame_phys_addr.addr() & !ENTRY_PHYS_ADDRESS_MASK, 0);

        self.0 = (frame_phys_addr.addr() as u32) | flags.bits();
    }

    /// Make this entry a page guard
    fn set_guard(&mut self) {
        self.0 = 0x00000000 | I386EntryFlags::GUARD_PAGE.bits;
    }
}
