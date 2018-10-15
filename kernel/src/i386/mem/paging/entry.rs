//! i386 page table entry

use i386::mem::frame_alloc::Frame;
use i386::mem::PhysicalAddress;
use core::fmt::{Debug, Formatter, Error};

bitflags! {
    /// The flags of a table entry
    pub struct EntryFlags: u32 {
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
        const IS_FRAME_ALLOC =  1 << 10;    // user_defined_2
        const USER_DEFINED_3 =  1 << 11;    // user_defined_3
    }
}

impl From<super::EntryFlags> for EntryFlags {
    fn from(flags: super::EntryFlags) -> EntryFlags {
        let mut newflags = EntryFlags::PRESENT;
        if flags.contains(super::EntryFlags::WRITABLE) {
            newflags |= EntryFlags::WRITABLE;
        }
        newflags
    }
}

const ENTRY_PHYS_ADDRESS_MASK: usize = 0xffff_f000;

/// An entry in a page table or page directory. An unused entry is 0
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Entry(u32);

impl Debug for Entry {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.debug_struct("Entry")
            .field("flags", &self.flags())
            .field("frame", &self.pointed_frame().as_option())
            .finish()
    }
}

impl Entry {
    /// Is the entry unused ?
    pub fn is_unused(&self) -> bool { self.0 == 0 }

    /// Clear the entry
    pub fn set_unused(&mut self) -> PageState<Frame> {
        let ret = self.pointed_frame().map(|addr| {
            if self.flags().contains(EntryFlags::IS_FRAME_ALLOC) {
                unsafe { Frame::from_allocated_addr(addr) }
            } else {
                Frame::from_physical_addr(addr)
            }
        });
        self.0 = 0;
        ret
    }

    /// Is the entry a page guard ?
    pub fn is_guard(&self) -> bool { self.flags().contains(EntryFlags::GUARD_PAGE) }

    /// Get the current entry flags
    pub fn flags(&self) -> EntryFlags { EntryFlags::from_bits_truncate(self.0) }

    /// Get the associated physical address, if available
    pub fn pointed_frame(&self) -> PageState<PhysicalAddress> {
        if self.flags().contains(EntryFlags::PRESENT) {
            let frame_phys_addr = self.0 as usize & ENTRY_PHYS_ADDRESS_MASK;
            PageState::Present(PhysicalAddress(frame_phys_addr))
        } else if self.flags().contains(EntryFlags::GUARD_PAGE) {
            PageState::Guarded
        } else {
            PageState::Available
        }
    }

    /// Sets the entry
    pub fn set(&mut self, frame: Frame, mut flags: EntryFlags) {
        assert_eq!(flags.contains(EntryFlags::PRESENT)
                && flags.contains(EntryFlags::GUARD_PAGE), false,
                "a GUARD_PAGE cannot also be PRESENT");
        assert!(!flags.contains(EntryFlags::IS_FRAME_ALLOC),
                "IS_FRAME_ALLOC is handled internally");
        let frame_phys_addr = frame.address();
        assert_eq!(frame_phys_addr.addr() & !ENTRY_PHYS_ADDRESS_MASK, 0);

        // Make sure we stay consistent.
        if frame.is_allocated() {
            flags.insert(EntryFlags::IS_FRAME_ALLOC);
        } else {
            flags.remove(EntryFlags::IS_FRAME_ALLOC);
        }

        self.0 = (frame_phys_addr.addr() as u32) | flags.bits();

        ::core::mem::forget(frame);
    }

    /// Make this entry a page guard
    pub fn set_guard(&mut self) {
        self.0 = 0x00000000 | EntryFlags::GUARD_PAGE.bits;
    }
}

/// Represent the current state of this Page Table Entry: It can either be:
///
/// - Available, aka unused
/// - Present, which is used and has a backing physical address
/// - Guarded, which is reserved and will cause a pagefault on use.
///
/// PageState is generic over various kind of Present states, similar to the
/// Option type.
#[derive(Debug)]
pub enum PageState<T> {
    Available,
    Guarded,
    Present(T)
}

impl<T> PageState<T> {
    /// Move the value T out of the PageState<T> if it is Present(T).
    ///
    /// # Panics
    ///
    /// Panics if the self value isn't Present.
    pub fn unwrap(self) -> T {
        match self {
            PageState::Present(t) => t,
            _ => panic!("Table was not present")
        }
    }

    /// Maps a PageState<T> to PageState<U> by applying a function to a
    /// contained value.
    pub fn map<U, F>(self, f: F) -> PageState<U>
        where F: FnOnce(T) -> U {
        match self {
            PageState::Present(t) => PageState::Present(f(t)),
            PageState::Guarded => PageState::Guarded,
            PageState::Available => PageState::Available
        }
    }

    /// Turns the PageState into an Option, setting both Guarded and Available
    /// state to None, and Present(t) state to Some(t).
    pub fn as_option(&self) -> Option<&T> {
        match *self {
            PageState::Present(ref t) => Some(t),
            PageState::Guarded => None,
            PageState::Available => None,
        }
    }
}
