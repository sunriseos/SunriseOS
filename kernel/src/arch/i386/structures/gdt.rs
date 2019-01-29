//! Types for the Global Descriptor Table and segment selectors.

use core::fmt;
use crate::arch::i386::PrivilegeLevel;
use bit_field::BitField;

/// Specifies which element to load into a segment from
/// descriptor tables (i.e., is a index to LDT or GDT table
/// with some additional flags).
///
/// See Intel 3a, Section 3.4.2 "Segment Selectors"
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct SegmentSelector(pub u16);

impl SegmentSelector {
    /// Creates a new SegmentSelector
    ///
    /// # Arguments
    ///  * `index`: index in GDT or LDT array.
    ///  * `rpl`: the requested privilege level
    pub const fn new(index: u16, rpl: PrivilegeLevel) -> SegmentSelector {
        SegmentSelector(index << 3 | (rpl as u16))
    }

    /// Returns the GDT index.
    pub fn index(self) -> u16 {
        self.0 >> 3
    }

    /// Returns the requested privilege level.
    pub fn rpl(self) -> PrivilegeLevel {
        PrivilegeLevel::from_u8(self.0.get_bits(0..2) as u8)
    }

    /// If true, this descriptor is backed by the LDT. If false, it is backed by
    /// the GDT.
    pub fn is_ldt(self) -> bool {
        self.0.get_bit(2)
    }
}

impl fmt::Debug for SegmentSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("SegmentSelector");
        s.field("index", &self.index());
        s.field("rpl", &self.rpl());
        s.field("is_ldt", &self.is_ldt());
        s.finish()
    }
}
