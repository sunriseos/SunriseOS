//! GDT Handler
//!
//! The Global Descriptor Table is responsible for segmentation of memory. In
//! our case though, we don't really care about that.

#![allow(dead_code)]

use spin::Once;
use arrayvec::ArrayVec;
use bit_field::BitField;

use super::i386::PrivilegeLevel;

#[link_section = ".gdt"]
static GDT: Once<Gdt> = Once::new();

pub fn init_gdt() {
    let gdt = GDT.call_once(|| Gdt::new());
    gdt.load();
}

/// A structure containing our GDT. We can have at most 8 segments, we should be
/// more than enough.
struct Gdt {
    table: ArrayVec<[GdtDescriptor; 8]>,
}

impl Gdt {
    pub fn new() -> Gdt {
        let mut vec = ArrayVec::new();
        vec.push(GdtDescriptor::null_descriptor()); // Push the null descriptor
        vec.push(GdtDescriptor::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring0,
        )); // Push a kernel code segment
        vec.push(GdtDescriptor::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        )); // Push a kernel data segment
        vec.push(GdtDescriptor::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring3,
        )); // Push a userland code segment
        vec.push(GdtDescriptor::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        )); // Push a userland data segment
        Gdt { table: vec }
    }

    // TODO: make this configurable

    pub fn load(&'static self) {
        use i386::instructions::tables::{lgdt, DescriptorTablePointer};
        use core::mem::size_of;

        let ptr = DescriptorTablePointer {
            base: self.table.as_ptr() as u64,
            limit: (self.table.len() * size_of::<u64>() - 1) as u16,
        };

        unsafe { lgdt(&ptr) };
    }
}

// TODO: make this an enum based on a bit? But then it's not repr(transparent)
// :(
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct GdtDescriptor(u64);

impl GdtDescriptor {
    pub fn null_descriptor() -> GdtDescriptor {
        GdtDescriptor(0)
    }

    /// Creates an empty GDT descriptor, but with some flags set correctly
    pub fn new(base: u32, limit: u32, is_code: bool, priv_level: PrivilegeLevel) -> GdtDescriptor {
        if limit & 0xFFF != 0xFFF {
            panic!("Wrong limit size: {}", limit);
        }

        let mut gdt = Self::null_descriptor();

        // First, the constant values.
        // We always allow read access for code, and write access for data.
        gdt.0.set_bit(41, true);
        // Make extra sure we don't touch is_conformant by a million miles pole.
        gdt.0.set_bit(42, false);
        // This bit is always set to 1.
        gdt.0.set_bit(44, true);
        // The segment is obviously present.
        gdt.0.set_bit(47, true);
        // The size is always 32-bit protected mode.
        gdt.0.set_bit(54, true);
        // We want granularity to always be 4k.
        gdt.0.set_bit(55, true);

        gdt.0.set_bit(43, is_code);
        gdt.0.set_bits(45..47, priv_level as u64);
        gdt.set_limit(limit);
        gdt.set_base(base);
        gdt
    }

    pub fn get_limit(&self) -> u32 {
        (self.0.get_bits(0..16) as u32) | ((self.0.get_bits(48..52) << 16) as u32)
    }

    fn set_limit(&mut self, newlimit: u32) {
        self.0.set_bits(0..16, newlimit.get_bits(0..16) as u64);
        self.0.set_bits(48..52, newlimit.get_bits(16..20) as u64);
    }

    pub fn get_base(&self) -> u32 {
        (self.0.get_bits(16..40) as u32) | ((self.0.get_bits(56..64) << 24) as u32)
    }

    fn set_base(&mut self, newbase: u32) {
        self.0.set_bits(16..40, newbase.get_bits(0..24) as u64);
        self.0.set_bits(56..64, newbase.get_bits(24..32) as u64);
    }

    pub fn get_accessed(&self) -> bool {
        self.0.get_bit(40)
    }

    pub fn is_readwrite_allowed(&self) -> bool {
        self.0.get_bit(41)
    }

    // TODO: also gets direction
    pub fn is_comformant(&self) -> bool {
        self.0.get_bit(42)
    }

    pub fn is_executable(&self) -> bool {
        self.0.get_bit(43)
    }

    // bit 44 is unused

    pub fn get_ring_level(&self) -> PrivilegeLevel {
        PrivilegeLevel::from_u16(self.0.get_bits(45..47) as u16)
    }

    pub fn get_present(&self) -> bool {
        self.0.get_bit(47)
    }

    pub fn is_4kb_page(&self) -> bool {
        self.0.get_bit(55)
    }

    pub fn is_32bit(&self) -> bool {
        self.0.get_bit(54)
    }
}
