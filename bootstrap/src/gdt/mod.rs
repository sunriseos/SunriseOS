//! GDT Handler
//!
//! The Global Descriptor Table is responsible for segmentation of memory. In
//! our case though, we don't really care about that.

#![allow(dead_code)]
#![allow(missing_docs)]

pub mod segment_selector;
pub mod i386;

use spin::Once;
use arrayvec::ArrayVec;
use bit_field::BitField;
use core::mem::size_of;
use core::fmt::Write;

use self::segment_selector::SegmentSelector;
use self::i386::{PrivilegeLevel, TssStruct};

#[cfg_attr(not(test), link_section = ".gdt")]
static GDT: Once<DescriptorTable> = Once::new();

/// The global LDT used by all the processes.
static GLOBAL_LDT: Once<DescriptorTable> = Once::new();

pub fn init_gdt() {
    use self::i386::instructions::tables::{lldt, ltr};

    let ldt = GLOBAL_LDT.call_once(|| DescriptorTable::new());

    let gdt = GDT.call_once(|| {
        let mut gdt = DescriptorTable::new();
        // Push the null descriptor
        gdt.push(DescriptorTableEntry::null_descriptor());
        // Push a kernel code segment
        gdt.push(DescriptorTableEntry::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring0,
        ));
        // Push a kernel data segment
        gdt.push(DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        ));
        // Push a kernel stack segment
        gdt.push(DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        ));
        // Push a userland code segment
        gdt.push(DescriptorTableEntry::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring3,
        ));
        // Push a userland data segment
        gdt.push(DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        ));
        // Push a userland stack segment
        gdt.push(DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        ));
        // Global LDT
        gdt.push(DescriptorTableEntry::new_ldt(ldt, PrivilegeLevel::Ring0));
        // Main task
        gdt.push(DescriptorTableEntry::new_tss(&*MAIN_TASK, PrivilegeLevel::Ring0));
        // Double Fault Task
        gdt.push(DescriptorTableEntry::new_tss(&*FAULT_TASK, PrivilegeLevel::Ring0));
        gdt
    });

    writeln!(super::Serial, "Loading GDT");
    gdt.load_global(0x8, 0x10, 0x18);
    unsafe { 
        writeln!(super::Serial, "Loading LDT");
        lldt(SegmentSelector(7 << 3));
        writeln!(super::Serial, "Loading Task");
        ltr(SegmentSelector(8 << 3));
    }
}

#[no_mangle]
lazy_static! {
    pub static ref MAIN_TASK: TssStruct = {
        TssStruct::new(0, (SegmentSelector(0), 0), (SegmentSelector(0), 0), (SegmentSelector(0), 0), SegmentSelector(7 << 3))
    };
    pub static ref FAULT_TASK: TssStruct = {
        unsafe {
            TssStruct::new(0, (SegmentSelector(0x18), (::STACK.0.as_ptr() as usize + ::STACK.0.len() - 1)), (SegmentSelector(0), 0), (SegmentSelector(0), 0), SegmentSelector(7 << 3))
        }
        //let tss = TssStruct::new(0, (SegmentSelector(0x18), ::STACK + ::STACK.len() - 1), (SegmentSelector(0), 0), (SegmentSelector(0), 0), SegmentSelector(7 << 3));
        //tss.ss0 = 0x18;
        //tss.esp0 = ::STACK + ::STACK.len() - 1;
        //// TODO: What about CR3 ?
        //tss.eip = ::interrupts::double_fault_handler;
    };
}

/// A structure containing our GDT. We can have at most 16 segments, we should be
/// more than enough.
struct DescriptorTable {
    table: ArrayVec<[DescriptorTableEntry; 16]>,
}

impl DescriptorTable {
    pub fn new() -> DescriptorTable {
        let mut vec = ArrayVec::new();
        DescriptorTable {
            table: vec
        }
    }

    pub fn push(&mut self, entry: DescriptorTableEntry) {
        self.table.push(entry);
    }

    // TODO: make this configurable
    pub fn load_global(&'static self, _new_cs: u16, new_ds: u16, new_ss: u16) {
        use self::i386::instructions::tables::{lgdt, DescriptorTablePointer};

        let ptr = DescriptorTablePointer {
            base: self.table.as_ptr() as u32,
            limit: (self.table.len() * size_of::<u64>() - 1) as u16,
        };

        // TODO: Figure out how to chose CS.
        #[cfg(not(test))]
        unsafe {
            lgdt(&ptr);


            // For some reason, I can only far jmp using AT&T syntax... Which
            // makes me unbelievably sad. I should probably yell at LLVM for
            // this one.
            asm!("
            // Reload CS through far jmp
            ljmp $$0x8, $$reload_CS
            reload_CS:");

            asm!("
            // Reload other selectors
            MOV   AX, $0
            MOV   DS, AX
            MOV   ES, AX
            MOV   FS, AX
            MOV   GS, AX
            MOV   AX, $1
            MOV   SS, AX
            " : : "r"(new_ds), "r"(new_ss) : "EAX" : "intel");
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum SystemDescriptorTypes {
    AvailableTss16 = 1,
    Ldt = 2,
    BusyTss16 = 3,
    CallGate16 = 4,
    TaskGate = 5,
    InterruptGate16 = 6,
    TrapGate16 = 7,
    AvailableTss32 = 9,
    BusyTss32 = 11,
    CallGate32 = 12,
    InterruptGate32 = 14,
    TrapGate32 = 15
}

// TODO: make this an enum based on a bit? But then it's not repr(transparent)
// :(
#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
struct DescriptorTableEntry(u64);

impl DescriptorTableEntry {
    pub fn null_descriptor() -> DescriptorTableEntry {
        DescriptorTableEntry(0)
    }

    /// Creates an empty GDT descriptor, but with some flags set correctly
    pub fn new(base: u32, limit: u32, is_code: bool, priv_level: PrivilegeLevel) -> DescriptorTableEntry {
        let mut gdt = Self::null_descriptor();

        // First, the constant values.
        // We always allow read access for code, and write access for data.
        gdt.0.set_bit(41, true);
        // Make extra sure we don't touch is_conformant by a million miles pole.
        gdt.0.set_bit(42, false);
        // This bit is set to 1 for segment descriptors, 0 for system descriptors.
        gdt.0.set_bit(44, true);
        // The segment is present.
        gdt.0.set_bit(47, true);
        // The size is always 32-bit protected mode.
        gdt.0.set_bit(54, true);

        gdt.0.set_bit(43, is_code);
        gdt.0.set_bits(45..47, priv_level as u64);
        gdt.set_base(base);
        gdt.set_limit(limit);
        gdt
    }

    /// Creates an empty GDT descriptor, but with some flags set correctly
    pub fn new_system(ty: SystemDescriptorTypes, base: u32, limit: u32, priv_level: PrivilegeLevel) -> DescriptorTableEntry {
        let mut gdt = Self::null_descriptor();

        // Set the system descriptor type
        gdt.0.set_bits(40..44, ty as u64);
        // Set the privilege level.
        gdt.0.set_bits(45..47, priv_level as u64);
        // The segment is present.
        gdt.0.set_bit(47, true);
        gdt.set_base(base);
        gdt.set_limit(limit);
        gdt
    }

    /// Creates a new LDT descriptor.
    pub fn new_ldt(base: &'static DescriptorTable, priv_level: PrivilegeLevel) -> DescriptorTableEntry {
        Self::new_system(SystemDescriptorTypes::Ldt, base as *const _ as u32, (base.table.len() * size_of::<DescriptorTableEntry>()) as u32, priv_level)
    }


    /// Creates a GDT descriptor pointing to a TSS segment
    pub fn new_tss(base: &'static TssStruct, priv_level: PrivilegeLevel) -> DescriptorTableEntry {
        Self::new_system(SystemDescriptorTypes::AvailableTss32, base as *const _ as u32, size_of::<TssStruct>() as u32, priv_level)
    }

    fn get_limit(&self) -> u32 {
        (self.0.get_bits(0..16) as u32) | ((self.0.get_bits(48..52) << 16) as u32)
    }

    fn set_limit(&mut self, mut newlimit: u32) {
        if newlimit > 65536 && (newlimit & 0xFFF) != 0xFFF {
            panic!("Limit {} is invalid", newlimit);
        }

        if newlimit > 65536 {
            newlimit = newlimit >> 12;
            self.set_4k_granularity(true);
        }

        self.0.set_bits(0..16, newlimit.get_bits(0..16) as u64);
        self.0.set_bits(48..52, newlimit.get_bits(16..20) as u64);
    }

    fn get_base(&self) -> u32 {
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

    pub fn is_4k_granularity(&self) -> bool {
        self.0.get_bit(55)
    }

    fn set_4k_granularity(&mut self, is: bool) {
        self.0.set_bit(55, is);
    }

    pub fn is_32bit(&self) -> bool {
        self.0.get_bit(54)
    }
}
