//! GDT Handler
//!
//! The Global Descriptor Table is responsible for segmentation of memory. In
//! our case though, we don't really care about that.

#![allow(dead_code)]

use sync::{SpinLock, Once};
use arrayvec::ArrayVec;
use bit_field::BitField;
use core::mem::{self, size_of};
use core::ops::{Deref, DerefMut};
use core::slice;

use super::i386::{PrivilegeLevel, TssStruct};
use i386::structures::gdt::SegmentSelector;
use i386::instructions::tables::{lgdt, sgdt, DescriptorTablePointer};
use i386::instructions::segmentation::*;

use paging::{self, KernelLand, VirtualAddress, PAGE_SIZE, ACTIVE_PAGE_TABLES, PageTablesSet};
use alloc::vec::Vec;
use utils::div_round_up;

static GDT: Once<SpinLock<GdtManager>> = Once::new();

/// The global LDT used by all the processes.
static GLOBAL_LDT: Once<DescriptorTable> = Once::new();

pub fn init_gdt() {
    use i386::instructions::tables::{lldt, ltr};

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

        let main_task = unsafe {
            (MAIN_TASK.addr() as *mut TssStruct).as_ref().unwrap()
        };

        // Main task
        gdt.push(DescriptorTableEntry::new_tss(main_task, PrivilegeLevel::Ring0, 0x2001));

        info!("Loading GDT");
        SpinLock::new(GdtManager::load(gdt, 0x8, 0x10, 0x18))
    });

    unsafe {
        info!("Loading LDT");
        lldt(SegmentSelector(7 << 3));
        info!("Loading Task");
        ltr(SegmentSelector(8 << 3));
    }
}

struct GdtManager {
    unloaded_table: Option<DescriptorTable>,
}

impl GdtManager {
    pub fn load(cur_loaded: DescriptorTable, new_cs: u16, new_ds: u16, new_ss: u16) -> GdtManager {
        let clone = cur_loaded.clone();
        cur_loaded.load_global(new_cs, new_ds, new_ss);

        GdtManager {
            unloaded_table: Some(clone)
        }
    }

    pub fn commit(&mut self, new_cs: u16, new_ds: u16, new_ss: u16) {
        let old_table = self.unloaded_table.take()
            .expect("Commit to not be called recursively")
            .load_global(new_cs, new_ds, new_ss);
        unsafe {
            self.unloaded_table = Some(DescriptorTable {
                table: Vec::from_raw_parts(
                    old_table.base as *mut DescriptorTableEntry,
                    old_table.limit as usize / size_of::<DescriptorTableEntry>(),
                    old_table.limit as usize / size_of::<DescriptorTableEntry>())
            });
        }
        self.set_from_loaded()
    }
}

impl Deref for GdtManager {
    type Target = DescriptorTable;

    fn deref(&self) -> &DescriptorTable {
        self.unloaded_table.as_ref().expect("Deref should not be called during commit")
    }
}

impl DerefMut for GdtManager {
    fn deref_mut(&mut self) -> &mut DescriptorTable {
        self.unloaded_table.as_mut().expect("DerefMut should not be called during commit")
    }
}

// Push a task segment.
pub fn push_task_segment(task: &'static TssStruct) -> u16 {
    info!("Pushing TSS: {:#?}", task);
    let mut gdt = GDT.try().unwrap().lock();
    let idx = gdt.push(DescriptorTableEntry::new_tss(task, PrivilegeLevel::Ring0, 0));
    gdt.commit(0x8, 0x10, 0x18);
    idx
}

lazy_static! {
    pub static ref MAIN_TASK: VirtualAddress = {
        // We need TssStruct + 0x2001 bytes of IOPB.
        let vaddr = ACTIVE_PAGE_TABLES.lock().get_pages::<KernelLand>(div_round_up(size_of::<TssStruct>() + 0x2001, paging::PAGE_SIZE));
        let tss = vaddr.addr() as *mut TssStruct;
        unsafe {
            *tss = TssStruct::new();

            // Now, set the IOPB to 0xFF to prevent all userland accesses
            slice::from_raw_parts_mut(tss.offset(1) as *mut u8, 0x2001).iter_mut().for_each(|v| *v = 0xFF);
        }
        vaddr
    };
}

// TODO: There's currently no guarantee that we don't create multiple &mut pointer to the IOPB.
// In practice, it should only be used by i386::process_switch, and as such, observed only there.
// TODO: Find a way to restrict usage there.
pub unsafe fn get_main_iopb() -> &'static mut [u8] {
    slice::from_raw_parts_mut((MAIN_TASK.addr() as *mut TssStruct).offset(1) as *mut u8, 0x2001)
}

/// A structure containing our GDT.
#[derive(Debug, Clone)]
struct DescriptorTable {
    table: Vec<DescriptorTableEntry>,
}

impl DescriptorTable {
    pub fn new() -> DescriptorTable {
        DescriptorTable {
            table: Vec::new()
        }
    }

    pub fn set_from_loaded(&mut self) {
        use core::slice;

        let mut loaded_ptr = sgdt();
        let loaded_table = unsafe {
            slice::from_raw_parts(loaded_ptr.base as *mut DescriptorTableEntry, loaded_ptr.limit as usize / size_of::<DescriptorTableEntry>())
        };

        self.table.clear();
        self.table.extend_from_slice(loaded_table);
    }

    pub fn push(&mut self, entry: DescriptorTableEntry) -> u16 {
        let ret = self.table.len() << 3;
        self.table.push(entry);
        ret as u16
    }

    fn load_global(mut self, new_cs: u16, new_ds: u16, new_ss: u16) -> DescriptorTablePointer {
        self.table.shrink_to_fit();
        assert_eq!(self.table.len(), self.table.capacity());

        let ptr = DescriptorTablePointer {
            base: self.table.as_ptr() as u32,
            limit: (self.table.len() * size_of::<DescriptorTableEntry>() - 1) as u16,
        };

        let oldptr = sgdt();

        // TODO: Figure out how to chose CS.
        unsafe {

            lgdt(&ptr);

            // Reload segment selectors
            set_cs(SegmentSelector(new_cs));
            load_ds(SegmentSelector(new_ds));
            load_es(SegmentSelector(new_ds));
            load_fs(SegmentSelector(new_ds));
            load_gs(SegmentSelector(new_ds));
            load_ss(SegmentSelector(new_ss));
        }

        mem::forget(self.table);

        oldptr
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
        Self::new_system(SystemDescriptorTypes::Ldt, base as *const _ as u32, (base.table.len() * size_of::<DescriptorTableEntry>() - 1) as u32, priv_level)
    }


    /// Creates a GDT descriptor pointing to a TSS segment
    pub fn new_tss(base: &'static TssStruct, priv_level: PrivilegeLevel, iobp_size: usize) -> DescriptorTableEntry {
        Self::new_system(SystemDescriptorTypes::AvailableTss32, base as *const _ as u32, (size_of::<TssStruct>() + iobp_size - 1) as u32, priv_level)
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
