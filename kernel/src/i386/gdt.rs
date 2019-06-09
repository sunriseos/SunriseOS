//! GDT Handler
//!
//! The Global Descriptor Table is responsible for segmentation of memory. In
//! our case though, we don't really care about that.

#![allow(dead_code)]

use crate::sync::{SpinLock, Once};
use bit_field::BitField;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::slice;
use core::fmt;

use crate::i386::{PrivilegeLevel, TssStruct};
use crate::i386::structures::gdt::SegmentSelector;
use crate::i386::instructions::tables::{lgdt, lldt, ltr, DescriptorTablePointer};
use crate::i386::instructions::segmentation::*;

use crate::paging::PAGE_SIZE;
use crate::paging::{MappingAccessRights, kernel_memory::get_kernel_memory};
use crate::frame_allocator::{FrameAllocator, FrameAllocatorTrait};
use crate::mem::VirtualAddress;
use crate::utils::align_up;
use sunrise_libkern::TLS;
use crate::paging::lands::{UserLand, VirtualSpaceLand};

/// The global GDT. Needs to be initialized with init_gdt().
static GDT: Once<SpinLock<GdtManager>> = Once::new();

/// The global LDT used by all the processes.
static GLOBAL_LDT: Once<DescriptorTable> = Once::new();

/// The index in the GDT of the null descriptor.
const GDT_NULL:   usize = 0;
/// The index in the GDT of the Kernel code segment descriptor.
const GDT_KCODE:  usize = 1;
/// The index in the GDT of the Kernel data segment descriptor.
const GDT_KDATA:  usize = 2;
/// The index in the GDT of the Kernel stack segment descriptor.
const GDT_KSTACK: usize = 3;
/// The index in the GDT of the Userland code segment descriptor.
const GDT_UCODE:  usize = 4;
/// The index in the GDT of the Userland data segment descriptor.
const GDT_UDATA:  usize = 5;
/// The index in the GDT of the Userland stack segment descriptor.
const GDT_USTACK: usize = 6;
/// The index in the GDT of the Userland thread local storage segment descriptor.
const GDT_UTLS:   usize = 7;
/// The index in the GDT of the LDT descriptor.
const GDT_LDT:    usize = 8;
/// The index in the GDT of the main TSS descriptor.
const GDT_TSS:    usize = 9;
/// The number of descriptors in the GDT.
const GDT_DESC_COUNT: usize = 10;

/// Initializes the GDT.
///
/// Creates a GDT with a flat memory segmentation model. It will create 3 kernel
/// segments (code, data, stack), four user segments (code, data, stack, tls), an
/// LDT, and a TSS for the main task.
///
/// This function should only be called once. Further calls will be silently
/// ignored.
pub fn init_gdt() {

    // fill LDT with null descriptors
    GLOBAL_LDT.call_once(Default::default);

    GDT.call_once(|| {
        let mut gdt = GdtManager::default();
        // Push the null descriptor
        gdt.set(GDT_NULL, DescriptorTableEntry::null_descriptor());
        // Push a kernel code segment
        let cs = gdt.set(GDT_KCODE, DescriptorTableEntry::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring0,
        ));
        // Push a kernel data segment
        let ds = gdt.set(GDT_KDATA, DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        ));
        // Push a kernel stack segment
        let ss = gdt.set(GDT_KSTACK, DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        ));
        // Push a userland code segment
        gdt.set(GDT_UCODE, DescriptorTableEntry::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring3,
        ));
        // Push a userland data segment
        gdt.set(GDT_UDATA, DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        ));
        // Push a userland stack segment
        gdt.set(GDT_USTACK, DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        ));
        // Push a userland thread local storage segment
        let gs = gdt.set(GDT_UTLS, DescriptorTableEntry::new(
            0,
            (size_of::<TLS>() - 1) as u32,
            false,
            PrivilegeLevel::Ring3,
        ));

        // Global LDT
        let ldt_ss = gdt.set(GDT_LDT, DescriptorTableEntry::new_ldt(&GLOBAL_LDT.r#try().unwrap(), PrivilegeLevel::Ring0));

        let main_task = unsafe {
            (MAIN_TASK.addr() as *mut TssStruct).as_ref().unwrap()
        };

        // Main task
        let tss_ss = gdt.set(GDT_TSS, DescriptorTableEntry::new_tss(main_task, PrivilegeLevel::Ring0, 0x2001));

        gdt.commit(Some(cs), Some(ds), Some(ds), Some(ds), Some(gs), Some(ss));

        unsafe {
            debug!("Loading LDT");
            lldt(ldt_ss);
            debug!("Loading Task");
            ltr(tss_ss);
        }

        info!("Loaded GDT {:#?}\ncs: {:?}\nds: {:?}\nss: {:?}\ngs: {:?}\nldt: {:?}\ntss: {:?}", gdt.deref().table, cs, ds, ss, gs, ldt_ss, tss_ss);

        SpinLock::new(gdt)
    });
}

/// Safety wrapper that manages the lifetime of GDT tables.
///
/// Although Intel's guide doesn't really say much about it, modifying a GDT
/// "live" is probably a terrible idea. To work around this, the GdtManager keeps
/// two copies of the DescriptorTable, one being the currently active one (loaded
/// in the GDTR), and the other being where the changes to the GDT go to until
/// they are committed.
///
/// When `commit` is called, the internal GDT and current GDTR are swapped.
///
/// This struct's implementation of `Deref` and `DerefMut` will always give a reference to the table
/// currently not in use, so you can make modifications to it, and call `commit` afterwards.
#[derive(Debug, Default)]
struct GdtManager {
    /// One of the two tables.
    table_a: DescriptorTable,
    /// One of the two tables.
    table_b: DescriptorTable,
    /// The table currently pointed to by GDTR. `0` is `table_a`, `1` is `table_b`.
    table_selector: bool
}

impl GdtManager {
    /// Commit the changes in the currently unloaded table, and update segment registers.
    ///
    /// # Selectors
    ///
    /// To make a segment register point to a new descriptor, pass `Some(selector)` to this function.
    ///
    /// If `None` is passed, the register will be reloaded from its current value.
    /// This is what you want if you only updated the content of the descriptor.
    /// We always perform a reload of all registers to make sure they reflect the state of the GDT,
    /// in case the user modified it.
    pub fn commit(&mut self, new_cs: Option<SegmentSelector>,
                             new_ds: Option<SegmentSelector>,
                             new_es: Option<SegmentSelector>,
                             new_fs: Option<SegmentSelector>,
                             new_gs: Option<SegmentSelector>,
                             new_ss: Option<SegmentSelector>) {
        let (previous_in_use, to_load) = if !self.table_selector {
            (&mut self.table_a, &mut self.table_b)
        } else {
            (&mut self.table_b, &mut self.table_a)
        };

        // first make gdtr point to the new table, and reload segment selector
        to_load.load_global(new_cs, new_ds, new_es, new_fs, new_gs, new_ss);
        // copy the new table to the old one
        previous_in_use.table.copy_from_slice(&to_load.table);
        // and toggle selector
        self.table_selector = !self.table_selector;
    }
}

impl Deref for GdtManager {
    type Target = DescriptorTable;

    /// Deref always returns a reference to the table not in use, so it can be modified,
    /// before being committed.
    fn deref(&self) -> &DescriptorTable {
        if !self.table_selector {
            &self.table_b
        } else {
            &self.table_a
        }
    }
}

impl DerefMut for GdtManager {
    /// DerefMut always returns a reference to the table not in use, so it can be modified,
    /// before being committed.
    fn deref_mut(&mut self) -> &mut DescriptorTable {
        if !self.table_selector {
            &mut self.table_b
        } else {
            &mut self.table_a
        }
    }
}

/// Push a task segment.
pub fn push_task_segment(task: &'static TssStruct) -> SegmentSelector {
    info!("Pushing TSS: {:#?}", task);
    let mut gdt = GDT.r#try().expect("GDT was not initialized").lock();
    let idx = gdt.set(GDT_TSS, DescriptorTableEntry::new_tss(task, PrivilegeLevel::Ring0, 0));
    gdt.commit(None, None, None, None, None, None);
    idx
}

lazy_static! {
    /// VirtualAddress of the TSS structure of the main task. Has 0x2001 bytes
    /// available after the TssStruct to encode the IOPB of the current process.
    pub static ref MAIN_TASK: VirtualAddress = {
        // We need TssStruct + 0x2001 bytes of IOPB.
        let pregion = FrameAllocator::allocate_region(align_up(size_of::<TssStruct>() + 0x2001, PAGE_SIZE))
            .expect("Failed to allocate physical region for tss MAIN_TASK");
        let vaddr = get_kernel_memory().map_phys_region(pregion, MappingAccessRights::WRITABLE);
        let tss = vaddr.addr() as *mut TssStruct;
        unsafe {
            *tss = TssStruct::new();

            // Now, set the IOPB to 0xFF to prevent all userland accesses
            slice::from_raw_parts_mut(tss.offset(1) as *mut u8, 0x2001).iter_mut().for_each(|v| *v = 0xFF);
        }
        vaddr
    };
}

/// Update the address of the TLS region. Called on context-switch.
pub fn update_userspace_tls(new_address: VirtualAddress) {
    debug!("Setting userspace TLS to {}", new_address);
    debug_assert!(UserLand::contains_region(new_address, size_of::<TLS>()), "Trying to set UTLS in KernelLand");
    let mut gdt = GDT.r#try().expect("GDT was not initialized").lock();
    gdt.set(GDT_UTLS, DescriptorTableEntry::new(
        new_address.addr() as u32,
        (size_of::<TLS>() - 1) as u32,
        false,
        PrivilegeLevel::Ring3));
    gdt.commit(None, None, None, None, None, None);
}

// TODO: gdt::get_main_iopb does not prevent creation of multiple mut ref.
// BODY: There's currently no guarantee that we don't create multiple &mut
// BODY: pointer to the IOPB region, which would cause undefined behavior. In
// BODY: practice, it should only be used by `i386::process_switch`, and as such,
// BODY: there is never actually two main_iopb active at the same time. Still,
// BODY: it'd be nicer to have safe functions to access the IOPB.
/// Get the IOPB of the Main Task.
///
/// # Safety
///
/// This function can be used to create multiple mut references to the same
/// region, which is very UB. Care should be taken to make sure any old mut slice
/// acquired through this method is dropped before it is called again.
pub unsafe fn get_main_iopb() -> &'static mut [u8] {
    slice::from_raw_parts_mut((MAIN_TASK.addr() as *mut TssStruct).offset(1) as *mut u8, 0x2001)
}

/// A structure containing our GDT.
#[derive(Debug, Clone, Default)]
struct DescriptorTable {
    /// The GDT table, an array of DescriptorTableEntry.
    table: [DescriptorTableEntry; GDT_DESC_COUNT],
}

impl DescriptorTable {

    /// Updates an entry in the table, returning a segment selector to it.
    pub fn set(&mut self, index: usize, entry: DescriptorTableEntry) -> SegmentSelector {
        self.table[index] = entry;
        SegmentSelector(((index as u16) << 3) | (entry.get_ring_level() as u16))
    }

    /// Load this descriptor table into the GDTR, and reload the segment registers.
    fn load_global(&mut self, new_cs: Option<SegmentSelector>,
                              new_ds: Option<SegmentSelector>,
                              new_es: Option<SegmentSelector>,
                              new_fs: Option<SegmentSelector>,
                              new_gs: Option<SegmentSelector>,
                              new_ss: Option<SegmentSelector>) {
        let ptr = DescriptorTablePointer {
            base: self.table.as_ptr() as u32,
            limit: (self.table.len() * size_of::<DescriptorTableEntry>()) as u16,
        };

        unsafe {

            lgdt(ptr);

            // Reload segment selectors
            set_cs(match new_cs { Some(s) => s, None => cs() });
            load_ds(match new_ds { Some(s) => s, None => ds()});
            load_es(match new_es { Some(s) => s, None => es()});
            load_fs(match new_fs { Some(s) => s, None => fs()});
            load_gs(match new_gs { Some(s) => s, None => gs()});
            load_ss(match new_ss { Some(s) => s, None => ss()});
        }
    }
}

/// Lists the valid values of System Descriptor Types.
// Trap/Task/Interrupt gates are voluntarily absent. This enum should only
// contain descriptor types valid for GDT/LDT. IDT is kept separate.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::missing_docs_in_private_items)]
enum SystemDescriptorTypes {
    AvailableTss16 = 1,
    Ldt = 2,
    BusyTss16 = 3,
    CallGate16 = 4,
    AvailableTss32 = 9,
    BusyTss32 = 11,
    CallGate32 = 12,
}

/// An entry in the GDT/LDT.
///
/// Those entries generally describe a segment. However, the DescriptorTable also
/// contains special descriptors called "System Descriptors". Those are used for
/// specifying different kind of memory regions used by the CPU, such as TSS,
/// LDT, or Call Gates.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct DescriptorTableEntry(u64);

impl fmt::Debug for DescriptorTableEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        //ES =0010 00000000 ffffffff 00c09300 DPL=0 DS   [-WA]
        if self.0 == 0 {
            write!(f, "DescriptorTableEntry(NULLDESC)")
        } else {
            let ty = if self.0.get_bit(44) && self.0.get_bit(43) {
                "CS"
            } else if self.0.get_bit(44) {
                "DS"
            } else {
                match self.0.get_bits(40..44) {
                    1 => "TSS16-avl",
                    2 => "LDT",
                    3 => "TSS16-busy",
                    4 => "CALL16",
                    5 => "TASK",
                    6 => "INT16",
                    7 => "TRAP16",
                    9 => "TSS32-avl",
                    11 => "TSS32-busy",
                    12 => "CALL32",
                    14 => "INT32",
                    15 => "TRAP32",
                    _ => "UNKN"
                }
            };
            write!(f, "DescriptorTableEntry(base={:#010x}, limit={:#010x}, flags={:#010x}, DPL={:?}, type={})",
                   self.get_base(), self.get_limit(), self.0, self.get_ring_level(), ty)
        }
    }
}

impl DescriptorTableEntry {
    /// Returns an empty descriptor. Using this descriptor is an error and will
    /// raise a GPF. Should only be used to create a descriptor to place at index
    /// 0 of the GDT.
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

    /// Creates an empty GDT system descriptor of the given type.
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
        let limit = if base.table.is_empty() { 0 } else { base.table.len() * size_of::<DescriptorTableEntry>() - 1 };
        Self::new_system(SystemDescriptorTypes::Ldt, base as *const _ as u32, limit as u32, priv_level)
    }


    /// Creates a GDT descriptor pointing to a TSS segment
    pub fn new_tss(base: &'static TssStruct, priv_level: PrivilegeLevel, iobp_size: usize) -> DescriptorTableEntry {
        Self::new_system(SystemDescriptorTypes::AvailableTss32, base as *const _ as u32, (size_of::<TssStruct>() + iobp_size - 1) as u32, priv_level)
    }

    /// Gets the byte length of the entry, minus 1.
    fn get_limit(self) -> u32 {
        (self.0.get_bits(0..16) as u32) | ((self.0.get_bits(48..52) << 16) as u32)
    }

    /// Sets the entry's byte length to the given number plus one. Note that if
    /// the given length is higher than 65536, it should be properly
    /// page-aligned.
    ///
    /// # Panics
    ///
    /// Panics if the given limit is higher than 65536 and not page aligned.
    fn set_limit(&mut self, mut newlimit: u32) {
        if newlimit > 65536 && (newlimit & 0xFFF) != 0xFFF {
            panic!("Limit {} is invalid", newlimit);
        }

        if newlimit > 65536 {
            newlimit >>= 12;
            self.set_4k_granularity(true);
        }

        self.0.set_bits( 0..16, u64::from(newlimit.get_bits( 0..16)));
        self.0.set_bits(48..52, u64::from(newlimit.get_bits(16..20)));
    }

    /// Gets the base address of the entry.
    fn get_base(self) -> u32 {
        (self.0.get_bits(16..40) as u32) | ((self.0.get_bits(56..64) << 24) as u32)
    }

    /// Sets the base address of the entry.
    fn set_base(&mut self, newbase: u32) {
        self.0.set_bits(16..40, u64::from(newbase.get_bits( 0..24)));
        self.0.set_bits(56..64, u64::from(newbase.get_bits(24..32)));
    }

    /// CPU sets this bit to true when the segment is accessed.
    pub fn get_accessed(self) -> bool {
        self.0.get_bit(40)
    }

    /// - Code Segments: Whether read access for this segment is allowed.
    /// - Data Segments: Whether write access for this segment is allowed.
    pub fn is_readwrite_allowed(self) -> bool {
        self.0.get_bit(41)
    }

    /// - Code Segments: if true, code in this segment can be executed from a
    ///   lower privilege level (example: ring3 can far jump into ring2 code).
    ///   If false, the code segment can only be executed from the right DPL.
    /// - Data Segments: if true, the segment grows up. If false, the segment
    ///   grows down.
    pub fn is_comformant(self) -> bool {
        self.0.get_bit(42)
    }

    /// Determines whether the segment is a code segment or a data segment. If
    /// true, this is a code segment and can be executed. If false, this is a
    /// data segment.
    pub fn is_executable(self) -> bool {
        self.0.get_bit(43)
    }

    // bit 44 is unused

    /// The privilege level associated with this segment.
    pub fn get_ring_level(self) -> PrivilegeLevel {
        PrivilegeLevel::from_u8(self.0.get_bits(45..47) as u8)
    }

    /// A segment needs to be present to have an effect. Using a not-present
    /// segment will cause an exception.
    pub fn get_present(self) -> bool {
        self.0.get_bit(47)
    }

    /// If true, the limit is a count of 4k pages. If false, it is a byte count.
    pub fn is_4k_granularity(self) -> bool {
        self.0.get_bit(55)
    }

    /// If true, the limit is a count of 4k pages. If false, it is a byte count.
    fn set_4k_granularity(&mut self, is: bool) {
        self.0.set_bit(55, is);
    }

    /// If true, this is a 32-bit segment. If false, it is a 16-bit selector.
    pub fn is_32bit(self) -> bool {
        self.0.get_bit(54)
    }
}

impl Default for DescriptorTableEntry {
    fn default() -> Self {
        DescriptorTableEntry::null_descriptor()
    }
}
