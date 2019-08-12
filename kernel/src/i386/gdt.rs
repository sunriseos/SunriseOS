//! GDT Handler
//!
//! The Global Descriptor Table is responsible for segmentation of memory.
//!
//! Since we manage memory permissions in the paging, we want to set-up our
//! segments so that we have a flat-memory model, i.e. having segments with
//! `base = 0; limit = 0xffffffff`.
//!
//! ### GDT segments
//!
//! | Index                    | Found in                               | Maps to                        | Purpose                                                           |
//! |--------------------------|----------------------------------------|--------------------------------|-------------------------------------------------------------------|
//! | [`GdtIndex::Null`]       | nowhere (hopefully)                    | _                              | _                                                                 |
//! | [`GdtIndex::KCode`]      | `cs`, while in kernel code             | flat: `0x00000000..0xffffffff` | kernel's code segment                                             |
//! | [`GdtIndex::KData`]      | `ds`, `es`, while in kernel code       | flat: `0x00000000..0xffffffff` | kernel's data segment                                             |
//! | [`GdtIndex::KTls`]       | `gs`, while in kernel code             | kernel's cpu-locals            | kernel sets-up cpu-locals at this address                         |
//! | [`GdtIndex::KStack`]     | `ss`, while in kernel code             | flat: `0x00000000..0xffffffff` | kernel's stack segment                                            |
//! | [`GdtIndex::UCode`]      | `cs`, while in user code               | flat: `0x00000000..0xffffffff` | user's code segment                                               |
//! | [`GdtIndex::UData`]      | `ds`, `es`, while in user code         | flat: `0x00000000..0xffffffff` | user's data segment                                               |
//! | [`GdtIndex::UTlsRegion`] | `fs`, while in user code               | `&`[`TLS`]`..&`[`TLS`]`+0x200` | user can get the address of its [`TLS`] from this selector        |
//! | [`GdtIndex::UTlsElf`]    | `gs`, while in user code               | User-defined                   | user can set-up elf TLS at this address                           |
//! | [`GdtIndex::UStack`]     | `ss`, while in user code               | flat: `0x00000000..0xffffffff` |                                                                   |
//! | [`GdtIndex::LDT`]        | _                                      | Points to the [`GLOBAL_LDT`]   |                                                                   |
//! | [`GdtIndex::TSS`]        | IDT Double fault vector                | Points to the [`MAIN_TASK`]    | Double fault exception backups registers to this TSS              |
//! | [`GdtIndex::FTSS`]       | IDT Double fault vector                |                                | Double fault exception loads registers from this TSS              |
//!
//! ##### UTlsRegion
//!
//! The kernel allocates a 0x200-bytes region for every thread, and always makes `fs` point to it
//! when jumping to userspace. See [`TLS`] for more.
//!
//! This region is thread local, its address is switched at every thread-switch.
//!
//! ##### UTlsElf:
//!
//! The segment pointed by `gs` is controlled by the user. It can set its address/limit with
//! [`svcSetThreadArea`]. The segment it chooses to use is local to every thread, and defaults to `0x00000000..0xffffffff`.
//!
//! Typically, the user will want to make `gs` point to its elf TLS.
//!
//! This segment is thread local, its address and size are switched at every thread-switch.
//!
//! ### LDT segments:
//!
//! None :)
//!
//! ## x86_64
//!
//! Because x86_64 uses `fs` for tls instead of `gs`, the purpose of `gs` and `fs` are swapped:
//!
//! | Index               | Found in                               | Maps to                        | Purpose                                                           |
//! |---------------------|----------------------------------------|--------------------------------|-------------------------------------------------------------------|
//! | MSR                 | `fs`, while in kernel code             | kernel's cpu-locals            | kernel sets-up cpu-locals at this address                         |
//! | MSR                 | `gs`, while in user code               | `&`[`TLS`]`..&`[`TLS`]`+0x200` | user can get the address of its [`TLS`] from this selector        |
//! | MSR                 | `fs`, while in user code               | User-defined                   | user can set-up elf TLS at this address                           |
//!
//! [`GdtIndex::Null`]: gdt::GdtIndex::Null
//! [`GdtIndex::KCode`]: gdt::GdtIndex::KCode
//! [`GdtIndex::KData`]: gdt::GdtIndex::KData
//! [`GdtIndex::KTls`]: gdt::GdtIndex::KTls
//! [`GdtIndex::KStack`]: gdt::GdtIndex::KStack
//! [`GdtIndex::UCode`]: gdt::GdtIndex::UCode
//! [`GdtIndex::UData`]: gdt::GdtIndex::UData
//! [`GdtIndex::UTlsRegion`]: gdt::GdtIndex::UTlsRegion
//! [`GdtIndex::UTlsElf`]: gdt::GdtIndex::UTlsElf
//! [`GdtIndex::UStack`]: gdt::GdtIndex::UStack
//! [`GdtIndex::LDT`]: gdt::GdtIndex::LDT
//! [`GdtIndex::TSS`]: gdt::GdtIndex::TSS
//! [`GdtIndex::FTSS`]: gdt::GdtIndex::FTSS
//! [`TLS`]: sunrise_libkern::TLS
//! [`GLOBAL_LDT`]: gdt::GLOBAL_LDT
//! [`MAIN_TASK`]: gdt::MAIN_TASK
//! [`svcSetThreadArea`]: crate::syscalls::set_thread_area

#![allow(dead_code)]

use crate::sync::{SpinLockIRQ, Once};
use bit_field::BitField;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::fmt;

use crate::i386::{PrivilegeLevel, TssStruct};
use crate::i386::structures::gdt::SegmentSelector;
use crate::i386::instructions::tables::{lgdt, lldt, ltr, DescriptorTablePointer};
use crate::i386::instructions::segmentation::*;

use crate::paging::PAGE_SIZE;
use sunrise_libkern::TLS;
use spin::Mutex;
use bitfield::fmt::Debug;

/// The global GDT. Needs to be initialized with [init_gdt].
///
/// Modifying it disables interrupts.
pub static GDT: Once<SpinLockIRQ<GdtManager>> = Once::new();

/// The global LDT used by all the processes.
///
/// Empty.
static GLOBAL_LDT: Once<DescriptorTable> = Once::new();

/// Index in the GDT of each segment descriptor.
#[repr(usize)]
#[derive(Debug, Clone, Copy)]
pub enum GdtIndex {
    /// The index in the GDT of the null descriptor.
    Null       = 0,
    /// The index in the GDT of the Kernel code segment descriptor.
    KCode      = 1,
    /// The index in the GDT of the Kernel data segment descriptor.
    KData      = 2,
    /// The index in the GDT of the Kernel thread local storage ("cpu-locals") segment descriptor.
    KTls       = 3,
    /// The index in the GDT of the Kernel stack segment descriptor.
    KStack     = 4,
    /// The index in the GDT of the Userland code segment descriptor.
    UCode      = 5,
    /// The index in the GDT of the Userland data segment descriptor.
    UData      = 6,
    /// The index in the GDT of the Userland thread local storage segment descriptor.
    UTlsRegion = 7,
    /// The index in the GDT of the Userland thread local storage segment descriptor.
    UTlsElf    = 8,
    /// The index in the GDT of the Userland stack segment descriptor.
    UStack     = 9,
    /// The index in the GDT of the LDT descriptor.
    LDT       = 10,
    /// The index in the GDT of the main TSS descriptor.
    TSS       = 11,
    /// The index in the GDT of the double fault TSS descriptor.
    FTSS      = 12,

    /// The number of descriptors in the GDT.
    DescCount,
}

impl GdtIndex {
    /// Turns a segment descriptor index to a segment selector.
    ///
    /// The ring part of the selector will be `0b00` for K* segments, and `0b11` for U* segments.
    pub fn selector(self) -> SegmentSelector {
        match self {
            GdtIndex::KCode | GdtIndex::KData | GdtIndex::KTls | GdtIndex::KStack |
            GdtIndex::LDT | GdtIndex::TSS | GdtIndex::FTSS
                => SegmentSelector::new(self as u16, PrivilegeLevel::Ring0),
            GdtIndex::UCode | GdtIndex::UData | GdtIndex::UTlsRegion | GdtIndex::UTlsElf |
            GdtIndex::UStack
                => SegmentSelector::new(self as u16, PrivilegeLevel::Ring3),

            _ => panic!("Cannot get segment selector of {:?}", self)
        }
    }
}

/// Initializes the GDT.
///
/// Creates a GDT with a flat memory segmentation model. It will create 4 kernel
/// segments (code, data, tls, stack), 5 user segments (code, data, tls region, tls elf, stack), an
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
        gdt.table[GdtIndex::Null as usize] = DescriptorTableEntry::null_descriptor();
        // Push a kernel code segment
        gdt.table[GdtIndex::KCode as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring0,
        );
        // Push a kernel data segment
        gdt.table[GdtIndex::KData as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        );
        // Push a dummy tls segment, will be moved and resized appropriately later
        gdt.table[GdtIndex::KTls as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        );
        // Push a kernel stack segment
        gdt.table[GdtIndex::KStack as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring0,
        );
        // Push a userland code segment
        gdt.table[GdtIndex::UCode as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            true,
            PrivilegeLevel::Ring3,
        );
        // Push a userland data segment
        gdt.table[GdtIndex::UData as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        );
        // Push a userland thread local storage segment, will be moved at every thread-switch.
        gdt.table[GdtIndex::UTlsRegion as usize] = DescriptorTableEntry::new(
            0,
            (size_of::<TLS>() - 1) as u32,
            false,
            PrivilegeLevel::Ring3,
        );
        // Push a userland thread local storage segment, will be moved at every thread-switch.
        gdt.table[GdtIndex::UTlsElf as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        );
        // Push a userland stack segment
        gdt.table[GdtIndex::UStack as usize] = DescriptorTableEntry::new(
            0,
            0xffffffff,
            false,
            PrivilegeLevel::Ring3,
        );

        // Global LDT
        gdt.table[GdtIndex::LDT as usize] = DescriptorTableEntry::new_ldt(&GLOBAL_LDT.r#try().unwrap(), PrivilegeLevel::Ring0);

        // Main task
        let mut main_task = MAIN_TASK.lock();
        main_task.init();
        let main_tss_ref: &'static TssStruct = unsafe {
            // creating a static ref to tss.
            // kinda-safe: the tss is in a static so it is 'static, but is behind a lock
            // and will still be accessed by the hardware with no consideration for the lock.
            (&main_task.tss as *const TssStruct).as_ref().unwrap()
        };
        gdt.table[GdtIndex::TSS as usize] = DescriptorTableEntry::new_tss(main_tss_ref, PrivilegeLevel::Ring0, 0x2001);

        // Double fault task
        let mut fault_task = DOUBLE_FAULT_TASK.lock();
        fault_task.init();
        let fault_task_stack_end = unsafe { &DOUBLE_FAULT_TASK_STACK.0 } as *const u8 as usize + size_of::<DoubleFaultTaskStack>();
        fault_task.esp = fault_task_stack_end as u32;
        fault_task.esp0 = fault_task_stack_end as u32;
        fault_task.eip = 0; // will be set by IDT init.
        let fault_task_ref: &'static TssStruct = unsafe {
            // creating a static ref to tss.
            // safety: the tss is in a static so it is 'static, but is behind a lock
            // and will still be accessed by the hardware with no consideration for the lock.
            (&*fault_task as *const TssStruct).as_ref().unwrap()
        };
        gdt.table[GdtIndex::FTSS as usize] = DescriptorTableEntry::new_tss(fault_task_ref, PrivilegeLevel::Ring0, 0x0);

        SpinLockIRQ::new(gdt)
    });

    // initialized, now let's use it !

    let cs = GdtIndex::KCode.selector();
    let ds = GdtIndex::KData.selector();
    let fs = GdtIndex::UTlsRegion.selector();
    let gs = GdtIndex::KTls.selector();
    let ss = GdtIndex::KStack.selector();
    let ldt_ss = GdtIndex::LDT.selector();
    let tss_ss = GdtIndex::TSS.selector();

    let mut gdt = GDT.r#try().unwrap().lock();

    debug!("Loading GDT {:#?}\ncs: {:?}\nds: {:?}\nes: {:?}\nfs: {:?}\ngs: {:?}\nss: {:?}\nldt: {:?}\ntss: {:?}", gdt.deref().table, cs, ds, ds, fs, gs, ss, ldt_ss, tss_ss);
    gdt.commit(Some(cs), Some(ds), Some(ds), Some(fs), Some(gs), Some(ss));

    unsafe {
        debug!("Loading LDT {:?}", ldt_ss);
        lldt(ldt_ss);
        debug!("Loading Task {:?}", tss_ss);
        ltr(tss_ss);
    }

    info!("Loaded GDT {:#?}\ncs: {:?}\nds: {:?}\nes: {:?}\nfs: {:?}\ngs: {:?}\nss: {:?}\nldt: {:?}\ntss: {:?}", gdt.deref().table, cs, ds, ds, fs, gs, ss, ldt_ss, tss_ss);
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
pub struct GdtManager {
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

/// The main TSS. See [MAIN_TASK].
#[repr(C)]
pub struct MainTask {
    /// TssStruct of the main task.
    pub tss: TssStruct,
    /// Array of bits representing the io-space permissions:
    ///
    /// * `0`: this port is addressable.
    /// * `1`: this port is not addressable.
    pub iopb: [u8; 0x2001]
}

impl Debug for MainTask {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("MainTask")
            .field("tss", &self.tss)
            .field("iopb", &"*omitted*")
            .finish()
    }
}

impl MainTask {
    /// Creates an empty TSS.
    ///
    /// Suitable for static declaration, the whole structure should end up in the `.bss`.
    ///
    /// This means that the IOPB will be set to everything addressable.
    ///
    /// Must be initialised by calling [init].
    ///
    /// [init]: MainTask::init
    const fn empty() -> MainTask {
        MainTask {
            tss: TssStruct::empty(),
            iopb: [0u8; 0x2001]
        }
    }

    /// Fills the TSS.
    ///
    /// The struct inherits the current task's values (except registers, which are set to 0).
    ///
    /// IOPB is set to nothing addressable.
    fn init(&mut self) {
        self.tss.init();
        for v in &mut self.iopb[..] { *v = 0xFF }
    }
}

/// Main TSS
///
/// Because Sunrise does not make use of Hardware Task Switching, we only allocate a single
/// TSS that will be used by every process, we update it at every software task switch.
///
/// We mostly set the `esp0` field, updating which stack the cpu will jump to when handling an
/// exception/syscall.
///
/// #### IOPB
///
/// Right after the [TssStruct], the MAIN_TASK holds a bitarray indicating io-space permissions
/// for the current process, one bit for every port:
///
/// * `0`: this port is addressable.
/// * `1`: this port is not addressable.
///
/// This array is checked by the cpu every time a port is accessed by userspace, and we use it
/// to enforce io-space policies. This array is updated at every task switch.
///
/// The kernel bypasses this protection by having the `IOPL` set to `0b00` in `EFLAGS`,
/// making the kernel able to access all ports at all times.
///
/// ### Double fault
///
/// The only exception to this is double faulting, which does use Hardware Task Switching, and
/// for which we allocate a second TSS, see [DOUBLE_FAULT_TASK].
// todo: per-cpu TSSs / GDT
// body: There are multiple things that aren't ideal about the way we handle TSSs.
// body:
// body: ## Initialization
// body:
// body: TSSs must always be initialized with an iopb_offset of `size_of::<TSS>()`,
// body: so that the TSS's data is not interpreted as the iopb.
// body:
// body: However, because MAIN_TASK has a huge iopb (0x2001 bytes), we want it to live in the
// body: .bss, and be lazy initialized (iopb_offset value, and iopb array memset to 0xFF).
// body: `lazy_static` seems appropriate for that, and we should use it, so we cannot *forget* to
// body: initialize a TSS.
// body:
// body: DOUBLE_FAULT_TASK could be statically initialized, except for the `cr3` field.
// body:
// body: ## Per-cpu
// body:
// body: But we will likely want a MAIN and DOUBLE_FAULT TSS per core. However, they cannot trivially
// body: be put behind a `#[thread_local]`, as they are initialized with the GDT, before cpu-locals
// body: are initialized. It might be possible to make them `#[thread_local]` with some
// body: post-initialization routine that switches to using the MAIN and DOUBLE_FAULT_TASK in the
// body: cpu-local memory area instead of the static early one, after cpu-local have been initialized,
// body: for core 0.
// body: The static early one could do without an iopb, since we're not going to userspace with it.
// body:
// body: For other cores, having a `#[thead_local]` inside a `lazy_static!` seems to work, but I don't
// body: yet know how cores are going to be started, whether they allocate/initialize their own
// body: GDT + MAIN + DOUBLE_FAULT TSS, if it their parent core do it.
// body:
// body: Because of these unknowns, the search for a good design for TSSs/GDT is postponed.
// body:
// body: ## Locking
// body:
// body: Since the TSSs are supposed to be cpu-local, there is no reason for them to have a mutex
// body: around them. An ideal design would be lock-less, which can either be achieved with `#[thread_local]`,
// body: or some custom wrapper around an UnsafeCell just for TSSs.
// body:
// body: ## DOUBLE_FAULT's cr3
// body:
// body: The DOUBLE_FAULT TSS(s)'s cr3 must point to a valid page directory, which will remain valid
// body: (i.e. not be freed) for the entire lifetime of the kernel, and possibly updated when kernel
// body: page tables are modified.
// body:
// body: For now, because we have no such hierarchy, we always make DOUBLE_FAULT's cr3 point
// body: to the current cr3, and update it when we switch page table hierarchies. However the current
// body: way we do kernel paging is not viable for SMP, and we might finally implement such a hierarchy
// body: for SMP, we could then make DOUBLE_FAULT TSS(s) point to it.
pub static MAIN_TASK: Mutex<MainTask> = Mutex::new(MainTask::empty());

/// Double fault TSS
///
/// Double faulting will most likely occur after a kernel stack overflow.
/// We can't use the regular way of handling exception, i.e. pushing some registers and handling
/// the exception on the same stack that we were using, since it has overflowed.
///
/// We must switch the stack when it happens, and the only way to do that is via a task gate.
///
/// We setup a Tss whose `esp0` points to [DOUBLE_FAULT_TASK_STACK],
/// its `eip` to the double fault handler, and make the double fault vector in IDT task gate to it.
///
/// When a double fault occurs, the current (faulty) cpu registers values will be backed up
/// to [MAIN_TASK], where the double fault handler can access them to work out what happened.
///
/// ##### IOPB
///
/// Unlike the [MAIN_TASK], this TSS does not have an associated IOPB.
pub static DOUBLE_FAULT_TASK: Mutex<TssStruct> = Mutex::new(TssStruct::empty());

/// The stack used while handling a double fault.
///
/// Just a page aligned array of bytes.
#[repr(C, align(4096))]
struct DoubleFaultTaskStack([u8; 4096]);

/// The stack used while handling a double fault. See [DOUBLE_FAULT_TASK].
static mut DOUBLE_FAULT_TASK_STACK: DoubleFaultTaskStack = DoubleFaultTaskStack([0u8; PAGE_SIZE]);

/// A structure containing our GDT.
///
/// See [module level documentation].
///
/// [module level documentation]: super
#[derive(Debug, Clone, Default)]
pub struct DescriptorTable {
    /// The GDT table, an array of DescriptorTableEntry.
    pub table: [DescriptorTableEntry; GdtIndex::DescCount as usize],
}

impl DescriptorTable {

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
pub struct DescriptorTableEntry(u64);

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
    fn null_descriptor() -> DescriptorTableEntry {
        DescriptorTableEntry(0)
    }

    /// Creates an empty GDT descriptor, but with some flags set correctly
    fn new(base: u32, limit: u32, is_code: bool, priv_level: PrivilegeLevel) -> DescriptorTableEntry {
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
    fn new_system(ty: SystemDescriptorTypes, base: u32, limit: u32, priv_level: PrivilegeLevel) -> DescriptorTableEntry {
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
    fn new_ldt(base: &'static DescriptorTable, priv_level: PrivilegeLevel) -> DescriptorTableEntry {
        let limit = if base.table.is_empty() { 0 } else { base.table.len() * size_of::<DescriptorTableEntry>() - 1 };
        Self::new_system(SystemDescriptorTypes::Ldt, base as *const _ as u32, limit as u32, priv_level)
    }


    /// Creates a GDT descriptor pointing to a TSS segment
    fn new_tss(base: &'static TssStruct, priv_level: PrivilegeLevel, iobp_size: usize) -> DescriptorTableEntry {
        Self::new_system(SystemDescriptorTypes::AvailableTss32, base as *const _ as u32, (size_of::<TssStruct>() + iobp_size - 1) as u32, priv_level)
    }

    /// Gets the byte length of the entry, minus 1.
    pub fn get_limit(self) -> u32 {
        (self.0.get_bits(0..16) as u32) | ((self.0.get_bits(48..52) << 16) as u32)
    }

    /// Sets the entry's byte length to the given number plus one. Note that if
    /// the given length is higher than 65536, it should be properly
    /// page-aligned.
    ///
    /// # Panics
    ///
    /// Panics if the given limit is higher than 65536 and not page aligned.
    pub fn set_limit(&mut self, mut newlimit: u32) {
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
    pub fn get_base(self) -> u32 {
        (self.0.get_bits(16..40) as u32) | ((self.0.get_bits(56..64) << 24) as u32)
    }

    /// Sets the base address of the entry.
    pub fn set_base(&mut self, newbase: u32) {
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
