//! This crate is x86_64's little brother. It provides i386 specific functions
//! and data structures, and access to various system registers.

#![cfg(any(target_arch = "x86", test, doc))]
#![allow(dead_code)]

pub mod acpi;

#[macro_use]
pub mod registers;
pub mod stack;
pub mod multiboot;
pub mod structures;
pub mod process_switch;
pub mod gdt;
pub mod interrupt;
pub mod interrupt_service_routines;

pub mod pio {
    //! Port IO
    //!
    //! Look at libutils::io for more documentation.

    pub use crate::utils::io::Pio;
}

pub mod instructions {
    //! Low level functions for special i386 instructions.
    pub mod tables {
        //! Instructions for loading descriptor tables (GDT, IDT, etc.).

        use core::arch::asm;

        use crate::i386::structures::gdt::SegmentSelector;

        /// A struct describing a pointer to a descriptor table (GDT / IDT).
        /// This is in a format suitable for giving to 'lgdt' or 'lidt'.
        #[derive(Clone, Copy, Debug)]
        #[repr(C, packed)]
        pub struct DescriptorTablePointer {
            /// Size of the DT.
            pub limit: u16,
            /// Physical address of the memory region containing the DT.
            pub base: u32,
        }

        /// Load GDT table.
        ///
        /// # Safety
        ///
        /// The gdt argument must be a valid table pointer, containing a pointer
        /// in physical memory to a correct GDT. The meaning of a "correct GDT"
        /// is left as an exercise to the reader.
        pub unsafe fn lgdt(gdt: DescriptorTablePointer) {
            asm!("lgdt [{}]", in(reg) &gdt);
        }

        /// Store GDT table.
        pub fn sgdt() -> DescriptorTablePointer {
            unsafe {
                let mut out: DescriptorTablePointer = DescriptorTablePointer {
                    base: 0,
                    limit: 0
                };
                // This *requires* the =*m bound. For whatever reason, using =r causes UB, the
                // compiler starts wildly reordering SGDTs and LGDTs, even with volatile.
                asm!("sgdt [{}]", in(reg) &mut out);
                out
            }
        }


        /// Load LDT table.
        ///
        /// # Safety
        ///
        /// The ldt must point to a valid LDT segment in the GDT. Note that
        /// modifying the current LDT might cause pointer invalidation.
        pub unsafe fn lldt(ldt: SegmentSelector) {
            asm!("lldt {:x}", in(reg) ldt.0);
        }

        // TODO: Goes somewhere else.
        /// Sets the task register to the given TSS segment.
        ///
        /// # Safety
        ///
        /// segment must point to a valid TSS segment in the GDT.
        pub unsafe fn ltr(segment: SegmentSelector) {
            asm!("ltr {:x}", in(reg) segment.0);
        }

        /// Load IDT table.
        ///
        /// # Safety
        ///
        /// The idt argument must be a valid table pointer, containing a pointer
        /// in physical memory to a correct IDT. The meaning of a "correct IDT"
        /// is left as an exercise to the reader.
        pub unsafe fn lidt(idt: DescriptorTablePointer) {
            asm!("lidt [{}]", in(reg) &idt);
        }
    }

    pub mod segmentation {
        //! Provides functions to read and write segment registers.

        use core::arch::asm;

        use crate::i386::structures::gdt::SegmentSelector;

        /// Reload code segment register.
        /// Note this is special since we can not directly move
        /// to %cs. Instead we push the new segment selector
        /// and return value on the stack and use lretq
        /// to reload cs and continue at 1:.
        ///
        /// # Safety
        ///
        /// Sel must point to a present, valid segment in the GDT or LDT.
        /// Changing a segment will cause pointers to become invalidated. The
        /// only sound way to use this function is if the target segment has the
        /// same layout as the original segment.
        pub unsafe fn set_cs(sel: SegmentSelector) {
            asm!("pushl {}
                  pushl $1f
                  lretl
                  1:",
                  in(reg) u32::from(sel.0), options(att_syntax));
        }

        /// Reload stack segment register.
        ///
        /// # Safety
        ///
        /// Sel must point to a present, valid segment in the GDT or LDT.
        /// Changing a segment will cause pointers to become invalidated. The
        /// only sound way to use this function is if the target segment has the
        /// same layout as the original segment.
        pub unsafe fn load_ss(sel: SegmentSelector) {
            asm!("movw {:x}, %ss", in(reg) sel.0, options(att_syntax));
        }

        /// Reload data segment register.
        ///
        /// # Safety
        ///
        /// Sel must point to a present, valid segment in the GDT or LDT.
        /// Changing a segment will cause pointers to become invalidated. The
        /// only sound way to use this function is if the target segment has the
        /// same layout as the original segment.
        pub unsafe fn load_ds(sel: SegmentSelector) {
            asm!("movw {:x}, %ds", in(reg) sel.0, options(att_syntax));
        }

        /// Reload es segment register.
        ///
        /// # Safety
        ///
        /// Sel must point to a present, valid segment in the GDT or LDT.
        /// Changing a segment will cause pointers to become invalidated. The
        /// only sound way to use this function is if the target segment has the
        /// same layout as the original segment.
        pub unsafe fn load_es(sel: SegmentSelector) {
            asm!("movw {:x}, %es", in(reg) sel.0, options(att_syntax));
        }

        /// Reload fs segment register.
        ///
        /// # Safety
        ///
        /// Sel must point to a present, valid segment in the GDT or LDT.
        /// Changing a segment will cause pointers to become invalidated. The
        /// only sound way to use this function is if the target segment has the
        /// same layout as the original segment.
        pub unsafe fn load_fs(sel: SegmentSelector) {
            asm!("movw {:x}, %fs", in(reg) sel.0, options(att_syntax));
        }

        /// Reload gs segment register.
        ///
        /// # Safety
        ///
        /// Sel must point to a present, valid segment in the GDT or LDT.
        /// Changing a segment will cause pointers to become invalidated. The
        /// only sound way to use this function is if the target segment has the
        /// same layout as the original segment.
        pub unsafe fn load_gs(sel: SegmentSelector) {
            asm!("movw {:x}, %gs", in(reg) sel.0, options(att_syntax));
        }

        /// Returns the current value of the code segment register.
        pub fn cs() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %cs, {:x}", out(reg) segment, options(att_syntax)) };
            SegmentSelector(segment)
        }

        /// Read the value of the stack segment register.
        pub fn ss() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %ss, {:x}", out(reg) segment, options(att_syntax)) };
            SegmentSelector(segment)
        }

        /// Read the value of the data segment register.
        pub fn ds() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %ds, {:x}", out(reg) segment, options(att_syntax)) };
            SegmentSelector(segment)
        }

        /// Read the value of the es segment register.
        pub fn es() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %es, {:x}", out(reg) segment, options(att_syntax)) };
            SegmentSelector(segment)
        }

        /// Read the value of the fs segment register.
        pub fn fs() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %fs, {:x}", out(reg) segment, options(att_syntax)) };
            SegmentSelector(segment)
        }

        /// Read the value of the gs segment register.
        pub fn gs() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %gs, {:x}", out(reg) segment, options(att_syntax)) };
            SegmentSelector(segment)
        }
    }
    pub mod interrupts {
        //! Interrupt disabling functionality.

        use core::arch::asm;

        /// Enable interrupts
        ///
        /// # Safety
        ///
        /// Enabling interrupts when they are disabled can break critical
        /// sections based on [SpinLockIRQ](crate::sync::SpinLockIRQ).
        pub unsafe fn sti() {
            asm!("sti");
        }

        /// Disable interrupts
        ///
        /// # Safety
        ///
        /// Should be paired with a call to [sti]. While interrupts are
        /// disabled, care should be taken not to sleep in any way, as this will
        /// cause a deadlock.
        pub unsafe fn cli() {
            asm!("cli");
        }

        /// Waits until an interrupt is fired
        pub fn hlt() {
            unsafe {
                // Safety: HLT won't cause undefined behavior. Calling it might
                // cause a deadlock if interrupts are disabled, but that's not a
                // safety concern.
                asm!("hlt");
            }
        }

        /// Returns whether interrupts are enabled.
        pub fn are_enabled() -> bool {
            use crate::i386::registers::eflags::{self, EFlags};

            eflags::read().contains(EFlags::INTERRUPT_FLAG)
        }

        /// Run a closue with disabled interrupts.
        ///
        /// Run the given closure, disabling interrupts before running it (if they aren't already disabled).
        /// Afterwards, interrupts are enabling again if they were enabled before.
        ///
        /// If you have other `sti` and `cli` calls _within_ the closure, things may not work as expected.
        ///
        /// # Examples
        ///
        /// ```ignore
        /// // interrupts are enabled
        /// without_interrupts(|| {
        ///     // interrupts are disabled
        ///     without_interrupts(|| {
        ///         // interrupts are disabled
        ///     });
        ///     // interrupts are still disabled
        /// });
        /// // interrupts are enabled again
        /// ```
        pub fn without_interrupts<F, R>(f: F) -> R
        where
            F: FnOnce() -> R,
        {
            // true if the interrupt flag is set (i.e. interrupts are enabled)
            let saved_intpt_flag = are_enabled();

            // if interrupts are enabled, disable them for now
            if saved_intpt_flag {
                unsafe { cli(); }
            }

            // do `f` while interrupts are disabled
            let ret = f();

            // re-enable interrupts if they were previously enabled
            if saved_intpt_flag {
                unsafe { sti(); }
            }

            // return the result of `f` to the caller
            ret
        }
    }
}

/// Represents a protection ring level.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PrivilegeLevel {
    /// Privilege-level 0 (most privilege): This level is used by critical system-software
    /// components that require direct access to, and control over, all processor and system
    /// resources. This can include BIOS, memory-management functions, and interrupt handlers.
    Ring0 = 0,

    /// Privilege-level 1 (moderate privilege): This level is used by less-critical system-
    /// software services that can access and control a limited scope of processor and system
    /// resources. Software running at these privilege levels might include some device drivers
    /// and library routines. The actual privileges of this level are defined by the
    /// operating system.
    Ring1 = 1,

    /// Privilege-level 2 (moderate privilege): Like level 1, this level is used by
    /// less-critical system-software services that can access and control a limited scope of
    /// processor and system resources. The actual privileges of this level are defined by the
    /// operating system.
    Ring2 = 2,

    /// Privilege-level 3 (least privilege): This level is used by application software.
    /// Software running at privilege-level 3 is normally prevented from directly accessing
    /// most processor and system resources. Instead, applications request access to the
    /// protected processor and system resources by calling more-privileged service routines
    /// to perform the accesses.
    Ring3 = 3,
}

impl From<u8> for PrivilegeLevel {
    fn from(ring: u8) -> PrivilegeLevel {
        PrivilegeLevel::from_u8(ring)
    }
}

impl PrivilegeLevel {
    /// Creates a `PrivilegeLevel` from a numeric value. The value must be in the range 0..4.
    ///
    /// This function panics if the passed value is >3.
    pub fn from_u8(value: u8) -> PrivilegeLevel {
        match value {
            0 => PrivilegeLevel::Ring0,
            1 => PrivilegeLevel::Ring1,
            2 => PrivilegeLevel::Ring2,
            3 => PrivilegeLevel::Ring3,
            i => panic!("{} is not a valid privilege level", i),
        }
    }
}

/// The Task State Segment (TSS) is a special data structure for x86 processors which holds
/// information about a task. The TSS is primarily suited for hardware multitasking,
/// where each individual process has its own TSS.
/// ([see OSDEV](https://wiki.osdev.org/TSS))
#[repr(C, align(128))] // According to the IA32-E PDF, volume 3, 7.2.1:
// If paging is used:
// - Avoid placing a page boundary in the part of the TSS that the processor
//   reads during a task switch (the first 104 bytes). The processor may not
//   correctly perform address translations if a boundary occurs in this area.
//   During a task switch, the processor reads and writes into the first 104
//   bytes of each TSS (using contiguous physical addresses beginning with the
//   physical address of the first byte of the TSS). So, after TSS access
//   begins, if part of the 104 bytes is not physically contiguous, the
//   processor will access incorrect information without generating a
//   page-fault exception.
#[derive(Copy, Clone, Debug)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
pub struct TssStruct {
    pub link: u16,
    _reserved1: u16,
    pub esp0: u32,
    pub ss0: u16,
    _reserved2: u16,
    pub esp1: u32,
    pub ss1: u16,
    _reserved3: u16,
    pub esp2: u32,
    pub ss2: u16,
    _reserved4: u16,
    pub cr3: u32,
    pub eip: u32,
    pub eflags: u32,
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,
    pub es: u16,
    _reserved5: u16,
    pub cs: u16,
    _reserved6: u16,
    pub ss: u16,
    _reserved7: u16,
    pub ds: u16,
    _reserved8: u16,
    pub fs: u16,
    _reserved9: u16,
    pub gs: u16,
    _reserveda: u16,
    pub ldt_selector: u16,
    _reservedb: u16,
    _reservedc: u16,
    pub iopboffset: u16,
}

impl TssStruct {
    /// Creates an empty TssStruct.
    ///
    /// All fields are set to `0`, suitable for static declarations, so that it can live in the `.bss`.
    ///
    /// The TssStruct must then be initialized with [init].
    ///
    /// Note that until it is initialized properly, the `.iopboffset` field will be invalid.
    ///
    /// [init]: TssStruct::init
    pub const fn empty() -> TssStruct {
        TssStruct {
            _reserved1: 0,
            link: 0,
            esp0: 0,
            _reserved2: 0,
            ss0: 0,
            esp1: 0,
            _reserved3: 0,
            ss1: 0,
            esp2: 0,
            _reserved4: 0,
            ss2: 0,
            cr3: 0,
            eip: 0,
            eflags: 0,
            eax: 0,
            ecx: 0,
            edx: 0,
            ebx: 0,
            esp: 0,
            ebp: 0,
            esi: 0,
            edi: 0,
            _reserved5: 0,
            es: 0,
            _reserved6: 0,
            cs: 0,
            _reserved7: 0,
            ss: 0,
            _reserved8: 0,
            ds: 0,
            _reserved9: 0,
            fs: 0,
            _reserveda: 0,
            gs: 0,
            _reservedb: 0,
            ldt_selector: 0,
            iopboffset: 0,
            _reservedc: 0,
        }
    }

    /// Fills the TSS.
    ///
    /// The TSS is filled with kernel segments selectors, and the current cr3.
    /// Registers are set to 0.
    pub fn init(&mut self) {
        let ds = gdt::GdtIndex::KData.selector().0;
        let cs = gdt::GdtIndex::KCode.selector().0;
        let ss = gdt::GdtIndex::KStack.selector().0;
        let cr3 = crate::paging::read_cr3().addr() as u32;
        let ldt_selector = gdt::GdtIndex::LDT.selector().0;

        *self = TssStruct {
            ss0: ss,
            ss1: ss,
            ss2: ss,
            cr3: cr3,
            ldt_selector: ldt_selector,
            es: ds,
            cs: cs,
            ss: ss,
            ds: ds,
            fs: ds,
            gs: ds,
            iopboffset: ::core::mem::size_of::<TssStruct>() as u16,
            ..TssStruct::empty()
        }
    }

    /// Set the stack pointer used to handle interrupts occuring while running
    /// in Ring3.
    ///
    /// If an interrupt occurs while running in Ring3, it would be a security
    /// problem to use the user-controlled stack to handle the interrupt. To
    /// avoid this, we can tell the CPU to instead run the interrupt handler in
    /// a separate stack.
    pub fn set_esp0_stack(&mut self, esp: u32) {
        self.esp0 = esp;
    }

    /// Set the IP of the current task struct. When we hardware task switch to
    /// this TSS, we will resume running at the given instruction.
    pub fn set_ip(&mut self, eip: u32) {
        self.eip = eip;
    }
}
