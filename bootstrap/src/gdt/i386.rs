//! This crate is x86_64's little brother. It provides i386 specific functions
//! and data structures, and access to various system registers.

#![cfg(any(target_arch = "x86", test, doc))]
#![allow(dead_code)]

pub mod instructions {
    //! Low level functions for special i386 instructions.
    pub mod tables {
        //! Instructions for loading descriptor tables (GDT, IDT, etc.).

        use core::arch::asm;

        use crate::gdt::segment_selector::SegmentSelector;

        /// A struct describing a pointer to a descriptor table (GDT / IDT).
        /// This is in a format suitable for giving to 'lgdt' or 'lidt'.
        #[repr(C, packed)]
        pub struct DescriptorTablePointer {
            /// Size of the DT.
            pub limit: u16,
            /// Pointer to the memory region containing the DT.
            pub base: u32,
        }

        /// Load GDT table.
        ///
        /// # Safety
        ///
        /// The gdt argument must be a valid table pointer, containing a pointer
        /// in physical memory to a correct GDT. The meaning of a "correct GDT"
        /// is left as an exercise to the reader.
        pub unsafe fn lgdt(gdt: &DescriptorTablePointer) {
            asm!("lgdt [{}]", in(reg) gdt);
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
        pub unsafe fn lidt(idt: &DescriptorTablePointer) {
            asm!("lidt [{}]", in(reg) idt);
        }
    }

    pub mod segmentation {
        //! Provides functions to read and write segment registers.

        use core::arch::asm;

        use crate::gdt::segment_selector::SegmentSelector;

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
            asm!("
                 pushl {:e}
                 pushl 1f
                 lretl
                 1:",
                 in(reg) u32::from(sel.0));
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
            asm!("movw {:x}, %ss", in(reg) sel.0);
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
            asm!("movw {:x}, %ds", in(reg) sel.0);
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
            asm!("movw {:x}, %es", in(reg) sel.0);
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
            asm!("movw {:x}, %fs", in(reg) sel.0);
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
            asm!("movw {:x}, %gs", in(reg) sel.0);
        }

        /// Returns the current value of the code segment register.
        pub fn cs() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %cs, {:x}", out(reg) segment) };
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
        /// sections.
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

impl PrivilegeLevel {
    /// Creates a `PrivilegeLevel` from a numeric value. The value must be in the range 0..4.
    ///
    /// This function panics if the passed value is >3.
    pub fn from_u16(value: u16) -> PrivilegeLevel {
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
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TssStruct {
    _reserved1: u16,
    link: u16,
    esp0: u32,
    _reserved2: u16,
    ss0: u16,
    esp1: u32,
    _reserved3: u16,
    ss1: u16,
    esp2: u32,
    _reserved4: u16,
    ss2: u16,
    cr3: u32,
    eip: u32,
    eflags: u32,
    eax: u32,
    ecx: u32,
    edx: u32,
    ebx: u32,
    esp: u32,
    ebp: u32,
    esi: u32,
    edi: u32,
    _reserved5: u16,
    es: u16,
    _reserved6: u16,
    cs: u16,
    _reserved7: u16,
    ss: u16,
    _reserved8: u16,
    ds: u16,
    _reserved9: u16,
    fs: u16,
    _reserveda: u16,
    gs: u16,
    _reservedb: u16,
    ldt_selector: u16,
    iopboffset: u16,
    _reservedc: u16,
}

use crate::gdt::segment_selector::SegmentSelector;

impl TssStruct {
    pub fn new(cr3: u32, sp0: (SegmentSelector, usize), sp1: (SegmentSelector, usize), sp2: (SegmentSelector, usize), ldt: SegmentSelector) -> TssStruct {
        TssStruct {
            esp0: sp0.1 as u32,
            ss0: (sp0.0).0,
            esp1: sp1.1 as u32,
            ss1: (sp1.0).0,
            esp2: sp2.1 as u32,
            ss2: (sp2.0).0,
            cr3: cr3 as u32,
            ldt_selector: ldt.0,
            ..TssStruct::default()
        }
    }
}
