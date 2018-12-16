//! This crate is x86_64's little brother. It provides i386 specific functions
//! and data structures, and access to various system registers.

#![cfg(any(target_arch = "x86", test))]
#![allow(dead_code)]

use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

#[macro_use]
pub mod registers;
pub mod stack;
pub mod pio;
pub mod multiboot;
pub mod structures;
pub mod process_switch;
pub mod gdt;

pub mod instructions {
    //! Low level functions for special i386 instructions.
    pub mod tables {
        //! Instructions for loading descriptor tables (GDT, IDT, etc.).

        use i386::structures::gdt::SegmentSelector;

        /// A struct describing a pointer to a descriptor table (GDT / IDT).
        /// This is in a format suitable for giving to 'lgdt' or 'lidt'.
        #[derive(Debug)]
        #[repr(C, packed)]
        pub struct DescriptorTablePointer {
            /// Size of the DT.
            pub limit: u16,
            /// Pointer to the memory region containing the DT.
            pub base: u32,
        }

        /// Load GDT table.
        pub unsafe fn lgdt(gdt: &DescriptorTablePointer) {
            asm!("lgdt ($0)" :: "r" (gdt) : "memory" : "volatile");
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
                asm!("sgdt $0" : "=*m"(&mut out) :: "memory" : "volatile");
                out
            }
        }


        /// Load LDT table.
        pub unsafe fn lldt(ldt: SegmentSelector) {
            asm!("lldt $0" :: "r" (ldt.0) : "memory");
        }

        // TODO: Goes somewhere else.
        /// Sets the task register to the given TSS segment.
        pub unsafe fn ltr(segment: SegmentSelector) {
            asm!("ltr $0" :: "r"(segment.0));
        }

        /// Load IDT table.
        pub unsafe fn lidt(idt: &DescriptorTablePointer) {
            asm!("lidt ($0)" :: "r" (idt) : "memory");
        }
    }

    pub mod segmentation {
        //! Provides functions to read and write segment registers.

        use i386::structures::gdt::SegmentSelector;

        /// Reload code segment register.
        /// Note this is special since we can not directly move
        /// to %cs. Instead we push the new segment selector
        /// and return value on the stack and use lretq
        /// to reload cs and continue at 1:.
        pub unsafe fn set_cs(sel: SegmentSelector) {
            asm!("pushl $0; \
                  pushl $$1f; \
                  lretl; \
                  1:" :: "ri" (u64::from(sel.0)) : "rax" "memory");
        }

        /// Reload stack segment register.
        pub unsafe fn load_ss(sel: SegmentSelector) {
            asm!("movw $0, %ss " :: "r" (sel.0) : "memory");
        }

        /// Reload data segment register.
        pub unsafe fn load_ds(sel: SegmentSelector) {
            asm!("movw $0, %ds " :: "r" (sel.0) : "memory");
        }

        /// Reload es segment register.
        pub unsafe fn load_es(sel: SegmentSelector) {
            asm!("movw $0, %es " :: "r" (sel.0) : "memory");
        }

        /// Reload fs segment register.
        pub unsafe fn load_fs(sel: SegmentSelector) {
            asm!("movw $0, %fs " :: "r" (sel.0) : "memory");
        }

        /// Reload gs segment register.
        pub unsafe fn load_gs(sel: SegmentSelector) {
            asm!("movw $0, %gs " :: "r" (sel.0) : "memory");
        }

        /// Returns the current value of the code segment register.
        pub fn cs() -> SegmentSelector {
            let segment: u16;
            unsafe { asm!("mov %cs, $0" : "=r" (segment) ) };
            SegmentSelector(segment)
        }
    }
    pub mod interrupts {
        //! Interrupt disabling functionality.

        /// Enable interrupts
        pub unsafe fn sti() {
            asm!("sti" :::: "volatile");
        }

        /// Disable interrupts
        pub unsafe fn cli() {
            asm!("cli" :::: "volatile");
        }

        /// Waits until an interrupt is fired
        pub unsafe fn hlt() {
            asm!("hlt" :::: "volatile");
        }

        /// Returns whether interrupts are enabled.
        pub fn are_enabled() -> bool {
            use i386::registers::eflags::{self, EFlags};

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
#[repr(C)]
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

impl Default for TssStruct {
    fn default() -> TssStruct {
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
            iopboffset: ::core::mem::size_of::<TssStruct>() as u16,
            _reservedc: 0,
        }
    }
}

const_assert_eq!(tss_struct_size; ::core::mem::size_of::<TssStruct>(), 0x68);

impl TssStruct {
    /// Creates a new TssStruct.
    ///
    /// The new struct inherits the current task's values (except registers, which are set to 0)
    pub fn new() -> TssStruct {
        let ds: u16;
        let cs: u16;
        let ss: u16;
        let cr3: u32;
        let ldt_selector: u16;

        unsafe {
            // Safety: this is perfectly safe. Maybe I should do safe wrappers for this however...
            asm!("
                 mov AX, DS
                 mov $0, AX
                 mov AX, CS
                 mov $1, AX
                 mov AX, SS
                 mov $2, AX
                 mov $3, CR3
                 sldt $4
             " : "=r"(ds), "=r"(cs), "=r"(ss), "=r"(cr3), "=r"(ldt_selector) :: "ax" : "intel");
        }

        TssStruct {
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
            ..Default::default()
        }
    }

    pub fn set_esp0_stack(&mut self, esp: u32) {
        self.esp0 = esp;
    }

    pub fn set_ip(&mut self, eip: u32) {
        self.eip = eip;
    }
}

/// Wrapper around TssStruct ensuring it is kept at the page boundary.
///
/// According to the IA32-E PDF, volume 3, 7.2.1:
///
/// If paging is used:
/// - Avoid placing a page boundary in the part of the TSS that the processor
///   reads during a task switch (the first 104 bytes). The processor may not
///   correctly perform address translations if a boundary occurs in this area.
///   During a task switch, the processor reads and writes into the first 104
///   bytes of each TSS (using contiguous physical addresses beginning with the
///   physical address of the first byte of the TSS). So, after TSS access
///   begins, if part of the 104 bytes is not physically contiguous, the
///   processor will access incorrect information without generating a
///   page-fault exception.
#[repr(C, align(4096))]
pub struct AlignedTssStruct(TssStruct);

impl AlignedTssStruct {
    /// Create a new AlignedTssStruct, using boxing to avoid putting a ridiculously large
    /// object (4kb) on the stack.
    pub fn new(tss: TssStruct) -> Box<AlignedTssStruct> {
        box AlignedTssStruct(tss)
    }
}

impl Deref for AlignedTssStruct {
    type Target = TssStruct;

    fn deref(&self) -> &TssStruct {
        &self.0
    }
}

impl DerefMut for AlignedTssStruct {
    fn deref_mut(&mut self) -> &mut TssStruct {
        &mut self.0
    }
}
