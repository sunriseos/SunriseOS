// Copyright 2017 Philipp Oppermann. See the README.md
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides types for the Interrupt Descriptor Table and its entries.

use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ops::{Index, IndexMut};
use bit_field::BitField;
use crate::i386::PrivilegeLevel;
use crate::mem::VirtualAddress;
use crate::i386::structures::gdt::SegmentSelector;

/// An Interrupt Descriptor Table with 256 entries.
///
/// The field descriptions are taken from the
/// [AMD64 manual volume 2](https://support.amd.com/TechDocs/24593.pdf)
/// (with slight modifications).
#[repr(C)]
pub struct Idt {
    /// A divide by zero exception (`#DE`) occurs when the denominator of a DIV instruction or
    /// an IDIV instruction is 0. A `#DE` also occurs if the result is too large to be
    /// represented in the destination.
    ///
    /// The saved instruction pointer points to the instruction that caused the `#DE`.
    ///
    /// The vector number of the `#DE` exception is 0.
    pub divide_by_zero: IdtEntry<HandlerFunc>,

    /// When the debug-exception mechanism is enabled, a `#DB` exception can occur under any
    /// of the following circumstances:
    ///
    /// <details>
    ///
    /// - Instruction execution.
    /// - Instruction single stepping.
    /// - Data read.
    /// - Data write.
    /// - I/O read.
    /// - I/O write.
    /// - Task switch.
    /// - Debug-register access, or general detect fault (debug register access when DR7.GD=1).
    /// - Executing the INT1 instruction (opcode 0F1h).
    ///
    /// </details>
    ///
    /// `#DB` conditions are enabled and disabled using the debug-control register, `DR7`
    /// and `RFLAGS.TF`.
    ///
    /// In the following cases, the saved instruction pointer points to the instruction that
    /// caused the `#DB`:
    ///
    /// - Instruction execution.
    /// - Invalid debug-register access, or general detect.
    ///
    /// In all other cases, the instruction that caused the `#DB` is completed, and the saved
    /// instruction pointer points to the instruction after the one that caused the `#DB`.
    ///
    /// The vector number of the `#DB` exception is 1.
    pub debug: IdtEntry<HandlerFunc>,

    /// An non maskable interrupt exception (NMI) occurs as a result of system logic
    /// signaling a non-maskable interrupt to the processor.
    ///
    /// The processor recognizes an NMI at an instruction boundary.
    /// The saved instruction pointer points to the instruction immediately following the
    /// boundary where the NMI was recognized.
    ///
    /// The vector number of the NMI exception is 2.
    pub non_maskable_interrupt: IdtEntry<HandlerFunc>,

    /// A breakpoint (`#BP`) exception occurs when an `INT3` instruction is executed. The
    /// `INT3` is normally used by debug software to set instruction breakpoints by replacing
    ///
    /// The saved instruction pointer points to the byte after the `INT3` instruction.
    ///
    /// The vector number of the `#BP` exception is 3.
    pub breakpoint: IdtEntry<HandlerFunc>,

    /// An overflow exception (`#OF`) occurs as a result of executing an `INTO` instruction
    /// while the overflow bit in `RFLAGS` is set to 1.
    ///
    /// The saved instruction pointer points to the instruction following the `INTO`
    /// instruction that caused the `#OF`.
    ///
    /// The vector number of the `#OF` exception is 4.
    pub overflow: IdtEntry<HandlerFunc>,

    /// A bound-range exception (`#BR`) exception can occur as a result of executing
    /// the `BOUND` instruction. The `BOUND` instruction compares an array index (first
    /// operand) with the lower bounds and upper bounds of an array (second operand).
    /// If the array index is not within the array boundary, the `#BR` occurs.
    ///
    /// The saved instruction pointer points to the `BOUND` instruction that caused the `#BR`.
    ///
    /// The vector number of the `#BR` exception is 5.
    pub bound_range_exceeded: IdtEntry<HandlerFunc>,

    /// An invalid opcode exception (`#UD`) occurs when an attempt is made to execute an
    /// invalid or undefined opcode. The validity of an opcode often depends on the
    /// processor operating mode.
    ///
    /// <details><summary>A `#UD` occurs under the following conditions:</summary>
    ///
    /// - Execution of any reserved or undefined opcode in any mode.
    /// - Execution of the `UD2` instruction.
    /// - Use of the `LOCK` prefix on an instruction that cannot be locked.
    /// - Use of the `LOCK` prefix on a lockable instruction with a non-memory target location.
    /// - Execution of an instruction with an invalid-operand type.
    /// - Execution of the `SYSENTER` or `SYSEXIT` instructions in long mode.
    /// - Execution of any of the following instructions in 64-bit mode: `AAA`, `AAD`,
    ///   `AAM`, `AAS`, `BOUND`, `CALL` (opcode 9A), `DAA`, `DAS`, `DEC`, `INC`, `INTO`,
    ///   `JMP` (opcode EA), `LDS`, `LES`, `POP` (`DS`, `ES`, `SS`), `POPA`, `PUSH` (`CS`,
    ///   `DS`, `ES`, `SS`), `PUSHA`, `SALC`.
    /// - Execution of the `ARPL`, `LAR`, `LLDT`, `LSL`, `LTR`, `SLDT`, `STR`, `VERR`, or
    ///   `VERW` instructions when protected mode is not enabled, or when virtual-8086 mode
    ///   is enabled.
    /// - Execution of any legacy SSE instruction when `CR4.OSFXSR` is cleared to 0.
    /// - Execution of any SSE instruction (uses `YMM`/`XMM` registers), or 64-bit media
    /// instruction (uses `MMXTM` registers) when `CR0.EM` = 1.
    /// - Execution of any SSE floating-point instruction (uses `YMM`/`XMM` registers) that
    /// causes a numeric exception when `CR4.OSXMMEXCPT` = 0.
    /// - Use of the `DR4` or `DR5` debug registers when `CR4.DE` = 1.
    /// - Execution of `RSM` when not in `SMM` mode.
    ///
    /// </details>
    ///
    /// The saved instruction pointer points to the instruction that caused the `#UD`.
    ///
    /// The vector number of the `#UD` exception is 6.
    pub invalid_opcode: IdtEntry<HandlerFunc>,

    /// A device not available exception (`#NM`) occurs under any of the following conditions:
    ///
    /// <details>
    ///
    /// - An `FWAIT`/`WAIT` instruction is executed when `CR0.MP=1` and `CR0.TS=1`.
    /// - Any x87 instruction other than `FWAIT` is executed when `CR0.EM=1`.
    /// - Any x87 instruction is executed when `CR0.TS=1`. The `CR0.MP` bit controls whether the
    ///   `FWAIT`/`WAIT` instruction causes an `#NM` exception when `TS=1`.
    /// - Any 128-bit or 64-bit media instruction when `CR0.TS=1`.
    ///
    /// </details>
    ///
    /// The saved instruction pointer points to the instruction that caused the `#NM`.
    ///
    /// The vector number of the `#NM` exception is 7.
    pub device_not_available: IdtEntry<HandlerFunc>,

    /// A double fault (`#DF`) exception can occur when a second exception occurs during
    /// the handling of a prior (first) exception or interrupt handler.
    ///
    /// <details>
    ///
    /// Usually, the first and second exceptions can be handled sequentially without
    /// resulting in a `#DF`. In this case, the first exception is considered _benign_, as
    /// it does not harm the ability of the processor to handle the second exception. In some
    /// cases, however, the first exception adversely affects the ability of the processor to
    /// handle the second exception. These exceptions contribute to the occurrence of a `#DF`,
    /// and are called _contributory exceptions_. The following exceptions are contributory:
    ///
    /// - Invalid-TSS Exception
    /// - Segment-Not-Present Exception
    /// - Stack Exception
    /// - General-Protection Exception
    ///
    /// A double-fault exception occurs in the following cases:
    ///
    /// - If a contributory exception is followed by another contributory exception.
    /// - If a divide-by-zero exception is followed by a contributory exception.
    /// - If a page  fault is followed by another page fault or a contributory exception.
    ///
    /// If a third interrupting event occurs while transferring control to the `#DF` handler,
    /// the processor shuts down.
    ///
    /// </details>
    ///
    /// The returned error code is always zero. The saved instruction pointer is undefined,
    /// and the program cannot be restarted.
    ///
    /// The vector number of the `#DF` exception is 8.
    pub double_fault: IdtEntry<HandlerFuncWithErrCode>,

    /// This interrupt vector is reserved. It is for a discontinued exception originally used
    /// by processors that supported external x87-instruction coprocessors. On those processors,
    /// the exception condition is caused by an invalid-segment or invalid-page access on an
    /// x87-instruction coprocessor-instruction operand. On current processors, this condition
    /// causes a general-protection exception to occur.
    coprocessor_segment_overrun: IdtEntry<HandlerFunc>,

    /// An invalid TSS exception (`#TS`) occurs only as a result of a control transfer through
    /// a gate descriptor that results in an invalid stack-segment reference using an `SS`
    /// selector in the TSS.
    ///
    /// The returned error code is the `SS` segment selector. The saved instruction pointer
    /// points to the control-transfer instruction that caused the `#TS`.
    ///
    /// The vector number of the `#DF` exception is 10.
    pub invalid_tss: IdtEntry<HandlerFuncWithErrCode>,

    /// An segment-not-present exception (`#NP`) occurs when an attempt is made to load a
    /// segment or gate with a clear present bit.
    ///
    /// The returned error code is the segment-selector index of the segment descriptor
    /// causing the `#NP` exception. The saved instruction pointer points to the instruction
    /// that loaded the segment selector resulting in the `#NP`.
    ///
    /// The vector number of the `#NP` exception is 11.
    pub segment_not_present: IdtEntry<HandlerFuncWithErrCode>,

    /// An stack segment exception (`#SS`) can occur in the following situations:
    ///
    /// - Implied stack references in which the stack address is not in canonical
    ///   form. Implied stack references include all push and pop instructions, and any
    ///   instruction using `RSP` or `RBP` as a base register.
    /// - Attempting to load a stack-segment selector that references a segment descriptor
    ///   containing a clear present bit.
    /// - Any stack access that fails the stack-limit check.
    ///
    /// The returned error code depends on the cause of the `#SS`. If the cause is a cleared
    /// present bit, the error code is the corresponding segment selector. Otherwise, the
    /// error code is zero. The saved instruction pointer points to the instruction that
    /// caused the `#SS`.
    ///
    /// The vector number of the `#NP` exception is 12.
    pub stack_segment_fault: IdtEntry<HandlerFuncWithErrCode>,

    /// A general protection fault (`#GP`) can occur in various situations. Common causes include:
    ///
    /// - Executing a privileged instruction while `CPL > 0`.
    /// - Writing a 1 into any register field that is reserved, must be zero (MBZ).
    /// - Attempting to execute an SSE instruction specifying an unaligned memory operand.
    /// - Loading a non-canonical base address into the `GDTR` or `IDTR`.
    /// - Using WRMSR to write a read-only MSR.
    /// - Any long-mode consistency-check violation.
    ///
    /// The returned error code is a segment selector, if the cause of the `#GP` is
    /// segment-related, and zero otherwise. The saved instruction pointer points to
    /// the instruction that caused the `#GP`.
    ///
    /// The vector number of the `#GP` exception is 13.
    pub general_protection_fault: IdtEntry<HandlerFuncWithErrCode>,

    /// A page fault (`#PF`) can occur during a memory access in any of the following situations:
    ///
    /// - A page-translation-table entry or physical page involved in translating the memory
    ///   access is not present in physical memory. This is indicated by a cleared present
    ///   bit in the translation-table entry.
    /// - An attempt is made by the processor to load the instruction TLB with a translation
    ///   for a non-executable page.
    /// - The memory access fails the paging-protection checks (user/supervisor, read/write,
    ///   or both).
    /// - A reserved bit in one of the page-translation-table entries is set to 1. A `#PF`
    ///   occurs for this reason only when `CR4.PSE=1` or `CR4.PAE=1`.
    ///
    /// The virtual (linear) address that caused the `#PF` is stored in the `CR2` register.
    /// The saved instruction pointer points to the instruction that caused the `#PF`.
    ///
    /// The page-fault error code is described by the
    /// [`PageFaultErrorCode`](struct.PageFaultErrorCode.html) struct.
    ///
    /// The vector number of the `#PF` exception is 14.
    pub page_fault: IdtEntry<PageFaultHandlerFunc>,

    /// vector nr. 15
    reserved_1: IdtEntry<HandlerFunc>,

    /// The x87 Floating-Point Exception-Pending exception (`#MF`) is used to handle unmasked x87
    /// floating-point exceptions. In 64-bit mode, the x87 floating point unit is not used
    /// anymore, so this exception is only relevant when executing programs in the 32-bit
    /// compatibility mode.
    ///
    /// The vector number of the `#MF` exception is 16.
    pub x87_floating_point: IdtEntry<HandlerFunc>,

    /// An alignment check exception (`#AC`) occurs when an unaligned-memory data reference
    /// is performed while alignment checking is enabled. An `#AC` can occur only when CPL=3.
    ///
    /// The returned error code is always zero. The saved instruction pointer points to the
    /// instruction that caused the `#AC`.
    ///
    /// The vector number of the `#AC` exception is 17.
    pub alignment_check: IdtEntry<HandlerFuncWithErrCode>,

    /// The machine check exception (`#MC`) is model specific. Processor implementations
    /// are not required to support the `#MC` exception, and those implementations that do
    /// support `#MC` can vary in how the `#MC` exception mechanism works.
    ///
    /// There is no reliable way to restart the program.
    ///
    /// The vector number of the `#MC` exception is 18.
    pub machine_check: IdtEntry<HandlerFunc>,

    /// The SIMD Floating-Point Exception (`#XF`) is used to handle unmasked SSE
    /// floating-point exceptions. The SSE floating-point exceptions reported by
    /// the `#XF` exception are (including mnemonics):
    ///
    /// - IE: Invalid-operation exception (also called #I).
    /// - DE: Denormalized-operand exception (also called #D).
    /// - ZE: Zero-divide exception (also called #Z).
    /// - OE: Overflow exception (also called #O).
    /// - UE: Underflow exception (also called #U).
    /// - PE: Precision exception (also called #P or inexact-result exception).
    ///
    /// The saved instruction pointer points to the instruction that caused the `#XF`.
    ///
    /// The vector number of the `#XF` exception is 19.
    pub simd_floating_point: IdtEntry<HandlerFunc>,

    /// vector nr. 20
    pub virtualization: IdtEntry<HandlerFunc>,

    /// vector nr. 21-29
    reserved_2: [IdtEntry<HandlerFunc>; 9],

    /// The Security Exception (`#SX`) signals security-sensitive events that occur while
    /// executing the VMM, in the form of an exception so that the VMM may take appropriate
    /// action. (A VMM would typically intercept comparable sensitive events in the guest.)
    /// In the current implementation, the only use of the `#SX` is to redirect external INITs
    /// into an exception so that the VMM may — among other possibilities.
    ///
    /// The only error code currently defined is 1, and indicates redirection of INIT has occurred.
    ///
    /// The vector number of the ``#SX`` exception is 30.
    pub security_exception: IdtEntry<HandlerFuncWithErrCode>,

    /// vector nr. 31
    reserved_3: IdtEntry<HandlerFunc>,

    /// User-defined interrupts can be initiated either by system logic or software. They occur
    /// when:
    ///
    /// - System logic signals an external interrupt request to the processor. The signaling
    ///   mechanism and the method of communicating the interrupt vector to the processor are
    ///   implementation dependent.
    /// - Software executes an `INTn` instruction. The `INTn` instruction operand provides
    ///   the interrupt vector number.
    ///
    /// Both methods can be used to initiate an interrupt into vectors 0 through 255. However,
    /// because vectors 0 through 31 are defined or reserved by the AMD64 architecture,
    /// software should not use vectors in this range for purposes other than their defined use.
    ///
    /// The saved instruction pointer depends on the interrupt source:
    ///
    /// - External interrupts are recognized on instruction boundaries. The saved instruction
    ///   pointer points to the instruction immediately following the boundary where the
    ///   external interrupt was recognized.
    /// - If the interrupt occurs as a result of executing the INTn instruction, the saved
    ///   instruction pointer points to the instruction after the INTn.
    pub interrupts: [IdtEntry<HandlerFunc>; 256 - 32],
}

impl fmt::Debug for Idt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Idt")
            .field("divide_by_zero", &self.divide_by_zero)
            .field("debug", &self.debug)
            .field("non_maskable_interrupt", &self.non_maskable_interrupt)
            .field("breakpoint", &self.breakpoint)
            .field("overflow", &self.overflow)
            .field("bound_range_exceeded", &self.bound_range_exceeded)
            .field("invalid_opcode", &self.invalid_opcode)
            .field("device_not_available", &self.device_not_available)
            .field("double_fault", &self.double_fault)
            .field("coprocessor_segment_overrun", &self.coprocessor_segment_overrun)
            .field("invalid_tss", &self.invalid_tss)
            .field("segment_not_present", &self.segment_not_present)
            .field("stack_segment_fault", &self.stack_segment_fault)
            .field("general_protection_fault", &self.general_protection_fault)
            .field("page_fault", &self.page_fault)
            .field("reserved_1", &self.reserved_1)
            .field("x87_floating_point", &self.x87_floating_point)
            .field("alignment_check", &self.alignment_check)
            .field("machine_check", &self.machine_check)
            .field("simd_floating_point", &self.simd_floating_point)
            .field("virtualization", &self.virtualization)
            .field("reserved_2", &self.reserved_2)
            .field("security_exception", &self.security_exception)
            .field("reserved_3", &self.reserved_3)
            .field("interrupts", &&self.interrupts[..])
            .finish()
    }
}

const_assert_eq!(mem::size_of::<Idt>(), 256 * 8);


impl Idt {
    /// Creates a new IDT filled with non-present entries.
    pub fn init(&mut self) {
        self.divide_by_zero = IdtEntry::missing();
        self.debug = IdtEntry::missing();
        self.non_maskable_interrupt = IdtEntry::missing();
        self.breakpoint = IdtEntry::missing();
        self.overflow = IdtEntry::missing();
        self.bound_range_exceeded = IdtEntry::missing();
        self.invalid_opcode = IdtEntry::missing();
        self.device_not_available = IdtEntry::missing();
        self.double_fault = IdtEntry::missing();
        self.coprocessor_segment_overrun = IdtEntry::missing();
        self.invalid_tss = IdtEntry::missing();
        self.segment_not_present = IdtEntry::missing();
        self.stack_segment_fault = IdtEntry::missing();
        self.general_protection_fault = IdtEntry::missing();
        self.page_fault = IdtEntry::missing();
        self.reserved_1 = IdtEntry::missing();
        self.x87_floating_point = IdtEntry::missing();
        self.alignment_check = IdtEntry::missing();
        self.machine_check = IdtEntry::missing();
        self.simd_floating_point = IdtEntry::missing();
        self.virtualization = IdtEntry::missing();
        self.reserved_2 = [IdtEntry::missing(); 9];
        self.security_exception = IdtEntry::missing();
        self.reserved_3 = IdtEntry::missing();
        self.interrupts = [IdtEntry::missing(); 256 - 32];
    }

    /// Loads the IDT in the CPU using the `lidt` command.
    pub fn load(&'static self) {
        use crate::i386::instructions::tables::{lidt, DescriptorTablePointer};
        use core::mem::size_of;

        let ptr = DescriptorTablePointer {
            base: self as *const _ as u32,
            limit: (size_of::<Self>() - 1) as u16,
        };

        unsafe { lidt(ptr) };
    }
}

impl Index<usize> for Idt {
    type Output = IdtEntry<HandlerFunc>;
    fn index(&self, index: usize) -> &Self::Output {
        match index {
            0 => &self.divide_by_zero,
            1 => &self.debug,
            2 => &self.non_maskable_interrupt,
            3 => &self.breakpoint,
            4 => &self.overflow,
            5 => &self.bound_range_exceeded,
            6 => &self.invalid_opcode,
            7 => &self.device_not_available,
            9 => &self.coprocessor_segment_overrun,
            16 => &self.x87_floating_point,
            18 => &self.machine_check,
            19 => &self.simd_floating_point,
            20 => &self.virtualization,
            i @ 32..=255 => &self.interrupts[i - 32],
            i @ 15 | i @ 31 | i @ 21..=29 => panic!("entry {} is reserved", i),
            i @ 8 | i @ 10..=14 | i @ 17 | i @ 30 => {
                panic!("entry {} is an exception with error code", i)
            }
            i => panic!("no entry with index {}", i),
        }
    }
}

impl IndexMut<usize> for Idt {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        match index {
            0 => &mut self.divide_by_zero,
            1 => &mut self.debug,
            2 => &mut self.non_maskable_interrupt,
            3 => &mut self.breakpoint,
            4 => &mut self.overflow,
            5 => &mut self.bound_range_exceeded,
            6 => &mut self.invalid_opcode,
            7 => &mut self.device_not_available,
            9 => &mut self.coprocessor_segment_overrun,
            16 => &mut self.x87_floating_point,
            18 => &mut self.machine_check,
            19 => &mut self.simd_floating_point,
            20 => &mut self.virtualization,
            i @ 32..=255 => &mut self.interrupts[i - 32],
            i @ 15 | i @ 31 | i @ 21..=29 => panic!("entry {} is reserved", i),
            i @ 8 | i @ 10..=14 | i @ 17 | i @ 30 => {
                panic!("entry {} is an exception with error code", i)
            }
            i => panic!("no entry with index {}", i),
        }
    }
}

/// An Interrupt Descriptor Table entry.
///
/// The generic parameter can either be `HandlerFunc` or `HandlerFuncWithErrCode`, depending
/// on the interrupt vector.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct IdtEntry<F> {
    /// Low word of the interrupt handler's virtual address. In an interrupt/trap
    /// gate, the processor will far jump to this pointer when the interrupt
    /// occurs. It is unused for task gates.
    pointer_low: u16,
    /// A segment selector.
    ///
    /// - For interrupt/trap gates, the selector will be used when far jumping to
    ///   the handler. It should be a selector to a code segment.
    /// - For task gates, the selector will be used to perform hardware task
    ///   switching. It should be a selector to a TSS segment.
    gdt_selector: SegmentSelector,
    /// Unused.
    zero: u8,
    /// Option bitfield.
    options: EntryOptions,
    /// High word of the interrupt handler's virtual address.
    pointer_high: u16,
    /// Type-safety guarantee: ensure that the function handler has the correct
    /// amount of arguments, return types, etc...
    phantom: PhantomData<F>,
}

impl<F> fmt::Debug for IdtEntry<F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !self.options.is_present() {
            write!(f, "IdtEntry::NotPresent")
        } else {
            let name = match self.options.gate_type() {
                GateType::TaskGate32 => "IdtEntry::TaskGate32",
                GateType::InterruptGate16 => "IdtEntry::InterruptGate16",
                GateType::TrapGate16 => "IdtEntry::TrapGate16",
                GateType::InterruptGate32 => "IdtEntry::InterruptGate32",
                GateType::TrapGate32 => "IdtEntry::TrapGate32",
            };
            let pointer = (u32::from(self.pointer_high) << 16) | u32::from(self.pointer_low);
            let pointer = VirtualAddress(pointer as usize);
            f.debug_struct(name)
                .field("pointer", &pointer)
                .field("gdt_selector", &self.gdt_selector)
                .field("privilege_level", &self.options.privilege_level())
                .finish()
        }
    }
}

const_assert_eq!(mem::size_of::<IdtEntry<()>>(), 8);

/// A handler function for an interrupt or an exception without error code.
pub type HandlerFunc = fn();
/// A handler function for an exception that pushes an error code.
pub type HandlerFuncWithErrCode = fn(error_code: u32);
/// A page fault handler function that pushes a page fault error code.
pub type PageFaultHandlerFunc = fn(error_code: u32);

impl<F> IdtEntry<F> {
    /// Creates a non-present IDT entry (but sets the must-be-one bits).
    fn missing() -> Self {
        IdtEntry {
            gdt_selector: SegmentSelector(0),
            pointer_low: 0,
            pointer_high: 0,
            zero: 0,
            options: EntryOptions::minimal(),
            phantom: PhantomData,
        }
    }

    /// Set an interrupt gate function for the IDT entry and sets the present bit.
    ///
    /// For the code selector field, this function uses the code segment selector currently
    /// active in the CPU.
    ///
    /// The function returns a mutable reference to the entry's options that allows
    /// further customization.
    pub unsafe fn set_interrupt_gate_addr(&mut self, addr: u32) -> &mut EntryOptions {
        use crate::i386::instructions::segmentation;

        self.pointer_low = addr as u16;
        self.pointer_high = (addr >> 16) as u16;

        self.gdt_selector = segmentation::cs();

        self.options.set_present_interrupt(true);
        &mut self.options
    }

    /// Set a task gate for the IDT entry and sets the present bit.
    ///
    /// # Safety
    ///
    /// `tss_selector` must point to a valid TSS, which will remain present.
    /// The TSS' `eip` should point to the handler function.
    /// The TSS' `esp` and `esp0` should point to a usable stack for the handler function.
    pub unsafe fn set_handler_task_gate(&mut self, tss_selector: SegmentSelector) {

        self.pointer_low = 0;
        self.pointer_high = 0;
        self.gdt_selector = tss_selector;
        self.options.set_present_task(true);
    }
}

impl<T> IdtEntry<T> {
    /// Set an interrupt gate function for the IDT entry and sets the present bit.
    ///
    /// For the code selector field, this function uses the code segment selector currently
    /// active in the CPU.
    ///
    /// The function returns a mutable reference to the entry's options that allows
    /// further customization.
    #[allow(clippy::fn_to_numeric_cast)] // it **is** a u32
    pub fn set_handler_fn(&mut self, handler_asm_wrapper: extern "C" fn()) -> &mut EntryOptions {
        unsafe {
            self.set_interrupt_gate_addr(handler_asm_wrapper as u32)
        }
    }
}

/// Represents the type of an IDT descriptor (called a gate).
///
/// Technically, this represents a subset of [SystemDescriptorTypes].
///
/// [SystemDescriptorTypes]: crate::i386::gdt::SystemDescriptorTypes
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
#[allow(clippy::missing_docs_in_private_items)]
enum GateType {
    TaskGate32 = 0b0101,
    InterruptGate16 = 0b0110,
    TrapGate16 = 0b0111,
    InterruptGate32 = 0b1110,
    TrapGate32 = 0b1111,
}

impl From<u8> for GateType {
    fn from(ty: u8) -> GateType {
        match ty {
            0b0101 => GateType::TaskGate32,
            0b0110 => GateType::InterruptGate16,
            0b0111 => GateType::TrapGate16,
            0b1110 => GateType::InterruptGate32,
            0b1111 => GateType::TrapGate32,
            _ => panic!("Invalid gate type {}", ty),
        }
    }
}

bitfield! {
    #[derive(Clone, Copy)]
    /// Represents the options field of an IDT entry.
    pub struct EntryOptions(u8);
    impl Debug;
    /// Type of the interrupt handler. Its value determines the mechanism used
    /// to trigger the handler.
    into GateType, gate_type, _: 3, 0;
    // Bit 4 is unused (0). OSDev lists it as "Storage Segment", but that name
    // comes up nowhere in the Intel documentation.
    into PrivilegeLevel, privilege_level, _: 6, 5;
    is_present, set_is_present: 7;
}

impl EntryOptions {
    /// Creates a minimal options field with all the must-be-one bits set.
    fn minimal() -> Self {
        let mut options = EntryOptions(0);
        options.set_gate_type(GateType::InterruptGate32);
        options
    }

    /// Set the kind of gate this IdtEntry represents.
    fn set_gate_type(&mut self, gate_type: GateType) -> &mut Self {
        self.0.set_bits(0..4, gate_type as u8);
        self
    }

    /// Set the required privilege level (DPL) for invoking the handler.
    /// If CPL < DPL, a general protection fault occurs.
    pub fn set_privilege_level(&mut self, privlvl: PrivilegeLevel) -> &mut Self {
        self.0.set_bits(5..7, privlvl as u8);
        self
    }

    /// Set or reset the preset bit.
    pub fn set_present_interrupt(&mut self, present: bool) -> &mut Self {
        self.0.set_bits(0..4, 0b1110); // 'must-be-one' bits
        self.0.set_bit(7, present);
        self
    }

    /// Set or reset the preset bit.
    pub fn set_present_task(&mut self, present: bool) -> &mut Self {
        self.0.set_bits(0..4, 0b0101); // 'must-be-one' bits
        self.0.set_bit(7, present);
        self
    }

    /// Let the CPU disable hardware interrupts when the handler is invoked. By default,
    /// interrupts are disabled on handler invocation.
    pub fn disable_interrupts(&mut self, disable: bool) -> &mut Self {
        self.0.set_bit(0, !disable);
        self
    }
}

/// Represents the exception stack frame pushed by the CPU on exception entry.
#[repr(C)]
pub struct ExceptionStackFrame {
    /// This value points to the instruction that should be executed when the interrupt
    /// handler returns. For most interrupts, this value points to the instruction immediately
    /// following the last executed instruction. However, for some exceptions (e.g., page faults),
    /// this value points to the faulting instruction, so that the instruction is restarted on
    /// return. See the documentation of the `Idt` fields for more details.
    pub instruction_pointer: VirtualAddress,
    /// The code segment selector, padded with zeros.
    pub code_segment: u32,
    /// The flags register before the interrupt handler was invoked.
    pub cpu_flags: u32,
    /// The stack pointer at the time of the interrupt.
    pub stack_pointer: VirtualAddress,
    /// The stack segment descriptor at the time of the interrupt (often zero in 64-bit mode).
    pub stack_segment: u32,
}

impl fmt::Debug for ExceptionStackFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[allow(clippy::missing_docs_in_private_items)]
        struct Hex(u32);
        impl fmt::Debug for Hex {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }

        let mut s = f.debug_struct("ExceptionStackFrame");
        s.field("instruction_pointer", &self.instruction_pointer);
        s.field("code_segment", &Hex(self.code_segment));
        s.field("cpu_flags", &Hex(self.cpu_flags));
        s.field("stack_pointer", &self.stack_pointer);
        s.field("stack_segment", &Hex(self.stack_segment));
        s.finish()
    }
}

bitflags! {
    /// Describes an page fault error code.
    pub struct PageFaultErrorCode: u32 {
        /// If this flag is set, the page fault was caused by a page-protection violation,
        /// else the page fault was caused by a not-present page.
        const PROTECTION_VIOLATION = 1 << 0;

        /// If this flag is set, the memory access that caused the page fault was a write.
        /// Else the access that caused the page fault is a memory read. This bit does not
        /// necessarily indicate the cause of the page fault was a read or write violation.
        const CAUSED_BY_WRITE = 1 << 1;

        /// If this flag is set, an access in user mode (CPL=3) caused the page fault. Else
        /// an access in supervisor mode (CPL=0, 1, or 2) caused the page fault. This bit
        /// does not necessarily indicate the cause of the page fault was a privilege violation.
        const USER_MODE = 1 << 2;

        /// If this flag is set, the page fault is a result of the processor reading a 1 from
        /// a reserved field within a page-translation-table entry.
        const MALFORMED_TABLE = 1 << 3;

        /// If this flag is set, it indicates that the access that caused the page fault was an
        /// instruction fetch.
        const INSTRUCTION_FETCH = 1 << 4;
    }
}
