//! i386 registers reading

#![allow(unused_macros)]
#![allow(dead_code)]

use core::arch::asm;

/// Gets the current $eip.
#[inline(never)]
pub extern fn eip() -> usize {
    let eip;
    unsafe { asm!("mov {}, [ebp + 4]", out(reg) eip); }
    eip
}

/// Gets the current $ebp.
macro_rules! ebp {
    () => {{
        let ebp;
        unsafe { asm!("mov {}, ebp", out(reg) ebp); }
        ebp
    }}
}

/// Gets the current $esp.
macro_rules! esp {
    () => {{
        let esp;
        unsafe { asm!("mov {}, esp", out(reg) esp); }
        esp
    }}
}

pub mod eflags {
    //! Processor state stored in the EFLAGS register.

    use core::arch::asm;

    bitflags! {
        /// The EFLAGS register.
        pub struct EFlags: u32 {
            /// Processor feature identification flag.
            ///
            /// If this flag is modifiable, the CPU supports CPUID.
            const ID = 1 << 21;
            /// Indicates that an external, maskable interrupt is pending.
            ///
            /// Used when virtual-8086 mode extensions (CR4.VME) or protected-mode virtual
            /// interrupts (CR4.PVI) are activated.
            const VIRTUAL_INTERRUPT_PENDING = 1 << 20;
            /// Virtual image of the INTERRUPT_FLAG bit.
            ///
            /// Used when virtual-8086 mode extensions (CR4.VME) or protected-mode virtual
            /// interrupts (CR4.PVI) are activated.
            const VIRTUAL_INTERRUPT = 1 << 19;
            /// Enable automatic alignment checking if CR0.AM is set. Only works if CPL is 3.
            const ALIGNMENT_CHECK = 1 << 18;
            /// Enable the virtual-8086 mode.
            const VIRTUAL_8086_MODE = 1 << 17;
            /// Allows to restart an instruction following an instrucion breakpoint.
            const RESUME_FLAG = 1 << 16;
            /// Used by `iret` in hardware task switch mode to determine if current task is nested.
            const NESTED_TASK = 1 << 14;
            /// The high bit of the I/O Privilege Level field.
            ///
            /// Specifies the privilege level required for executing I/O address-space instructions.
            const IOPL_HIGH = 1 << 13;
            /// The low bit of the I/O Privilege Level field.
            ///
            /// Specifies the privilege level required for executing I/O address-space instructions.
            const IOPL_LOW = 1 << 12;
            /// Set by hardware to indicate that the sign bit of the result of the last signed integer
            /// operation differs from the source operands.
            const OVERFLOW_FLAG = 1 << 11;
            /// Determines the order in which strings are processed.
            const DIRECTION_FLAG = 1 << 10;
            /// Enable interrupts.
            const INTERRUPT_FLAG = 1 << 9;
            /// Enable single-step mode for debugging.
            const TRAP_FLAG = 1 << 8;
            /// Set by hardware if last arithmetic operation resulted in a negative value.
            const SIGN_FLAG = 1 << 7;
            /// Set by hardware if last arithmetic operation resulted in a zero value.
            const ZERO_FLAG = 1 << 6;
            /// Set by hardware if last arithmetic operation generated a carry ouf of bit 3 of the
            /// result.
            const AUXILIARY_CARRY_FLAG = 1 << 4;
            /// Set by hardware if last result has an even number of 1 bits (only for some operations).
            const PARITY_FLAG = 1 << 2;
            /// Set by hardware if last arithmetic operation generated a carry out of the
            /// most-significant bit of the result.
            const CARRY_FLAG = 1 << 0;
        }
    }

    /// Returns the current value of the EFLAGS register.
    ///
    /// Drops any unknown bits.
    pub fn read() -> EFlags {
        EFlags::from_bits_truncate(read_raw())
    }

    /// Returns the raw current value of the EFLAGS register.
    pub fn read_raw() -> u32 {
        let r: u32;
        unsafe { asm!("pushfd; pop {}", out(reg) r) };
        r
    }

    /// Writes the EFLAGS register, preserves reserved bits.
    pub fn write(flags: EFlags) {
        let old_value = read_raw();
        let reserved = old_value & !(EFlags::all().bits());
        let new_value = reserved | flags.bits();

        write_raw(new_value);
    }

    /// Writes the EFLAGS register.
    ///
    /// Does not preserve any bits, including reserved bits.
    pub fn write_raw(val: u32) {
        unsafe { asm!("pushd {}; popfd", in(reg) val) };
    }
}
