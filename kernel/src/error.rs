//! UserspaceError and KernelError

use failure::Backtrace;
use paging::error::MmError;
use mem::VirtualAddress;
use core::fmt::{self, Display};

#[derive(Debug, Clone, Copy)]
pub enum UserspaceError {
    InvalidKernelCaps = 14,
    NotDebugMode = 33,
    InvalidSize = 101,
    InvalidAddress = 102,
    // SlabheapFull = 103,
    MemoryFull = 104,
    HandleTableFull = 105,
    // InvalidMemState = 106,
    // InvalidMemPerms = 108,
    // InvalidMemRange = 110,
    // InvalidThreadPrio = 112,
    // InvalidProcId = 113,
    InvalidHandle = 114,
    CopyFromUserFailed = 115,
    InvalidCombination = 116,
    Timeout = 117,
    Canceled = 118,
    ExceedingMaximum = 119,
    // InvalidEnum = 120,
    NoSuchEntry = 121,
    // AlreadyRegistered = 122,
    PortRemoteDead = 123,
    // UnhandledInterrupt = 124,
    ProcessAlreadyStarted = 125,
    // ReservedValue = 126,
    // InvalidHardwareBreakpoint = 127,
    // FatalException = 128,
    // LastThreadNotYours = 129,
    // PortMaxSessions = 131,
    // ResourceLimitExceeded = 132,
    // CommandBufferTooSmall = 260,
    // ProcessNotBeingDebugged = 520
}

impl UserspaceError {
    pub fn make_ret(self) -> usize {
        ((self as usize) << 9) | 1
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ArithmeticOperation { Add, Sub, Mul, Div, Mod, Pow }

impl Display for ArithmeticOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ArithmeticOperation::Add => write!(f, "+"),
            ArithmeticOperation::Sub => write!(f, "-"),
            ArithmeticOperation::Mul => write!(f, "*"),
            ArithmeticOperation::Div => write!(f, "/"),
            ArithmeticOperation::Mod => write!(f, "%"),
            ArithmeticOperation::Pow => write!(f, "**"),
        }
    }
}

#[derive(Debug, Fail)]
pub enum KernelError {
    #[fail(display = "Frame allocation error: physical address space exhausted")]
    PhysicalMemoryExhaustion {
        backtrace: Backtrace
    },
    #[fail(display = "Virtual allocation error: virtual address space exhausted")]
    VirtualMemoryExhaustion {
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid address: virtual address {} len {} is considered invalid", address, length)]
    InvalidAddress {
        address: VirtualAddress,
        length: usize,
        backtrace: Backtrace,
    },
    #[fail(display = "Alignment error: expected alignment {}, got {}", needed, given)]
    AlignmentError {
        given: usize,
        needed: usize,
        backtrace: Backtrace,
    },
    #[fail(display = "Arithmetic error: {} {} {} would cause an overflow", lhs, operation, rhs)]
    WouldOverflow {
        lhs: usize,
        rhs: usize,
        operation: ArithmeticOperation,
        backtrace: Backtrace,
    },
    #[fail(display = "Length error: length is 0")]
    ZeroLengthError {
        backtrace: Backtrace,
    },
    #[fail(display = "Memory management error: {}", _0)]
    MmError(MmError),
    #[fail(display = "Process was killed before finishing operation")]
    ProcessKilled {
        backtrace: Backtrace,
    },
    #[doc(hidden)]
    #[fail(display = "Should never ever ***EVER*** be returned")]
    ThisWillNeverHappenButPleaseDontMatchExhaustively,
}

impl From<KernelError> for UserspaceError {
    fn from(err: KernelError) -> UserspaceError {
        match err {
            KernelError::PhysicalMemoryExhaustion { .. } => UserspaceError::MemoryFull,
            KernelError::VirtualMemoryExhaustion { .. } => UserspaceError::MemoryFull,
            //KernelError::
            KernelError::ThisWillNeverHappenButPleaseDontMatchExhaustively => unreachable!(),
            // todo
            _ => unimplemented!("Unmatched Error: {}", err)
        }
    }
}

