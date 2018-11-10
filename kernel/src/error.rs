//! UserspaceError and KernelError

use failure::Backtrace;

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
    #[doc(hidden)]
    #[fail(display = "Should never ever ***EVER*** be returned")]
    ThisWillNeverHappenButPleaseDontMatchExhaustively,
}

impl From<KernelError> for UserspaceError {
    fn from(err: KernelError) -> UserspaceError {
        match err {
            KernelError::PhysicalMemoryExhaustion { .. } => UserspaceError::MemoryFull,
            KernelError::VirtualMemoryExhaustion { .. } => UserspaceError::MemoryFull,
            KernelError::ThisWillNeverHappenButPleaseDontMatchExhaustively => unreachable!()
        }
    }
}
