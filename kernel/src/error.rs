pub enum Error {
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
    // ExceedingMaximum = 119,
    // InvalidEnum = 120,
    // NoSuchEntry = 121,
    // AlreadyRegistered = 122,
    // PortRemoteDead = 123,
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

impl Error {
    pub fn make_ret(self) -> usize {
        ((self as usize) << 9) | 1
    }
}
