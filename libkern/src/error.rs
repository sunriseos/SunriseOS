use core::fmt;

enum_with_val! {
    /// Kernel syscall error codes.
    ///
    /// When a syscall fails, it returns one of this values as a reason for the fail.
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[allow(missing_docs)]
    pub struct KernelError(u32) {
        InvalidKernelCaps = 14,
        NotImplemented = 33,
        InvalidSize = 101,
        InvalidAddress = 102,
        // SlabheapFull = 103,
        MemoryFull = 104,
        HandleTableFull = 105,
        // InvalidMemState = 106,
        InvalidMemPerms = 108,
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
}

impl KernelError {
    pub fn make_ret(self) -> usize {
        ((self.0 as usize) << 9) | 1
    }

    pub fn from_syscall_ret(err: u32) -> KernelError {
        KernelError(err >> 9)
    }

    pub fn from_description(err: u32) -> KernelError {
        KernelError(err)
    }

    pub fn description(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KernelError::InvalidKernelCaps => write!(f, "Invalid kernel capabilities. Check the format."),
            KernelError::NotImplemented => write!(f, "Method not implemented. Notify roblabla!"),
            KernelError::InvalidSize => write!(f, "Invalid size."),
            KernelError::InvalidAddress => write!(f, "Invalid address."),
            KernelError::MemoryFull => write!(f, "Memory full. Try to kill some processes and try again."),
            KernelError::HandleTableFull => write!(f, "Handle table full. You might want to bump your handle table size in the NPDM."),
            KernelError::InvalidMemPerms => write!(f, "Invalid memory permissions."),
            KernelError::InvalidHandle => write!(f, "Invalid handle. Either it does not exist, or the Handle is of the wrong type."),
            KernelError::CopyFromUserFailed => write!(f, "Copy from user failed. The pointer either does not point in userspace, or points to unmapped memory."),
            KernelError::InvalidCombination => write!(f, "Invalid combination."),
            KernelError::Timeout => write!(f, "Timeout exceeded."),
            KernelError::Canceled => write!(f, "Cancelled."),
            KernelError::ExceedingMaximum => write!(f, "Argument exceeded maximum possible value."),
            KernelError::NoSuchEntry => write!(f, "The entry does not exist."),
            KernelError::PortRemoteDead => write!(f, "Remote handle closed. Usually happens when an IPC got sent in the wrong format."),
            KernelError::ProcessAlreadyStarted => write!(f, "Process already started."),
            KernelError(err) => write!(f, "Unknown error: {}", err)
        }
    }
}
