//! Kernel errors

use core::fmt;

enum_with_val! {
    /// Kernel syscall error codes.
    ///
    /// When a syscall fails, it returns one of this values as a reason for the fail.
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[allow(missing_docs)]
    pub struct KernelError(u32) {
        /// Kernel capabilities are invalid.
        InvalidKernelCaps = 14,
        /// This function is not implemented.
        NotImplemented = 33,
        /// The size argument is invalid.
        ///
        /// Generally means it's not properly aligned.
        InvalidSize = 101,
        /// The passed address is invalid.
        ///
        /// Generally means it is not page aligned.
        InvalidAddress = 102,
        // SlabheapFull = 103,
        /// The virtual address space was exhausted.
        MemoryFull = 104,
        /// The process' handle table is full.
        HandleTableFull = 105,
        /// The memory state is invalid for this action.
        InvalidMemState = 106,
        /// The memory permissions passed are wrong.
        InvalidMemPerms = 108,
        /// Memory range is not at an expected location.
        InvalidMemRange = 110,
        /// Invalid thread priority. Thread priority should be within the range
        /// 0..=0x3F, and should be allowed in the kernel capabilities.
        InvalidThreadPriority = 112,
        /// Invalid processor id. Processor ID should exist on the current
        /// machine and be allowed in the kernel capabilities.
        InvalidProcessorId = 113,
        /// Passed handle is invalid.
        ///
        /// Either the handle passed is of the wrong type, or the handle number
        /// wasn't valid at all.
        InvalidHandle = 114,
        /// Attempt to copy the userspace address failed.
        CopyFromUserFailed = 115,
        /// The combination of argument is invalid.
        InvalidCombination = 116,
        /// A timeout was reached.
        Timeout = 117,
        /// The syscall was cancelled through cancel_synchronization.
        Canceled = 118,
        /// A size or address was given exceeding the maximum allowed value.
        ExceedingMaximum = 119,
        /// No enum variants match this integer value.
        InvalidEnum = 120,
        /// The given entry does not exist.
        NoSuchEntry = 121,
        // AlreadyRegistered = 122,
        /// The remote part of the session was closed.
        PortRemoteDead = 123,
        // UnhandledInterrupt = 124,
        /// Attempted to do an operation that's invalid in the handle's current
        /// state.
        InvalidState = 125,
        /// Attempted to use an unknown value, reserved for future use.
        ReservedValue = 126,
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
    /// Transforms a KernelError into the encoding acceptable for a syscall
    /// return value.
    pub fn make_ret(self) -> u32 {
        (self.0 << 9) | 1
    }

    /// Turns a syscall return value into a Kernel Error.
    pub fn from_syscall_ret(err: u32) -> KernelError {
        KernelError(err >> 9)
    }

    /// Turns a kernel error description into a KernelError.
    pub fn from_description(err: u32) -> KernelError {
        KernelError(err)
    }

    /// Gets the underlying KernelError description.
    pub fn description(self) -> u32 {
        self.0
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            KernelError::InvalidState => write!(f, "Handle is in invalid state for this operation."),
            KernelError(err) => write!(f, "Unknown error: {}", err)
        }
    }
}
