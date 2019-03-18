//! UserspaceError and KernelError

use failure::Backtrace;
use crate::paging::error::MmError;

pub use kfs_libkern::error::KernelError as UserspaceError;

/// Kernel Error.
///
/// Used pretty much everywhere that an error can occur. Holds the reason of the error,
/// and a backtrace of its origin, for debug.
///
/// When a KernelError must be propagated to userspace, i.e. a syscall failed, it must be
/// converted to a [UserspaceError].
#[derive(Debug, Fail)]
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
pub enum KernelError {
    #[fail(display = "Frame allocation error: physical address space exhausted")]
    PhysicalMemoryExhaustion {
        backtrace: Backtrace
    },
    #[fail(display = "Virtual allocation error: virtual address space exhausted")]
    VirtualMemoryExhaustion {
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid address: address {:#010x} is considered invalid", address)]
    InvalidAddress {
        address: usize,
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid size: size {} is considered invalid", size)]
    InvalidSize {
        size: usize,
        backtrace: Backtrace,
    },
    #[fail(display = "Memory management error: {}", _0)]
    MmError(MmError),
    #[fail(display = "Process was killed before finishing operation")]
    ProcessKilled {
        backtrace: Backtrace,
    },
    #[fail(display = "Thread was already started")]
    ThreadAlreadyStarted {
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid combination of values passed.")]
    InvalidCombination {
        backtrace: Backtrace,
    },
    #[fail(display = "The passed value ({}) would overflow the maximum ({}).", value, maximum)]
    ExceedingMaximum {
        value: u64,
        maximum: u64,
        backtrace: Backtrace,
    },
    #[fail(display = "Invalid kernel capability u32: {}", _0)]
    InvalidKernelCaps {
        kcap: u32,
        backtrace: Backtrace,
    },
    #[fail(display = "Value is reserved for future use.")]
    ReservedValue {
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
            KernelError::ThreadAlreadyStarted { .. } => UserspaceError::ProcessAlreadyStarted,
            KernelError::InvalidAddress { .. } => UserspaceError::InvalidAddress,
            KernelError::InvalidSize { .. } => UserspaceError::InvalidSize,
            KernelError::InvalidCombination { .. } => UserspaceError::InvalidCombination,
            KernelError::ExceedingMaximum { .. } => UserspaceError::ExceedingMaximum,
            KernelError::InvalidKernelCaps { .. } => UserspaceError::InvalidKernelCaps,
            KernelError::ReservedValue { .. } => UserspaceError::ReservedValue,
            //KernelError::
            KernelError::ThisWillNeverHappenButPleaseDontMatchExhaustively => unreachable!(),
            // todo
            _ => unimplemented!("Unmatched Error: {}", err)
        }
    }
}

