//! Errors specific to memory management

use error::UserspaceError;
use mem::VirtualAddress;
use failure::Backtrace;

/// An error related to Memory Management
#[derive(Debug, Fail)]
pub enum MmError {
    #[fail(display = "Memory management error: Virtual region is already occupied")]
    OccupiedMapping {
        address: VirtualAddress,
        length: usize,
        backtrace: Backtrace
    },
    #[fail(display = "Memory management error: Virtual region does not span the mapping exactly")]
    DoesNotSpanMapping {
        address: VirtualAddress,
        length: usize,
        backtrace: Backtrace
    },
    #[fail(display = "Memory management error: Virtual region spans several mappings")]
    SpansSeveralMappings {
        address: VirtualAddress,
        length: usize,
        backtrace: Backtrace
    },
    #[fail(display = "Memory management error: asked to remove an already available mapping")]
    WasAvailable {
        address: VirtualAddress,
        backtrace: Backtrace
    },
    #[fail(display = "Memory management error: cannot split mapping because it is shared")]
    SharedMapping {
        backtrace: Backtrace,
    },
    #[fail(display = "Memory management error: operation not supported for this type of mapping")]
    InvalidMapping {
        backtrace: Backtrace
    },
    #[doc(hidden)]
    #[fail(display = "Should never ever ***EVER*** be returned")]
    ThisWillNeverHappenButPleaseDontMatchExhaustively,
}

impl From<MmError> for UserspaceError {
    fn from(_: MmError) -> Self {
        unimplemented!()
    }
}
