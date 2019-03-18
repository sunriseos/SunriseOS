//! Checked maths functions returning useful errors.

use crate::error::KernelError;
use failure::Backtrace;

/// Checks that a size meets the given alignment.
///
/// # Errors
///
/// * `InvalidSize`: `size` is not aligned to `alignment`.
pub fn check_size_aligned(size: usize, alignment: usize) -> Result<(), KernelError> {
    match size % alignment {
        0 => Ok(()),
        _ => Err(KernelError::InvalidSize { size, backtrace: Backtrace::new() })
    }
}

/// checks that a length is not 0.
pub fn check_nonzero_length(length: usize) -> Result<(), KernelError> {
    if length == 0 {
        Err(KernelError::ZeroLengthError { backtrace: Backtrace::new() })
    } else {
        Ok(())
    }
}
