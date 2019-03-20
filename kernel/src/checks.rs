//! Checked maths functions returning useful errors.

use crate::error::{KernelError, UserspaceError};
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
        Err(KernelError::InvalidSize { size: 0, backtrace: Backtrace::new() })
    } else {
        Ok(())
    }
}

/// Checks the given u64 fits an usize on this architecture.
pub fn check_lower_than_usize(val: u64, err: UserspaceError) -> Result<(), UserspaceError> {
    if (usize::max_value() as u64) < val {
        Err(err)
    } else {
        Ok(())
    }
}
