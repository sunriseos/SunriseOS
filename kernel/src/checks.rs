//! Checked maths functions returning useful errors.

use error::KernelError;
use failure::Backtrace;

/// checks that a certain value meets the given alignment.
pub fn check_aligned(val: usize, alignment: usize) -> Result<(), KernelError> {
    match val % alignment {
        0 => Ok(()),
        _ => Err(KernelError::AlignmentError { given: val, needed: alignment, backtrace: Backtrace::new() } )
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

/// adds to usize, and returns an KernelError if it would cause an overflow.
pub fn add_or_error(lhs: usize, rhs: usize) -> Result<usize, KernelError> {
    match lhs.checked_add(rhs) {
        Some(result) => Ok(result),
        None => Err(KernelError::WouldOverflow { lhs,
                                                 operation: ::error::ArithmeticOperation::Add,
                                                 rhs,
                                                 backtrace: Backtrace::new() })
    }
}

/// subtracts to usize, and returns an KernelError if it would cause an overflow.
pub fn sub_or_error(lhs: usize, rhs: usize) -> Result<usize, KernelError> {
    match lhs.checked_add(rhs) {
        Some(result) => Ok(result),
        None => Err(KernelError::WouldOverflow { lhs,
                                                 operation: ::error::ArithmeticOperation::Sub,
                                                 rhs,
                                                 backtrace: Backtrace::new() })
    }
}
