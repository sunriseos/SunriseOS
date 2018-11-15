//! Generic useful functions

use logger::Loggers;
use core::fmt::Write;
use error::KernelError;
use failure::Backtrace;

/// Displays memory as hexdump
pub fn print_hexdump(mem: &[u8]) {
    // just print as if at its own address ... which it is
    print_hexdump_as_if_at_addr(mem, mem.as_ptr() as usize)
}

/// Makes a hexdump of a slice, but display different addresses.
/// Used for displaying memory areas which are not identity mapped in the current pages
pub fn print_hexdump_as_if_at_addr(mem: &[u8], display_addr: usize) {
    for chunk in mem.chunks(16) {
        let mut arr = [None; 16];
        for (i, elem) in chunk.iter().enumerate() {
            arr[i] = Some(*elem);
        }

        let offset_in_mem = chunk.as_ptr() as usize - mem.as_ptr() as usize;
        let _ = write!(Loggers, "{:#0x}:", display_addr + offset_in_mem);

        for pair in arr.chunks(2) {
            let _ = write!(Loggers, " ");
            for elem in pair {
                if let &Some(i) = elem {
                    let _ = write!(Loggers, "{:02x}", i);
                } else {
                    let _ = write!(Loggers, "  ");
                }
            }
        }
        let _ = write!(Loggers, "  ");
        for i in chunk {
            if i.is_ascii_graphic() {
                let _ = write!(Loggers, "{}", *i as char);
            } else {
                let _ = write!(Loggers, ".");
            }
        }
        let _ = writeln!(Loggers, "");
    }
}

pub trait BitArrayExt<U: ::bit_field::BitField>: ::bit_field::BitArray<U> {
    fn set_bits_area(&mut self, range: ::core::ops::Range<usize>, value: bool) {
        for i in range {
            self.set_bit(i, value);
        }
    }
}

impl<T: ?Sized, U: ::bit_field::BitField> BitArrayExt<U> for T where T: ::bit_field::BitArray<U> {}

// We could have made a generic implementation of this two functions working for either 1 or 0,
// but it will just be slower checking "what is our needle again ?" in every loop

/// Returns the index of the first 0 in a bit array
pub fn bit_array_first_zero(bitarray: &[u8]) -> Option<usize> {
    for (index, &byte) in bitarray.iter().enumerate() {
        if byte == 0xFF {
            // not here
            continue;
        }
        // We've got a zero in this byte
        for offset in 0..8 {
            if (byte & (1 << offset)) == 0 {
                return Some(index * 8 + offset);
            }
        }
    }
    // not found
    None
}

/// Returns the index of the first 1 in a bit array
pub fn bit_array_first_one(bitarray: &[u8]) -> Option<usize> {
    for (index, &byte) in bitarray.iter().enumerate() {
        if byte == 0x00 {
            // not here
            continue;
        }
        // We've got a one in this byte
        for offset in 0..8 {
            if (byte & (1 << offset)) != 0 {
                return Some(index * 8 + offset);
            }
        }
    }
    // not found
    None
}

pub fn align_up(addr: usize, align: usize) -> usize {
    match addr & align - 1 {
        0 => addr,
        _ => align_down(addr, align) + align
    }
}

pub fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}

pub fn div_round_up(a: usize, b: usize) -> usize {
    if a % b != 0 {
        a / b + 1
    } else {
        a / b
    }
}

/// align_up, but checks if addr overflows
pub fn align_up_checked(addr: usize, align: usize) -> Option<usize> {
    match addr & align - 1 {
        0 => Some(addr),
        _ => addr.checked_add(align - (addr % align))
    }
}

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

/// A trait for things that can be splitted in two parts
pub trait Splittable where Self: Sized {
    /// Split the given object in two at a given offset.
    ///
    /// The left side is modified in place, and the new right side is returned.
    ///
    /// If offset >= self.length, the object is untouched, and the right-hand side is None.
    /// If offset == 0, the object is untouched, and the right-hand side is None.
    fn split_at(&mut self, offset: usize) -> Result<Option<Self>, KernelError>;

    /// Splits the given object in two at the given offset.
    ///
    /// The right side is modified in place, and the new left side is returned.
    ///
    /// If offset >= self.length, the object is untouched, and the right-hand side is None.
    /// If offset == 0, the object is untouched, and the right-hand side is None.
    fn right_split(&mut self, offset: usize) -> Result<Option<Self>, KernelError> {
        let right_opt = self.split_at(offset)?;
        match right_opt {
            None => Ok(None), // no split was done
            Some(mut other) => {
                // swap the left and the right parts
                ::core::mem::swap(self, &mut other);
                Ok(Some(other))
            }
        }
    }
}
