//! A messy crate with various utilities shared between the user and kernel code.
//! Should probably be further split into several useful libraries.

#![no_std]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(rustdoc::broken_intra_doc_links)]





use num_traits::Num;
use core::ops::{Not, BitAnd};
use core::fmt::Write;

pub mod io;
mod cursor;
pub use crate::cursor::*;
pub mod loop_future;

/// Align the address to the next alignment.
///
/// The given number should be a power of two to get coherent results!
///
/// # Panics
///
/// Panics on underflow if align is 0.
/// Panics on overflow if the expression `addr + (align - 1)` overflows.
pub fn align_up<T: Num + Not<Output = T> + BitAnd<Output = T> + Copy>(addr: T, align: T) -> T
{
    align_down(addr + (align - T::one()), align)
}

/// Align the address to the previous alignment.
///
/// The given number should be a power of two to get coherent results!
///
/// # Panics
///
/// Panics on underflow if align is 0.
pub fn align_down<T: Num + Not<Output = T> + BitAnd<Output = T> + Copy>(addr: T, align: T) -> T
{
    addr & !(align - T::one())
}

/// align_up, but checks if addr overflows
pub fn align_up_checked(addr: usize, align: usize) -> Option<usize> {
    match addr & (align - 1) {
        0 => Some(addr),
        _ => addr.checked_add(align - (addr % align))
    }
}


/// Counts the numbers of `b` in `a`, rounding the result up.
///
/// Ex:
/// ```
///   # use sunrise_libutils::div_ceil;
///   # let PAGE_SIZE: usize = 0x1000;
///     let pages_count = div_ceil(0x3002, PAGE_SIZE);
/// ```
/// counts the number of pages needed to store 0x3002 bytes.
pub fn div_ceil<T: Num + Copy>(a: T, b: T) -> T {
    if a % b != T::zero() {
        a / b + T::one()
    } else {
        a / b
    }
}

/// Creates a fake C-like enum, where all bit values are accepted.
///
/// This is mainly useful for FFI constructs. In C, an enum is allowed to take
/// any bit value, not just those defined in the enumeration. In Rust,
/// constructing an enum with a value outside the enumeration is UB. In order
/// to avoid this, we define our enum as a struct with associated variants.
#[macro_export]
macro_rules! enum_with_val {
    ($(#[$meta:meta])* $vis:vis struct $ident:ident($innervis:vis $ty:ty) {
        $($(#[$varmeta:meta])* $variant:ident = $num:expr),* $(,)*
    }) => {
        $(#[$meta])*
        #[repr(transparent)]
        $vis struct $ident($innervis $ty);
        impl $ident {
            $($(#[$varmeta])* $vis const $variant: $ident = $ident($num);)*
        }

        impl ::core::fmt::Debug for $ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    $(&$ident::$variant => write!(f, "{}::{}", stringify!($ident), stringify!($variant)),)*
                    &$ident(v) => write!(f, "UNKNOWN({})", v),
                }
            }
        }
    }
}

/// Displays memory as hexdump
///
/// This function follows the output format of the `xxd` command so you can easily diff
/// between two hexdumps on the host machine, to help debugging sessions.
pub fn print_hexdump<T: Write>(f: &mut T, mem: &[u8]) {
    // just print as if at its own address ... which it is
    print_hexdump_as_if_at_addr(f, mem, mem.as_ptr() as usize)
}

/// Makes a hexdump of a slice, but display different addresses.
/// Used for displaying memory areas which are not identity mapped in the current pages
///
/// This function follows the output format of the `xxd` command so you can easily diff
/// between two hexdumps on the host machine, to help debugging sessions.
pub fn print_hexdump_as_if_at_addr<T: Write>(f: &mut T, mem: &[u8], display_addr: usize) {
    for chunk in mem.chunks(16) {
        let mut arr = [None; 16];
        for (i, elem) in chunk.iter().enumerate() {
            arr[i] = Some(*elem);
        }

        let offset_in_mem = chunk.as_ptr() as usize - mem.as_ptr() as usize;
        let _ = write!(f, "{:08x}:", display_addr + offset_in_mem);

        for pair in arr.chunks(2) {
            let _ = write!(f, " ");
            for elem in pair {
                if let Some(i) = *elem {
                    let _ = write!(f, "{:02x}", i);
                } else {
                    let _ = write!(f, "  ");
                }
            }
        }
        let _ = write!(f, "  ");
        for i in chunk {
            if i.is_ascii_graphic() || *i == 0x20 {
                let _ = write!(f, "{}", *i as char);
            } else {
                let _ = write!(f, ".");
            }
        }
        let _ = writeln!(f);
    }
}

/// Extension of the [BitField] trait, that adds the `set_bits_area` function.
///
/// [BitField]: ::bit_field::BitField
pub trait BitArrayExt<U: ::bit_field::BitField>: ::bit_field::BitArray<U> {
    /// Sets a range of bits to `value` in the BitField.
    fn set_bits_area(&mut self, range: ::core::ops::Range<usize>, value: bool) {
        for i in range {
            self.set_bit(i, value);
        }
    }
}

impl<T: ?Sized, U: ::bit_field::BitField> BitArrayExt<U> for T where T: ::bit_field::BitArray<U> {}

// We could have made a generic implementation of this two functions working for either 1 or 0,
// but it will just be slower checking "what is our needle again ?" in every loop

/// Returns the index of the first 0 in a bit array.
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

/// Returns the index of the first 1 in a bit array.
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

/// Returns the index of the first instance of count contiguous 1 in a bit array
pub fn bit_array_first_count_one(bitarray: &[u8], count: usize) -> Option<usize> {
    let mut curcount = 0;
    for (index, &byte) in bitarray.iter().enumerate() {
        if byte == 0x00 {
            // not here
            curcount = 0;
            continue;
        }
        // We've got a one in this byte
        for offset in 0..8 {
            if (byte & (1 << offset)) != 0 {
                curcount += 1;
                if curcount == count {
                    return Some((index * 8 + offset) - (count - 1));
                }
            } else {
                curcount = 0;
            }
        }
    }
    // not found
    None
}

/// Returns the floored base 2 logarithm of the number.
///
/// # Panics
///
/// Panics if val is 0.
pub const fn log2_floor(val: usize) -> usize {
    core::mem::size_of::<usize>() * 8 - val.leading_zeros() as usize - 1
}

/// Returns the ceiled base 2 logarithm of the number.
///
/// # Panics
///
/// Panics if val is 0.
pub const fn log2_ceil(val: usize) -> usize {
    core::mem::size_of::<usize>() * 8 - val.leading_zeros() as usize - (val & (val - 1) == 0) as usize
}

/// Cast a slice while keeping the lifetimes.
///
/// Thanks I hate it.
///
/// # Safety
///
/// `data` must be aligned for R, even for zero-length slices.
///
/// `T` must be safely castable as `R`. This generally means that T and R must both be POD types without padding.
#[allow(clippy::cast_ptr_alignment)]
pub unsafe fn cast_mut<T, R>(data: &mut [T]) -> &mut [R] {
    let elem_of_r = core::mem::size_of::<T>() * data.len() / core::mem::size_of::<R>();
    core::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut R, elem_of_r)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_log2_floor() {
        for i in 1..512 {
            assert_eq!((i as f32).log2().floor() as usize, log2_floor(i));
        }
    }

    #[test]
    fn test_log2_ceil() {
        for i in 1..512 {
            assert_eq!((i as f32).log2().ceil() as usize, log2_ceil(i));
        }
    }

    #[test]
    #[should_panic]
    fn test_log2_floor_panic() {
        log2_floor(0);
    }

    #[test]
    #[should_panic]
    fn test_log2_ceil_panic() {
        log2_ceil(0);
    }
}

#[macro_export]
/// A macro to initialize a struct directly in global.
///
/// # Note
///
/// - This construct the struct on the stack. For the same behaviours on the heap, please refer to ZeroBox.
/// - The type should not contain anything that is not allowed to be initialized to Zero (references, certain enums, and complex types).
///
/// # Usage
///
/// ```rust
/// use sunrise_libutils::initialize_to_zero;
/// let zero_initialized = unsafe { initialize_to_zero!(u32) };
/// ```
macro_rules! initialize_to_zero {
    ($ty:ty) => {{
        #[doc(hidden)]
        union ZeroedTypeUnion {
            data: core::mem::ManuallyDrop<$ty>,
            arr: [u8; core::mem::size_of::<$ty>()]
        }

        core::mem::ManuallyDrop::into_inner(ZeroedTypeUnion { arr: [0; core::mem::size_of::<$ty>()] }.data)
    }}
}
