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
#![deny(intra_doc_link_resolution_failure)]

extern crate byteorder;
extern crate bit_field;
extern crate num_traits;

use num_traits::Num;
use core::ops::{Not, BitAnd};
use core::fmt::Write;

mod cursor;
pub use cursor::*;

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
    match addr & align - 1 {
        0 => Some(addr),
        _ => addr.checked_add(align - (addr % align))
    }
}


/// Counts the numbers of `b` in `a`, rounding the result up.
///
/// Ex:
/// ```
///   # use kfs_libutils::div_ceil;
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

#[macro_export]
macro_rules! enum_with_val {
    ($(#[$meta:meta])* $vis:vis struct $ident:ident($ty:ty) {
        $($variant:ident = $num:expr),* $(,)*
    }) => {
        $(#[$meta])*
        $vis struct $ident($ty);
        impl $ident {
            $($vis const $variant: $ident = $ident($num);)*
        }

        impl ::core::fmt::Debug for $ident {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    $(&$ident::$variant => f.write_str(stringify!($ident)),)*
                    &$ident(v) => write!(f, "UNKNOWN({})", v),
                }
            }
        }
    }
}

/// Displays memory as hexdump
pub fn print_hexdump<T: Write>(f: &mut T, mem: &[u8]) {
    // just print as if at its own address ... which it is
    print_hexdump_as_if_at_addr(f, mem, mem.as_ptr() as usize)
}

/// Makes a hexdump of a slice, but display different addresses.
/// Used for displaying memory areas which are not identity mapped in the current pages
pub fn print_hexdump_as_if_at_addr<T: Write>(f: &mut T, mem: &[u8], display_addr: usize) {
    for chunk in mem.chunks(16) {
        let mut arr = [None; 16];
        for (i, elem) in chunk.iter().enumerate() {
            arr[i] = Some(*elem);
        }

        let offset_in_mem = chunk.as_ptr() as usize - mem.as_ptr() as usize;
        let _ = write!(f, "{:#0x}:", display_addr + offset_in_mem);

        for pair in arr.chunks(2) {
            let _ = write!(f, " ");
            for elem in pair {
                if let &Some(i) = elem {
                    let _ = write!(f, "{:02x}", i);
                } else {
                    let _ = write!(f, "  ");
                }
            }
        }
        let _ = write!(f, "  ");
        for i in chunk {
            if i.is_ascii_graphic() {
                let _ = write!(f, "{}", *i as char);
            } else {
                let _ = write!(f, ".");
            }
        }
        let _ = writeln!(f, "");
    }
}

/// Extension of the [BitField] trait, that adds the `set_bits_area` function.
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

