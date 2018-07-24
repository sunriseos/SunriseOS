//! Generic useful functions

use logger::Loggers;
use core::fmt::Write;

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
