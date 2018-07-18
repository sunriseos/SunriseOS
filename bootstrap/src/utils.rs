//! Generic useful functions

use bootstrap_logging::*;
use core::fmt::Write;

pub fn print_hexdump(addr: &[u8]) {
    for chunk in addr.chunks(16) {
        let mut arr = [None; 16];
        for (i, elem) in chunk.iter().enumerate() {
            arr[i] = Some(*elem);
        }

        let _ = write!(Serial, "{:#0x}:", chunk.as_ptr() as usize);

        for pair in arr.chunks(2) {
            let _ = write!(Serial, " ");
            for elem in pair {
                if let &Some(i) = elem {
                    let _ = write!(Serial, "{:02x}", i);
                } else {
                    let _ = write!(Serial, "  ");
                }
            }
        }
        let _ = write!(Serial, "  ");
        for i in chunk {
            if i.is_ascii_graphic() {
                let _ = write!(Serial, "{}", *i as char);
            } else {
                let _ = write!(Serial, ".");
            }
        }
        let _ = writeln!(Serial, "");
    }
}

pub fn print_stack() {
    unsafe {
        // TODO: I hate this.
        let sp: usize;
        asm!("mov $0, esp" : "=r"(sp) : : : "intel");
        let sp_start = sp - ::STACK.0.as_ptr() as usize;
        print_hexdump(&::STACK.0[sp_start..]);
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
