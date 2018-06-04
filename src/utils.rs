use print::Printer;
use core::fmt::Write;

pub fn print_hexdump(addr: &[u8]) {
    for chunk in addr.chunks(16) {
        let mut arr = [None; 16];
        for (i, elem) in chunk.iter().enumerate() {
            arr[i] = Some(*elem);
        }

        let _ = write!(Printer, "{:#0x}:", chunk.as_ptr() as usize);

        for pair in arr.chunks(2) {
            let _ = write!(Printer, " ");
            for elem in pair {
                if let &Some(i) = elem {
                    let _ = write!(Printer, "{:02x}", i);
                } else {
                    let _ = write!(Printer, "  ");
                }
            }
        }
        let _ = write!(Printer, "  ");
        for i in chunk {
            if i.is_ascii_graphic() {
                let _ = write!(Printer, "{}", *i as char);
            } else {
                let _ = write!(Printer, ".");
            }
        }
        let _ = writeln!(Printer, "");
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

/// Returns the index of the first zero in a bit array
/// If no zero is found, returns bitarray.len(), which is outside the set of valid indexes
pub fn bit_array_first_zero(bitarray: &[u8]) -> usize {
    for (index, &byte) in bitarray.iter().enumerate() {
        if byte == 0xFF {
            continue;
        }
        // We've got a zero in this byte
        for offset in 0..7 {
            if (byte & (1 << offset)) == 0 {
                return index * 8 + offset;
            }
        }
    }
    // not found
    bitarray.len()
}
