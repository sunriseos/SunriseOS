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
        let sp_start = sp - ::STACK.as_ptr() as usize;
        print_hexdump(&::STACK[sp_start..]);
    }
}
