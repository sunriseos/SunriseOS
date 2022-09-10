//! bootstrap logging on rs232
//!
//! A pale copy of the rs232 kernel device.
//! Used by the bootstrap stage to provide some logging.
//!
//! This driver is meant to be as simple as possible

use core::arch::asm;

const COM1: u16 = 0x3F8;

/// Init the rs232 COM1. Must be called before logging anything.
///
/// # Safety
///
/// May only be called once.
pub unsafe fn init_bootstrap_log() {
    let _data_port      = COM1 + 0;
    let interrupt_port  = COM1 + 1;
    let baud_diviser_lo = COM1 + 0; // when DLB is set, data and intr
    let baud_diviser_hi = COM1 + 1; // become baud divisor lo and hi
    let fifo_port       = COM1 + 2;
    let lcr_port        = COM1 + 3;
    let _mcr_port       = COM1 + 4;
    let _status_port    = COM1 + 5;

    bootstrap_outb(interrupt_port , 0x00);       // Disable interrupts
    bootstrap_outb(lcr_port       , 0x80);       // Enable DLAB (set baud rate divisor)
    bootstrap_outb(baud_diviser_lo, 0x03); // set divisor to 3 (lo byte) 38400 baud rate
    bootstrap_outb(baud_diviser_hi, 0x00); //                  (hi byte)
    bootstrap_outb(lcr_port       , 0x03);       // 8 bits, no parity, one stop bit. Disables DLAB
    bootstrap_outb(fifo_port      , 0xC7);       // Enable FIFO, clear them, with 14-byte threshold
                                                        // Note : no idea what this is
    //mcr_port     .write(0x0B);                        // IRQs enabled, RTS/DSR set
}

/// Sends a string to COM1.
pub fn bootstrap_log(string: &str) {
    let status_port = COM1 + 5;
    for byte in string.bytes() {
        // Wait for the transmit buffer to be empty
        unsafe {
            while bootstrap_inb(status_port) & 0x20 == 0 { }
            bootstrap_outb(COM1, byte);
        }
    }
}

unsafe fn bootstrap_inb(port: u16) -> u8 {
    let value: u8;
    asm!("in al, dx", in("dx") port, out("al") value, options(nostack, nomem, preserves_flags));
    value
}

unsafe fn bootstrap_outb(port: u16, value: u8) {
    asm!("out dx, al", in("dx") port, in("al") value, options(nostack, nomem, preserves_flags));
}

/// A logger that sends its output to COM1.
///
/// Use it like this:
/// ```
/// use ::core::fmt::Write;
///
/// write!(Serial, "I got {} problems, but logging ain't one", 99);
/// ```
pub struct Serial;

impl ::core::fmt::Write for Serial {
    /// Writes a string to COM1.
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        bootstrap_log(s);
        Ok(())
    }
}
