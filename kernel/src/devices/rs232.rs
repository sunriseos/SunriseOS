//! RS-232

use core::fmt::{Display, Write, Error, Formatter};
use crate::sync::{Once, SpinLock};
use crate::io::Io;
use crate::i386::pio::Pio;

/// The port of a COM
#[derive(Debug, Copy, Clone)]
pub struct ComPort(u16);

#[cfg(all(target_arch="x86", not(test)))]
const COM1: ComPort = ComPort(0x3F8);
#[cfg(all(target_arch="x86", not(test)))]
const COM2: ComPort = ComPort(0x2F8);
#[cfg(all(target_arch="x86", not(test)))]
const COM3: ComPort = ComPort(0x3E8);
#[cfg(all(target_arch="x86", not(test)))]
const COM4: ComPort = ComPort(0x2E8);

// TODO: device drivers should be compiled only for i386
#[cfg(test)]
const COM1: ComPort = ComPort(0x7777);

/// The possible colors for serial
#[allow(missing_docs)]
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum SerialColor {
    Black        = 0,
    Red          = 1,
    Green        = 2,
    Yellow       = 3,
    Blue         = 4,
    Magenta      = 5,
    Cyan         = 6,
    LightGray    = 7,
    Default      = 9,
    DarkGray     = 60,
    LightRed     = 61,
    LightGreen   = 62,
    LightYellow  = 63,
    LightBlue    = 64,
    LightMagenta = 65,
    LightCyan    = 66,
    White        = 67,
}

#[derive(Debug, Copy, Clone)]
/// A foreground and a background combination
pub struct SerialAttributes {
    fg: SerialColor,
    bg: SerialColor,
}

impl SerialAttributes {
    /// Creates a color attribute with `fg` foreground and default background.
    pub fn fg(fg: SerialColor) -> SerialAttributes {
        SerialAttributes { fg, bg: SerialColor::Default }
    }

    /// Creates a color attribute with `fg` foreground and `bg` background.
    pub fn fg_bg(fg: SerialColor, bg: SerialColor) -> SerialAttributes {
        SerialAttributes { fg, bg }
    }

    /// Creates a color attribute with default foreground and default background.
    pub fn default() -> SerialAttributes {
        SerialAttributes { fg: SerialColor::Default, bg: SerialColor::Default }
    }
}

/// To log something with color attributes do something like this:
///
/// ```
/// use ::device::rs232::{SerialLogger, SerialAttributes, SerialColor};
/// use ::core::fmt::Write;
///
/// write!(SerialLogger, "Hello {}World{}!",
///     SerialAttributes::fg(SerialColor::Green), // a green foreground with default background.
///     SerialAttributes::default() // don't forget to set back to default attributes at the end.
/// );
/// ```
impl Display for SerialAttributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "\x1B[{};{}m", self.fg as u8 + 30, self.bg as u8 + 40)
    }
}

static G_SERIAL: Once<SpinLock<SerialInternal<Pio<u8>>>> = Once::new();

struct SerialInternal<T> {
    data_port: T,
    status_port: T
}

impl <T> SerialInternal<T> {
    /// Creates the serial for i386
    #[cfg(all(target_arch="x86", not(test)))]
    #[allow(unused)]
    pub fn new(com_port: ComPort) -> SerialInternal<Pio<u8>> {
        let mut data_port       = Pio::<u8>::new(com_port.0 + 0);
        let mut interrupt_port  = Pio::<u8>::new(com_port.0 + 1);
        let mut baud_diviser_lo = Pio::<u8>::new(com_port.0 + 0); // when DLB is set, data and intr
        let mut baud_diviser_hi = Pio::<u8>::new(com_port.0 + 1); // become baud divisor lo and hi
        let mut fifo_port       = Pio::<u8>::new(com_port.0 + 2);
        let mut lcr_port        = Pio::<u8>::new(com_port.0 + 3);
        let mut mcr_port        = Pio::<u8>::new(com_port.0 + 4);
        let mut status_port     = Pio::<u8>::new(com_port.0 + 5);

        interrupt_port .write(0x00); // Disable interrupts
        lcr_port       .write(0x80); // Enable DLAB (set baud rate divisor)
        baud_diviser_lo.write(0x03); // set divisor to 3 (lo byte) 38400 baud rate
        baud_diviser_hi.write(0x00); //                  (hi byte)
        lcr_port       .write(0x03); // 8 bits, no parity, one stop bit. Disables DLAB
        fifo_port      .write(0xC7); // Enable FIFO, clear them, with 14-byte threshold
                                           // Note : no idea what this is
        //mcr_port     .write(0x0B);       // IRQs enabled, RTS/DSR set

        SerialInternal { data_port, status_port }
    }

    #[cfg(test)]
    pub fn new(_com_port: ComPort) -> SerialInternal<Pio<u8>> { panic!("mock implementation !") }
}

impl SerialInternal<Pio<u8>> {
    fn send_string(&mut self, string: &str) {
        for byte in string.bytes() {
            // Wait for the transmit buffer to be empty.
            while self.status_port.read() & 0x20 == 0 {}
            self.data_port.write(byte);
        }
    }
}


/* ********************************************************************************************** */

/// A logger that sends its output to COM1.
///
/// Use it like this:
/// ```
/// use ::core::fmt::Write;
///
/// write!(SerialLogger, "I got {} problems, but logging ain't one", 99);
/// ```
pub struct SerialLogger;

impl SerialLogger {
    /// Re-take the lock protecting multiple access to the device.
    ///
    /// # Safety
    ///
    /// This function should only be used when panicking.
    pub unsafe fn force_unlock(&mut self) {
        G_SERIAL.call_once(|| SpinLock::new(SerialInternal::<Pio<u8>>::new(COM1))).force_unlock();
    }
}

impl Write for SerialLogger {
    /// Writes a string to COM1.
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        let mut internal = G_SERIAL.call_once(|| SpinLock::new(SerialInternal::<Pio<u8>>::new(COM1))).lock();
        internal.send_string(s);
        Ok(())
    }
}
