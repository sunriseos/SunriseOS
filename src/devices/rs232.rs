//! RS-232

use core::fmt::Write;
use ::spin::Once;
use ::spin::Mutex;
use ::io::Io;
use ::i386::pio::Pio;
use ::logger::*;

/// The port of a COM
#[derive(Debug, Copy, Clone)]
pub struct ComPort(u16);

#[cfg(target_arch="x86")]
const COM1: ComPort = ComPort(0x3F8);
#[cfg(target_arch="x86")]
const COM2: ComPort = ComPort(0x2F8);
#[cfg(target_arch="x86")]
const COM3: ComPort = ComPort(0x3E8);
#[cfg(target_arch="x86")]
const COM4: ComPort = ComPort(0x2E8);

/// The possible colors for serial
#[allow(dead_code)]
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

impl SerialColor {
    fn from_log_color(orig: LogColor) -> SerialColor {
        match orig {
            LogColor::Black         => SerialColor::Black,
            LogColor::White         => SerialColor::White,
            LogColor::Blue          => SerialColor::Blue,
            LogColor::Green         => SerialColor::Green,
            LogColor::Cyan          => SerialColor::Cyan,
            LogColor::Red           => SerialColor::Red,
            LogColor::Magenta       => SerialColor::Magenta,
            LogColor::Yellow        => SerialColor::Yellow,
            LogColor::LightGray     => SerialColor::LightGray,
            LogColor::DarkGray      => SerialColor::DarkGray,
            LogColor::LightBlue     => SerialColor::LightBlue,
            LogColor::LightGreen    => SerialColor::LightGreen,
            LogColor::LightCyan     => SerialColor::LightCyan,
            LogColor::LightRed      => SerialColor::LightRed,
            LogColor::LightYellow   => SerialColor::Yellow,
            LogColor::LightMagenta  => SerialColor::Magenta,

            // fallback colors
            LogColor::Brown         => SerialColor::Red,
            LogColor::Pink          => SerialColor::LightMagenta,
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct SerialAttributes(LogAttributes);

impl SerialAttributes {
    pub fn new(attr: LogAttributes) -> SerialAttributes {
        SerialAttributes(attr)
    }

    pub fn enable(&self) {
        let fg = SerialColor::from_log_color(self.0.foreground);
        let bg = SerialColor::from_log_color(self.0.background);
        write!(SerialLogger, "\x1B[{};{}m", fg as u8 + 30, bg as u8 + 40);
    }
}

static G_SERIAL: Once<Mutex<SerialInternal<Pio<u8>>>> = Once::new();

pub struct SerialInternal<T> {
    t: T
}

impl <T> SerialInternal<T> {
    /// Creates the serial for i386
    #[cfg(target_arch="x86")]
    pub fn new(com_port: ComPort) -> SerialInternal<Pio<u8>> {
        let mut data_port       = Pio::<u8>::new(com_port.0 + 0);
        let mut interrupt_port  = Pio::<u8>::new(com_port.0 + 1);
        let mut baud_diviser_lo = Pio::<u8>::new(com_port.0 + 0); // when DLB is set, data and intr
        let mut baud_diviser_hi = Pio::<u8>::new(com_port.0 + 1); // become baud divisor lo and hi
        let mut fifo_port       = Pio::<u8>::new(com_port.0 + 2);
        let mut lcr_port        = Pio::<u8>::new(com_port.0 + 3);
        let mut mcr_port        = Pio::<u8>::new(com_port.0 + 4);

        interrupt_port .write(0x00); // Disable interrupts
        lcr_port       .write(0x80); // Enable DLAB (set baud rate divisor)
        baud_diviser_lo.write(0x03); // set divisor to 3 (lo byte) 38400 baud rate
        baud_diviser_hi.write(0x00); //                  (hi byte)
        lcr_port       .write(0x03); // 8 bits, no parity, one stop bit. Disables DLAB
        fifo_port      .write(0xC7); // Enable FIFO, clear them, with 14-byte threshold
                                           // Note : no idea what this is
        //mcr_port     .write(0x0B);       // IRQs enabled, RTS/DSR set

        SerialInternal { t: data_port}
    }
}

impl SerialInternal<Pio<u8>> {
    fn send_string(&mut self, string: &str) {
        for byte in string.bytes() {
            self.t.write(byte);
        }
    }
}


/* ********************************************************************************************** */

pub struct SerialLogger;

impl Logger for SerialLogger {
    /// Prints a string to the serial port
    fn print(&mut self, string: &str) {
        let mut internal = G_SERIAL.call_once(|| Mutex::new(SerialInternal::<Pio<u8>>::new(COM1))).lock();
        internal.send_string(string);
    }

    /// Prints a string to the screen and adds a line feed
    fn println(&mut self, string: &str) {
        let mut internal = G_SERIAL.call_once(|| Mutex::new(SerialInternal::<Pio<u8>>::new(COM1))).lock();
        internal.send_string(string);
        internal.send_string("\n");
    }

    /// Prints a string to the serial port with attributes
    fn print_attr(&mut self, string: &str, attr: LogAttributes) {
        SerialAttributes::new(attr).enable();
        {
            let mut internal = G_SERIAL.call_once(|| Mutex::new(SerialInternal::<Pio<u8>>::new(COM1))).lock();
            internal.send_string(string);
        }
        SerialAttributes::new(LogAttributes::default()).enable();
    }

    /// Prints a string to the serial port with attributes and adds a line feed
    fn println_attr(&mut self, string: &str, attr: LogAttributes) {
        let logger = &mut SerialLogger;
        logger.print_attr(string, attr);
        logger.print("\n");
    }

    unsafe fn force_unlock(&mut self) {
        G_SERIAL.call_once(|| Mutex::new(SerialInternal::<Pio<u8>>::new(COM1))).force_unlock();
    }

    fn clear(&mut self) {
        // We don't clear
    }
}

impl ::core::fmt::Write for SerialLogger {
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        let logger = &mut SerialLogger;
        logger.print(s);
        Ok(())
    }
}
