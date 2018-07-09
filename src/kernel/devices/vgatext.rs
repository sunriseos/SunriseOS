//! A module for printing text to screen using VGA compatible text mode
//! by writing in the video memory

use spin::Mutex;
use ascii::AsciiStr;
use ascii::AsAsciiStr;
use frame_alloc::PhysicalAddress;
use logger::{Logger, LogAttributes, LogColor};

pub const VGA_SCREEN_ADDRESS: PhysicalAddress = PhysicalAddress(0xb8000);
pub const VGA_SCREEN_SIZE: (usize, usize) = (25, 80); // y, x
pub const VGA_SCREEN_MEMORY_SIZE: usize = 32 * 1024 / 2; // 32 ko in u16

#[cfg(not(target_os = "none"))]
/// When debugging we will write to this buffer instead
static mut VGA_SPACE_DEBUG : [u16; VGA_SCREEN_MEMORY_SIZE] = [0; VGA_SCREEN_MEMORY_SIZE];

lazy_static! {
    static ref G_PRINTER: Mutex<VGATextLoggerInternal> = Mutex::new(VGATextLoggerInternal::new());
}

#[allow(dead_code)]
#[repr(u8)]
/// The possible colors of VGA-compatible text mode
pub enum VGATextColor {
    Black      = 0,
    Blue       = 1,
    Green      = 2,
    Cyan       = 3,
    Red        = 4,
    Magenta    = 5,
    Brown      = 6,
    LightGray  = 7,
    DarkGray   = 8,
    LightBlue  = 9,
    LightGreen = 10,
    LightCyan  = 11,
    LightRed   = 12,
    Pink       = 13,
    Yellow     = 14,
    White      = 15,
}

impl VGATextColor {
    fn from_log_color(orig: LogColor) -> VGATextColor {
        match orig {
            LogColor::DefaultBackground => VGATextColor::Black,
            LogColor::DefaultForeground => VGATextColor::White,

            LogColor::Black         => VGATextColor::Black,
            LogColor::White         => VGATextColor::White,
            LogColor::Blue          => VGATextColor::Blue,
            LogColor::Green         => VGATextColor::Green,
            LogColor::Cyan          => VGATextColor::Cyan,
            LogColor::Red           => VGATextColor::Red,
            LogColor::Magenta       => VGATextColor::Magenta,
            LogColor::Brown         => VGATextColor::Brown,
            LogColor::Pink          => VGATextColor::Pink,
            LogColor::Yellow        => VGATextColor::Yellow,
            LogColor::LightGray     => VGATextColor::LightGray,
            LogColor::DarkGray      => VGATextColor::DarkGray,
            LogColor::LightBlue     => VGATextColor::LightBlue,
            LogColor::LightGreen    => VGATextColor::LightGreen,
            LogColor::LightCyan     => VGATextColor::LightCyan,
            LogColor::LightRed      => VGATextColor::LightRed,

            // fallback colors
            LogColor::LightYellow   => VGATextColor::Yellow,
            LogColor::LightMagenta  => VGATextColor::Magenta,
        }
    }
}

/// A class to create foreground + background attributes for vga-compatible text mode
pub struct VGATextPrintAttribute(u16);

impl VGATextPrintAttribute {

    /// Creates an attribute representing the combination of foreground + background + blink
    pub fn new(foreground: VGATextColor, background: VGATextColor, blink: bool) -> VGATextPrintAttribute {
        VGATextPrintAttribute(((foreground as u16) << 8)
            | ((background as u16) << 12)
            | ((blink as u16) << 15))
    }

    /// returns the u16 representing the combination of attr and letter
    fn combine_ascii(&self, ascii_letter: u8) -> u16 {
        self.0 | ((ascii_letter as u16) & 0x7F)
    }

    pub fn from_log_attr(log_attr: &LogAttributes) -> VGATextPrintAttribute {
        Self::new(
            VGATextColor::from_log_color(log_attr.foreground),
            VGATextColor::from_log_color(log_attr.background),
            log_attr.blink)
    }
}

/// Default attribute is white foreground on black background
impl Default for VGATextPrintAttribute {
    fn default() -> Self {
        VGATextPrintAttribute::new(VGATextColor::White, VGATextColor::Black, false)
    }
}

/// A class managing the VGA compatible text mode
/// (see [wikipedia page](https://en.wikipedia.org/wiki/VGA-compatible_text_mode))
struct VGATextLoggerInternal {
    pos: (usize, usize), // (y, x)
    buffer: &'static mut [u16]
}

impl VGATextLoggerInternal {

    fn new() -> VGATextLoggerInternal {
        #[cfg(target_os = "none")]
        return VGATextLoggerInternal {
            pos: (0, 0),
            buffer: unsafe { ::core::slice::from_raw_parts_mut(VGA_SCREEN_ADDRESS.addr() as _, VGA_SCREEN_MEMORY_SIZE) }
        };
        #[cfg(not(target_os = "none"))]
            VGATextLoggerInternal {
            pos: (0, 0),
            buffer: unsafe { ::core::slice::from_raw_parts_mut(VGA_SPACE_DEBUG.as_mut_ptr(), VGA_SCREEN_MEMORY_SIZE) }
        }
    }

    #[inline]
    fn carriage_return(&mut self) {
        self.pos.1 = 0;
    }

    #[inline]
    fn line_feed(&mut self) {
        if self.pos.0 == VGA_SCREEN_SIZE.0 - 1 {
            self.scroll_screen();
        } else {
            self.pos.0 += 1;
        }
        self.carriage_return();
    }

    #[inline]
    fn advance_pos(&mut self) {
        self.pos.1 += 1;
        if self.pos.1 >= VGA_SCREEN_SIZE.1 {
            self.line_feed();
        }
    }

    /// returns the index in vga memory corresponding to self.pos
    #[inline]
    fn index_of_pos(&self) -> usize {
        (self.pos.0 * VGA_SCREEN_SIZE.1 + (self.pos.1))
    }

    /// scrolls the whole screen by one line
    fn scroll_screen(&mut self) {
        for i in 0..(VGA_SCREEN_SIZE.0 - 1) * VGA_SCREEN_SIZE.1 {
            self.buffer[i] = self.buffer[i + VGA_SCREEN_SIZE.1];
        }
        // Erase last line
        for i in (VGA_SCREEN_SIZE.0 - 1) * VGA_SCREEN_SIZE.1
                .. VGA_SCREEN_SIZE.0 * VGA_SCREEN_SIZE.1 {
            self.buffer[i] = 0;
        }
    }

    /// Prints a string to the screen with attributes
    fn print_attr(&mut self, string: &AsciiStr, attr: VGATextPrintAttribute) {
        let slice = string.as_bytes();

        // TODO check max len
        for letter in slice {
            match *letter {
                b'\n' => { self.line_feed() }
                b'\r' => { self.carriage_return() }
                l => {
                    self.buffer[self.index_of_pos()] = attr.combine_ascii(l);
                    self.advance_pos();
                }
            }
        }
    }

    /// Clears the whole screen by writing 0 to it and reset cursor
    fn clear(&mut self) {
        for i in 0..(VGA_SCREEN_SIZE.0 * VGA_SCREEN_SIZE.1) {
            self.buffer[i] = 0;
        }
        self.pos = (0,0);
    }
}

/// A class to print text to the screen
pub struct VGATextLogger;

impl Logger for VGATextLogger {

    /// Prints a string to the screen
    fn print(&mut self, string: &str) {
        let string = string.as_ascii_str().expect("ASCII");
        G_PRINTER.lock().print_attr(string, VGATextPrintAttribute::default());
    }

    /// Prints a string to the screen and adds a line feed
    fn println(&mut self, string: &str) {
        let string = string.as_ascii_str().expect("ASCII");
        let mut myprinter = G_PRINTER.lock();
        myprinter.print_attr(string, VGATextPrintAttribute::default());
        myprinter.line_feed();
    }

    /// Prints a string to the screen with attributes
    fn print_attr(&mut self, string: &str, attr: LogAttributes) {
        let string = string.as_ascii_str().expect("ASCII");
        G_PRINTER.lock().print_attr(string, VGATextPrintAttribute::from_log_attr(&attr));
    }

    /// Prints a string to the screen with attributes and adds a line feed
    fn println_attr(&mut self, string: &str, attr: LogAttributes) {
        let string = string.as_ascii_str().expect("ASCII");
        let mut myprinter = G_PRINTER.lock();
        myprinter.print_attr(string, VGATextPrintAttribute::from_log_attr(&attr));
        myprinter.line_feed();
    }

    unsafe fn force_unlock(&mut self) {
        G_PRINTER.force_unlock();
    }

    /// Clears the whole screen and resets cursor to top left
    fn clear(&mut self) {
        let mut myprinter = G_PRINTER.lock();
        myprinter.clear();
    }
}

impl ::core::fmt::Write for VGATextLogger {
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        let logger = &mut VGATextLogger;
        logger.print(s);
        Ok(())
    }
}
