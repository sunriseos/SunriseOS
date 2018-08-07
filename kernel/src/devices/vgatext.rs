//! A module for printing text to screen using VGA compatible text mode
//! by writing in the video memory

use spin::Once;
use spin::{Mutex, MutexGuard};
use ascii::AsciiStr;
use ascii::AsAsciiStr;
use frame_alloc::PhysicalAddress;
use paging::VirtualAddress;
use paging::{ACTIVE_PAGE_TABLES, PAGE_SIZE, PageTablesSet, EntryFlags, KernelLand, count_pages};
use logger::{Logger, LogAttributes, LogColor};

pub const VGA_SCREEN_ADDRESS: PhysicalAddress = PhysicalAddress(0xb8000);
pub const VGA_SCREEN_SIZE: (usize, usize) = (25, 80); // y, x
pub const VGA_SCREEN_MEMORY_SIZE: usize = 32 * 1024 / 2; // 32 ko in u16

static G_VGATEXT: Once<Mutex<VGATextLoggerInternal>> = Once::new();

#[allow(dead_code)]
#[repr(u8)]
/// The possible colors of VGA-compatible text mode
pub enum VGATextColor {
    Black        = 0,   DarkGray     = 8,
    Blue         = 1,   LightBlue    = 9,
    Green        = 2,   LightGreen   = 10,
    Cyan         = 3,   LightCyan    = 11,
    Red          = 4,   LightRed     = 12,
    Magenta      = 5,   LightMagenta = 13,
    Brown        = 6,   Yellow       = 14,
    LightGray    = 7,   White        = 15,
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
            LogColor::Yellow        => VGATextColor::Yellow,
            LogColor::LightGray     => VGATextColor::LightGray,
            LogColor::DarkGray      => VGATextColor::DarkGray,
            LogColor::LightBlue     => VGATextColor::LightBlue,
            LogColor::LightGreen    => VGATextColor::LightGreen,
            LogColor::LightCyan     => VGATextColor::LightCyan,
            LogColor::LightRed      => VGATextColor::LightRed,
            LogColor::LightMagenta  => VGATextColor::Magenta,

            // fallback colors
            LogColor::LightYellow   => VGATextColor::Yellow,
            LogColor::Pink          => VGATextColor::LightMagenta,
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
        let mut page_tables = ACTIVE_PAGE_TABLES.lock();

        let vga_vadr = page_tables.find_available_virtual_space::<KernelLand>(count_pages(VGA_SCREEN_MEMORY_SIZE))
            .expect("Cannot map vga text mode mmio");
        page_tables.map_range(VGA_SCREEN_ADDRESS,
                              vga_vadr,
                              count_pages(VGA_SCREEN_MEMORY_SIZE),
                              EntryFlags::WRITABLE);

        let mut ret = VGATextLoggerInternal {
            pos: (0, 0),
            buffer: unsafe { ::core::slice::from_raw_parts_mut(vga_vadr.addr() as _, VGA_SCREEN_MEMORY_SIZE) }
        };
        ret.clear();
        ret
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

impl VGATextLogger {
    fn get_internal(&mut self) -> MutexGuard<VGATextLoggerInternal> {
        G_VGATEXT.call_once(|| Mutex::new(VGATextLoggerInternal::new())).lock()
    }

    unsafe fn internal_force_unlock(&mut self) {
        G_VGATEXT.call_once(|| Mutex::new(VGATextLoggerInternal::new())).force_unlock()
    }
}

impl Logger for VGATextLogger {

    /// Prints a string to the screen
    fn print(&mut self, string: &str) {
        let string = string.as_ascii_str().expect("ASCII");
        self.get_internal().print_attr(string, VGATextPrintAttribute::default());
    }

    /// Prints a string to the screen and adds a line feed
    fn println(&mut self, string: &str) {
        let string = string.as_ascii_str().expect("ASCII");
        let mut internal = self.get_internal();
        internal.print_attr(string, VGATextPrintAttribute::default());
        internal.line_feed();
    }

    /// Prints a string to the screen with attributes
    fn print_attr(&mut self, string: &str, attr: LogAttributes) {
        let string = string.as_ascii_str().expect("ASCII");
        self.get_internal().print_attr(string, VGATextPrintAttribute::from_log_attr(&attr));
    }

    /// Prints a string to the screen with attributes and adds a line feed
    fn println_attr(&mut self, string: &str, attr: LogAttributes) {
        let string = string.as_ascii_str().expect("ASCII");
        let mut internal = self.get_internal();
        internal.print_attr(string, VGATextPrintAttribute::from_log_attr(&attr));
        internal.line_feed();
    }

    unsafe fn force_unlock(&mut self) {
        self.internal_force_unlock();
    }

    /// Clears the whole screen and resets cursor to top left
    fn clear(&mut self) {
        self.get_internal().clear();
    }
}

impl ::core::fmt::Write for VGATextLogger {
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        let logger = &mut VGATextLogger;
        logger.print(s);
        Ok(())
    }
}
