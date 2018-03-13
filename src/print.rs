/// A class for printing text to screen using the BIOS by writing in the video memory

use spin::Mutex;
use ascii::AsciiStr;
use ascii::AsAsciiStr;

const VGA_SCREEN_SIZE: (usize, usize) = (25, 80); // y, x
const VGA_SCREEN_MEMORY_SIZE: usize = 32 * 1024 / 2; // 32 ko in u16

#[cfg(not(target_os = "none"))]
static mut VGA_SPACE_DEBUG : [u16; VGA_SCREEN_MEMORY_SIZE] = [0; VGA_SCREEN_MEMORY_SIZE];

lazy_static! {
    static ref PRINTER: Mutex<PrinterInternal> = Mutex::new(PrinterInternal::new());
}

#[allow(dead_code)]
#[repr(u8)]
pub enum Color {
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

pub struct PrintAttribute(u16);

impl PrintAttribute {

    pub fn new(foreground: Color, background: Color, blink: bool) -> PrintAttribute {
        PrintAttribute(((foreground as u16) << 8)
            | ((background as u16) << 12)
            | ((blink as u16) << 15))
    }

    /// returns the u16 representing the combination of attr and letter
    fn combine_ascii(&self, ascii_letter: u8) -> u16 {
        self.0 | ((ascii_letter as u16) & 0x7F)
    }
}

impl Default for PrintAttribute {
    fn default() -> Self {
        PrintAttribute::new(Color::White, Color::Black, false)
    }
}

/// A class to print text to the screen
pub struct PrinterInternal {
    pos: (usize, usize), // (y, x)
    buffer: &'static mut [u16]
}

impl PrinterInternal {
    // Constructs a new printer
    fn new() -> PrinterInternal {
        #[cfg(target_os = "none")]
        return PrinterInternal {
            pos: (0, 0),
            buffer: unsafe { ::core::slice::from_raw_parts_mut(0xb8000 as _, VGA_SCREEN_MEMORY_SIZE) }
        };
        #[cfg(not(target_os = "none"))]
        PrinterInternal {
            pos: (0, 0),
            buffer: unsafe { ::core::slice::from_raw_parts_mut(VGA_SPACE_DEBUG.as_mut_ptr(), VGA_SCREEN_MEMORY_SIZE) }
        }
    }

    fn carriage_return(&mut self) {
        self.pos.1 = 0;
    }

    fn line_feed(&mut self) {
        if self.pos.0 == VGA_SCREEN_SIZE.0 - 1 {
            self.scroll_screen();
        } else {
            self.pos.0 += 1;
        }
        self.carriage_return();
    }

    fn advance_pos(&mut self) {
        self.pos.1 += 1;
        if self.pos.1 >= VGA_SCREEN_SIZE.1 {
            self.line_feed();
        }
    }

    /// returns the index in vga memory corresponding to self.pos
    #[inline]
    fn index_of_pos(&self) -> usize {
        (self.pos.0 * VGA_SCREEN_SIZE.1 + (self.pos.1)) //* 2
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

    /// Prints a screen to the screen with attributes
    pub fn print_attr(&mut self, string: &AsciiStr, attr: PrintAttribute) {
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
}

pub struct Printer;

impl Printer {

    /// Prints a screen to the screen with attributes
    pub fn print_attr(string: &AsciiStr, attr: PrintAttribute) {
        PRINTER.lock().print_attr(string, attr);
    }

    /// Prints a screen to the screen with attributes and adds a line feed
    pub fn println_attr(string: &AsciiStr, attr: PrintAttribute) {
        let mut myprinter = PRINTER.lock();
        myprinter.print_attr(string, attr);
        myprinter.line_feed();
    }

    /// Prints a string to the screen
    pub fn print(string: &AsciiStr) {
        PRINTER.lock().print_attr(string, PrintAttribute::default());
    }

    /// Prints a string to the screen and adds a line feed
    pub fn println(string: &AsciiStr) {
        let mut myprinter = PRINTER.lock();
        myprinter.print_attr(string, PrintAttribute::default());
        myprinter.line_feed();
    }
}

impl ::core::fmt::Write for Printer {
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        if let Ok(ascii_str) = s.as_ascii_str() {
            Printer::print(ascii_str);
            Ok(())
        } else {
            Err(::core::fmt::Error)
        }
    }
}
