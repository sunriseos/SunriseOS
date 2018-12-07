//! VESA Bios Extensions Framebuffer
//! and VBE logger

use alloc::prelude::*;
//use utils;
//use i386::mem::paging::{self, EntryFlags, PageTablesSet};
//use frame_alloc::PhysicalAddress;
//use multiboot2::{BootInformation, FramebufferInfoTag};
use logger::{Logger, LogAttributes, LogColor};
use font_rs::{font, font::{Font, GlyphBitmap}};
use spin::{Mutex, MutexGuard, Once};
use hashmap_core::HashMap;
use kfs_libuser::syscalls::{self, MemoryPermissions};
use kfs_libuser;
use kfs_libuser::types::{SharedMemory, MappedSharedMemory};
use kfs_libuser::error::Error;
use vi::{ViInterface, IBuffer};
use kfs_libutils::align_up;

/// A rgb color
#[derive(Copy, Clone, Debug)]
pub struct VBEColor {
    b: u8,
    g: u8,
    r: u8,
}

pub struct Window {
    buf: MappedSharedMemory,
    handle: IBuffer,
    width: usize,
    height: usize,
    bpp: usize
}


impl Window {
    /// Creates a window in the vi compositor.
    pub fn new(top: i32, left: i32, width: u32, height: u32) -> Result<Window, Error> {
        let mut vi = ViInterface::raw_new()?;

        let bpp = 4;
        let size = height * width * bpp;

        let sharedmem = SharedMemory::new(align_up(size, 0x1000) as _, MemoryPermissions::READABLE | MemoryPermissions::WRITABLE, MemoryPermissions::READABLE)?;
        let addr = kfs_libuser::find_free_address(size as _, 0x1000)?;
        let buf = sharedmem.map(addr, align_up(size as _, 0x1000), MemoryPermissions::READABLE | MemoryPermissions::WRITABLE)?;
        let handle = vi.create_buffer(buf.as_shared_mem(), top, left, width, height)?;

        let mut fb = Window {
            buf,
            handle,
            width: width as _,
            height: height as _,
            bpp: 32
        };
        fb.clear();
        Ok(fb)
    }

    pub fn draw(&mut self) -> Result<(), Error> {
        self.handle.draw()
    }

    /// framebuffer width in pixels. Does not account for bpp
    #[inline]
    pub fn width(&self) -> usize {
        self.width
    }

    /// framebuffer height in pixels. Does not account for bpp
    #[inline]
    pub fn height(&self) -> usize {
        self.height
    }

    /// The number of bits that forms a pixel.
    /// Used to compute offsets in framebuffer memory to corresponding pixel
    /// px_offset = px_nbr * bpp
    #[inline]
    pub fn bpp(&self) -> usize {
        self.bpp
    }

    /// Gets the offset in memory of a pixel based on an x and y.
    /// Does not guaranty that the result is valid, it can fall outside the
    /// screen if x or y are to big.
    #[inline]
    pub fn get_px_offset(&self, x: usize, y: usize) -> usize {
        (y * self.width() + x) * (self.bpp() / 8)
    }

    /// Writes a pixel in the framebuffer respecting the bgr pattern
    ///
    /// # Panics
    ///
    /// Panics if offset is invalid
    #[inline]
    pub fn write_px(&mut self, offset: usize, color: &VBEColor) {
        unsafe {
            self.buf.get_mut()[offset + 0] = color.b;
            self.buf.get_mut()[offset + 1] = color.g;
            self.buf.get_mut()[offset + 2] = color.r;
        }
    }

    /// Writes a pixel in the framebuffer respecting the bgr pattern
    /// Computes the offset in the framebuffer from x and y
    ///
    /// # Panics
    ///
    /// Panics if coords are invalid
    #[inline]
    pub fn write_px_at(&mut self, x: usize, y: usize, color: &VBEColor) {
        let offset = self.get_px_offset(x, y);
        self.write_px(offset, color);
    }

    pub fn get_fb(&mut self) -> &mut [u8] {
        unsafe {
            self.buf.get_mut()
        }
    }

    /// Clears the whole screen
    pub fn clear(&mut self) {
        let fb = self.get_fb();
        for i in fb.iter_mut() { *i = 0x00; }
    }
}

/* ********************************************************************************************** */

/* implementing the logger */

/// Some colors for the vbe
impl VBEColor {
    fn rgb(r: u8, g: u8, b: u8) -> VBEColor {
        VBEColor {r, g, b }
    }

    fn from_log_color(orig: LogColor) -> VBEColor {
        match orig {
            LogColor::DefaultBackground => Self::rgb(0x00, 0x00, 0x00),
            LogColor::DefaultForeground => Self::rgb(0xff, 0xff, 0xff),

            // CGA colors
            LogColor::Black         => Self::rgb(0x00, 0x00, 0x00),
            LogColor::Blue          => Self::rgb(0x00, 0x00, 0xaa),
            LogColor::Green         => Self::rgb(0x00, 0xaa, 0x00),
            LogColor::Cyan          => Self::rgb(0x00, 0xaa, 0xaa),
            LogColor::Red           => Self::rgb(0xaa, 0x00, 0x00),
            LogColor::Magenta       => Self::rgb(0xaa, 0x00, 0xaa),
            LogColor::Brown         => Self::rgb(0xaa, 0x55, 0x00),
            LogColor::LightGray     => Self::rgb(0xaa, 0xaa, 0xaa),
            LogColor::DarkGray      => Self::rgb(0x55, 0x55, 0x55),
            LogColor::LightBlue     => Self::rgb(0x55, 0x55, 0xff),
            LogColor::LightGreen    => Self::rgb(0x55, 0xff, 0x55),
            LogColor::LightCyan     => Self::rgb(0x55, 0xff, 0xff),
            LogColor::LightRed      => Self::rgb(0xff, 0x55, 0x55),
            LogColor::LightMagenta  => Self::rgb(0xff, 0x55, 0xff),
            LogColor::Yellow        => Self::rgb(0xff, 0xff, 0x55),
            LogColor::White         => Self::rgb(0xff, 0xff, 0xff),

            // X11 colors
            LogColor::Pink          => Self::rgb(0xff, 0xc0, 0xcb),
            LogColor::LightYellow   => Self::rgb(0xff, 0xff, 0xe0),
        }
    }
}

/// Just an x and a y
#[derive(Copy, Clone, Debug)]
struct Pos {
    x: usize,
    y: usize,
}

/// A struct for logging text to the vbe screen.
/// Renders characters from a .ttf font using the font-rs crate
pub struct VBELogger {
    framebuffer: Window,
    cursor_pos: Pos,        /* Cursor pos, in pixels. Does not account for bpp.
                               Reprensents the pen position on the baseline. */
    font: Font<'static>,
    cached_glyphs: HashMap<char, GlyphBitmap>, /* We cache ascii glyphs
                                                  to avoid rendering them every time */
    advance_width:  usize, /* Expected to be the same for every glyph since
                              it should be a monospaced font */
    linespace: usize,      /* The distance between two baselines */
    ascent: usize,         /* The maximum ascent  in the font. */
    descent: usize,        /* The maximum descent in the font. */
}

/// The font we choose to render in
static FONT:  &'static [u8] = include_bytes!("../../shell/img/Monaco.ttf");

/// The size we choose to render in
const FONT_SIZE: u32 = 10;

pub enum WindowSize {
    Fullscreen, FontLines(i32, bool), Manual(i32, i32, u32, u32)
}

impl VBELogger {
    pub fn new(size: WindowSize) -> Result<Self, Error> {
        let my_font = font::parse(FONT)
            .expect("Failed parsing provided font");

        let my_ascent        =  my_font.max_ascent(FONT_SIZE).unwrap() as usize;
        let my_descent       = -my_font.max_descent(FONT_SIZE).unwrap() as usize;
        let my_advance_width =  my_font.max_advance_width(FONT_SIZE).unwrap() as usize;

        let my_linespace = my_descent + my_ascent;

        let framebuffer = match size {
            WindowSize::Fullscreen => Window::new(0, 0, 1280, 800)?,
            WindowSize::FontLines(lines, is_bottom) => {
                let height = if lines < 0 {
                    let max_lines = 800 / my_linespace;
                    my_linespace * ((max_lines as i32) + lines) as usize
                } else {
                    my_linespace * lines as usize
                };
                let top = if is_bottom {
                    800 - height
                } else {
                    0
                };
                Window::new(top as i32, 0, 1280, height as u32)?
            }
            WindowSize::Manual(top, left, width, height) => Window::new(0, 0, width, height)?
        };

        Ok(VBELogger {
            framebuffer,
            font: my_font,
            cached_glyphs: HashMap::with_capacity(128), // the ascii table
            advance_width: my_advance_width,
            linespace: my_linespace,
            ascent: my_ascent,
            descent: my_descent,
            cursor_pos: Pos { x: 0, y: my_ascent },
        })
    }

    pub fn draw(&mut self) -> Result<(), Error> {
        self.framebuffer.draw()
    }

    #[inline]
    fn carriage_return(&mut self) {
        self.cursor_pos.x = 0;
    }

    #[inline]
    fn line_feed(&mut self) {
        let _ = self.draw();
        // Are we already on the last line ?
        if self.cursor_pos.y + self.linespace + self.descent >= self.framebuffer.height() {
            self.scroll_screen();
        } else {
            self.cursor_pos.y += self.linespace;
        }
        self.carriage_return();
    }

    #[inline]
    fn advance_pos(&mut self) {
        self.cursor_pos.x += self.advance_width;
        // is next displayed char going to be cut out of screen ?
        if self.cursor_pos.x + self.advance_width >= self.framebuffer.width() {
            self.line_feed();
        }
    }

    fn move_pos_back(&mut self) {
        if self.cursor_pos.x >= self.advance_width {
            self.cursor_pos.x -= self.advance_width;
        }
    }

    #[inline]
    /// scrolls the whole screen by one line.
    /// self.pos must be on last baseline.
    fn scroll_screen(&mut self) {
        let linespace_size_in_framebuffer = self.framebuffer.get_px_offset(0, self.linespace);
        let lastline_top_left_corner = self.framebuffer.get_px_offset(0, self.cursor_pos.y - self.ascent);
        // Copy up from the line under it
        assert!(lastline_top_left_corner + linespace_size_in_framebuffer < self.framebuffer.buf.len(), "Window is drunk: {} + {} < {}", lastline_top_left_corner, linespace_size_in_framebuffer, self.framebuffer.buf.len());
        unsafe {
            // memmove in the same slice. Should be safe with the assert above.
            ::core::ptr::copy(self.framebuffer.buf.as_ptr().offset(linespace_size_in_framebuffer as isize),
                              self.framebuffer.buf.as_mut_ptr(),
                              lastline_top_left_corner);
        }
        // Erase last line
        unsafe {
            // memset to 0x00. Should be safe with the assert above
            ::core::ptr::write_bytes(self.framebuffer.buf.as_mut_ptr().offset(lastline_top_left_corner as isize),
                                    0x00,
                                    self.framebuffer.buf.len() - lastline_top_left_corner);
        }
    }

    /// Clears the whole screen and reset cursor
    fn clear(&mut self) {
        self.framebuffer.clear();
        self.cursor_pos = Pos { x: 0, y: self.ascent };
    }

    /// Prints a string to the screen with attributes
    fn print_attr(&mut self, string: &str, fg: VBEColor, bg: VBEColor) {
        for mychar in string.chars() {
            match mychar {
                '\n'   => { self.line_feed(); }
                '\x08' => {
                    self.move_pos_back();
                    let empty_glyph = GlyphBitmap { width: 0, height: 0, top: 0, left: 0, data: Vec::new() };
                    Self::display_glyph_in_box(&empty_glyph, &mut self.framebuffer,
                                               self.advance_width, self.ascent, self.descent,
                                                &fg, &bg, self.cursor_pos);
                }
                mychar => {
                    {
                        let VBELogger {
                            cached_glyphs, font, advance_width, ascent, descent, cursor_pos, ..
                        } = self;

                        // Try to get the rendered char from the cache
                        if (mychar as u64) < 128 {
                            // It's ascii, so if it's not already in the cache, add it !
                            let glyph = cached_glyphs.entry(mychar)
                                .or_insert_with(|| {
                                    font.lookup_glyph_id(mychar as u32)
                                        .and_then(|glyphid| font.render_glyph(glyphid, FONT_SIZE))
                                        .unwrap_or(GlyphBitmap { width: 0, height: 0, top: 0, left: 0, data: Vec::new() })
                                });
                            Self::display_glyph_in_box(glyph, &mut self.framebuffer,
                                                       *advance_width, *ascent, *descent,
                                                       &fg, &bg, *cursor_pos);
                        } else {
                            // Simply render the glyph and display it ...
                            let glyph = font.lookup_glyph_id(mychar as u32)
                                .and_then(|glyphid| font.render_glyph(glyphid, FONT_SIZE))
                                .unwrap_or(GlyphBitmap { width: 0, height: 0, top: 0, left: 0, data: Vec::new() });
                            Self::display_glyph_in_box(&glyph, &mut self.framebuffer,
                                                       *advance_width, *ascent, *descent,
                                                       &fg, &bg, *cursor_pos);
                        }
                    }
                    self.advance_pos();
                }
            }
        }
    }

    /// Copies a rendered character to the screen, displaying it in a bg colored box
    ///
    /// # Panics
    ///
    /// Panics if pos makes writing the glyph overflow the screen
    fn display_glyph_in_box(glyph: &GlyphBitmap, framebuffer: &mut Window,
                            box_width: usize, box_ascent: usize, box_descent: usize,
                            fg: &VBEColor, bg: &VBEColor, pos: Pos) {

        /// Blends foreground and background subpixels together
        /// by doing a weighted average of fg and bg
        #[inline]
        fn blend_subpixels(fg: u8, bg: u8, fg_alpha: u8) -> u8 {
            // compute everything u16 to avoid overflows
            ((   fg as u16 * fg_alpha as u16
               + bg as u16 * (0xFF - fg_alpha) as u16
             ) / 0xFF // the weight should be (fg_alpha / 0xFF), but we move this division
                      // as final step so we don't loose precision
            ) as u8
        }

        /* The GlyphBitmap represents a small box, that fits inside an imaginary
           bigger box, that we want to color */

        // The bigger box
        for y in -(box_ascent as i32)..=(box_descent as i32) {
            for x in 0..(box_width as i32) {
                // translate x,y as glyph coordinates
                let glyphx: i32 = x - glyph.left;
                let glyphy: i32 = y - glyph.top;
                // compute the color to display
                let to_display =
                if glyphx >= 0 && glyphy >= 0
                && glyphx < (glyph.width as i32) && glyphy < (glyph.height as i32) {
                    // it's inside the glyph box !
                    // blend foreground and background colors according to intensity
                    let glyph_alpha = glyph.data[glyphy as usize * glyph.width + glyphx as usize];
                    VBEColor::rgb(
                        blend_subpixels(fg.r, bg.r, glyph_alpha),
                        blend_subpixels(fg.g, bg.g, glyph_alpha),
                        blend_subpixels(fg.b, bg.b, glyph_alpha),
                    )
                } else {
                    // it's oustide the glyph box, just paint it bg color
                    *bg
                };
                framebuffer.write_px_at((pos.x as i32 + x) as usize,
                                             (pos.y as i32 + y) as usize,
                                             &to_display);
            }
        }
    }
}

impl Logger for VBELogger {

    /// Prints a string to the screen
    fn print(&mut self, string: &str) {
        let fg = VBEColor::from_log_color(LogColor::DefaultForeground);
        let bg = VBEColor::from_log_color(LogColor::DefaultBackground);
        self.print_attr(string, fg, bg);
    }

    /// Prints a string to the screen and adds a line feed
    fn println(&mut self, string: &str) {
        let fg = VBEColor::from_log_color(LogColor::DefaultForeground);
        let bg = VBEColor::from_log_color(LogColor::DefaultBackground);
        self.print_attr(string, fg, bg);
        self.line_feed();
    }

    /// Prints a string to the screen with attributes
    fn print_attr(&mut self, string: &str, attr: LogAttributes) {
        let fg = VBEColor::from_log_color(attr.foreground);
        let bg = VBEColor::from_log_color(attr.background);
        self.print_attr(string, fg, bg);
    }

    /// Prints a string to the screen with attributes and adds a line feed
    fn println_attr(&mut self, string: &str, attr: LogAttributes) {
        let fg = VBEColor::from_log_color(attr.foreground);
        let bg = VBEColor::from_log_color(attr.background);
        self.print_attr(string, fg, bg);
        self.line_feed();
    }

    /// Clears the whole screen and resets cursor to top left
    fn clear(&mut self) {
        self.clear();
    }
}

impl ::core::fmt::Write for VBELogger {
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        self.print(s);
        Ok(())
    }
}
