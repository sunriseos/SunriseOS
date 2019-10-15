//! Terminal rendering APIs
//!
//! Some simple APIs to handle CLIs.
//!
//! Currently only handles printing, but will eventually support reading as well.

use alloc::sync::Arc;
use alloc::vec::Vec;
use font_rs::{font, font::{Font, GlyphBitmap}};
use hashbrown::HashMap;
use spin::Mutex;
use sunrise_libuser::error::{ViError, Error};
use sunrise_libuser::futures::WorkQueue;
use sunrise_libuser::mem::{find_free_address, PAGE_SIZE};
use sunrise_libuser::types::SharedMemory;
use sunrise_libutils::align_up;
use sunrise_libkern::MemoryPermissions;
use crate::Buffer;
use crate::VBEColor as Color;
use core::fmt::Write;

/// Just an x and a y
#[derive(Copy, Clone, Debug)]
#[allow(clippy::missing_docs_in_private_items)]
struct Pos {
    x: usize,
    y: usize,
}

/// A struct for logging text to the window.
/// Renders characters from a .ttf font using the font-rs crate
#[allow(missing_debug_implementations)] // Font does not implement Debug :/ Maybe I could do a PR
pub struct Terminal {
    /// Rendering target for this terminal.
    framebuffer: Arc<Buffer>,
    /// Cursor pos, in pixels. Does not account for bpp. Reprensents the pen
    /// position on the baseline.
    cursor_pos: Pos,
    /// The font in use for this terminal.
    font: Font<'static>,
    /// We cache ascii glyphs to avoid rendering them every time.
    cached_glyphs: HashMap<char, GlyphBitmap>,
    /// Expected to be the same for every glyph since it should be a monospaced
    /// font.
    advance_width: usize,
    /// The distance between two baselines.
    linespace: usize,
    /// The maximum ascent in the font.
    ascent: usize,
    /// The maximum descent in the font.
    descent: usize,
}

/// The font we choose to render in
static FONT:  &[u8] = include_bytes!("../../external/fonts/Monaco.ttf");

/// Get the height of the built-in monospaced font.
#[allow(clippy::cast_sign_loss)]
pub fn font_height() -> usize {
    let my_font = font::parse(FONT)
        .expect("Failed parsing provided font");

    let v_metrics        = my_font.get_v_metrics(FONT_SIZE).unwrap();
    let my_ascent        =  v_metrics.ascent as usize;
    let my_descent       = -v_metrics.descent as usize;

    my_descent + my_ascent
}

/// The size we choose to render in
const FONT_SIZE: u32 = 10;

impl Terminal {
    /// Creates a new Window of the requested size for terminal usage.
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn new(sharedmem: SharedMemory, top: i32, left: i32, width: u32, height: u32) -> Result<Self, Error> {
        let my_font = font::parse(FONT)
            .expect("Failed parsing provided font");

        let v_metrics        = my_font.get_v_metrics(FONT_SIZE).unwrap();
        let h_metrics        = my_font.get_h_metrics(my_font.lookup_glyph_id('A' as u32).unwrap(), FONT_SIZE).unwrap();
        let my_ascent        =  v_metrics.ascent as usize;
        let my_descent       = -v_metrics.descent as usize;
        let my_advance_width =  h_metrics.advance_width as usize;

        let my_linespace = my_descent + my_ascent;

        let size = align_up(width * height * 4, PAGE_SIZE as _);
        let addr = find_free_address(size as _, PAGE_SIZE)?;
        let mapped = sharedmem.map(addr, size as _, MemoryPermissions::READABLE | MemoryPermissions::WRITABLE)?;
        let buf = Arc::new(Buffer { mem: mapped, top, left, width, height });
        super::BUFFERS.lock().push(Arc::downgrade(&buf));

        Ok(Terminal {
            framebuffer: buf,
            font: my_font,
            cached_glyphs: HashMap::with_capacity(128), // the ascii table
            advance_width: my_advance_width,
            linespace: my_linespace,
            ascent: my_ascent,
            descent: my_descent,
            cursor_pos: Pos { x: 0, y: my_ascent },
        })
    }

    /// Ask the compositor to redraw the window.
    pub fn draw(&mut self) {
        self.framebuffer.draw();
    }

    /// Move the cursor to the beginning of the current line.
    #[inline]
    fn carriage_return(&mut self) {
        self.cursor_pos.x = 0;
    }

    /// Move the cursor to the beginning of the next line, scrolling the screen
    /// if necessary.
    #[inline]
    fn line_feed(&mut self) {
        // Are we already on the last line ?
        if self.cursor_pos.y + self.linespace + self.descent >= self.framebuffer.height() as usize {
            self.scroll_screen();
        } else {
            self.cursor_pos.y += self.linespace;
        }
        self.carriage_return();
    }

    /// Move the cursor to the next position for drawing a character, possibly
    /// the next line if we need to wrap.
    #[inline]
    fn advance_pos(&mut self) {
        self.cursor_pos.x += self.advance_width;
        // is next displayed char going to be cut out of screen ?
        if self.cursor_pos.x + self.advance_width >= self.framebuffer.width() as usize {
            self.line_feed();
        }
    }

    /// Move the cursor back to the previous position. If we are already on the
    /// first character position on this line, do not move.
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
        assert!(lastline_top_left_corner + linespace_size_in_framebuffer < self.framebuffer.get_buffer().len(), "Window is drunk: {} + {} < {}", lastline_top_left_corner, linespace_size_in_framebuffer, self.framebuffer.get_buffer().len());
        unsafe {
            // memmove in the same slice. Should be safe with the assert above.
            ::core::ptr::copy(self.framebuffer.get_buffer().as_ptr().add(linespace_size_in_framebuffer),
                              self.framebuffer.get_buffer().as_mut_ptr(),
                              lastline_top_left_corner);
        }
        // Erase last line
        unsafe {
            // memset to 0x00. Should be safe with the assert above
            ::core::ptr::write_bytes(self.framebuffer.get_buffer().as_mut_ptr().add(lastline_top_left_corner),
                                    0x00,
                                    self.framebuffer.get_buffer().len() - lastline_top_left_corner);
        }
    }

    /// Clears the whole screen and reset cursor
    pub fn clear(&mut self) {
        unsafe {
            // Safety: it can't change from under us, we're the only owner.
            let buf = self.framebuffer.get_buffer();
            for i in buf {
                *i = 0;
            }
        }
        self.cursor_pos = Pos { x: 0, y: self.ascent };
    }

    /// Prints a string to the screen with attributes
    pub fn print_attr(&mut self, string: &str, fg: Color, bg: Color) {
        for mychar in string.chars() {
            match mychar {
                '\n'   => { self.line_feed(); }
                '\x08' => {
                    self.move_pos_back();
                    let empty_glyph = GlyphBitmap { width: 0, height: 0, top: 0, left: 0, data: Vec::new() };
                    Self::display_glyph_in_box(&empty_glyph, &self.framebuffer,
                                               self.advance_width, self.ascent, self.descent,
                                                fg, bg, self.cursor_pos);
                }
                mychar => {
                    {
                        let Terminal {
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
                            Self::display_glyph_in_box(glyph, &self.framebuffer,
                                                       *advance_width, *ascent, *descent,
                                                       fg, bg, *cursor_pos);
                        } else {
                            // Simply render the glyph and display it ...
                            let glyph = font.lookup_glyph_id(mychar as u32)
                                .and_then(|glyphid| font.render_glyph(glyphid, FONT_SIZE))
                                .unwrap_or(GlyphBitmap { width: 0, height: 0, top: 0, left: 0, data: Vec::new() });
                            Self::display_glyph_in_box(&glyph, &self.framebuffer,
                                                       *advance_width, *ascent, *descent,
                                                       fg, bg, *cursor_pos);
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
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_wrap)]
    #[allow(clippy::too_many_arguments)]
    fn display_glyph_in_box(glyph: &GlyphBitmap, framebuffer: &Buffer,
                            box_width: usize, box_ascent: usize, box_descent: usize,
                            fg: Color, bg: Color, pos: Pos) {

        /// Blends foreground and background subpixels together
        /// by doing a weighted average of fg and bg
        #[inline]
        fn blend_subpixels(fg: u8, bg: u8, fg_alpha: u8) -> u8 {
            // compute everything u16 to avoid overflows
            ((   u16::from(fg) * u16::from(fg_alpha)
               + u16::from(bg) * u16::from(0xFF - fg_alpha)
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
                    Color::rgb(
                        blend_subpixels(fg.r, bg.r, glyph_alpha),
                        blend_subpixels(fg.g, bg.g, glyph_alpha),
                        blend_subpixels(fg.b, bg.b, glyph_alpha),
                    )
                } else {
                    // it's oustide the glyph box, just paint it bg color
                    bg
                };

                let idx = framebuffer.get_px_offset(
                        (pos.x as i32 + x) as usize,
                        (pos.y as i32 + y) as usize) * 4;
                unsafe {
                    // Safety: We're the only owner of that buffer
                    framebuffer.get_buffer()[idx + 0] = to_display.b;
                    framebuffer.get_buffer()[idx + 1] = to_display.g;
                    framebuffer.get_buffer()[idx + 2] = to_display.r;
                    framebuffer.get_buffer()[idx + 3] = to_display.a;
                }
            }
        }
    }
}

impl Write for Terminal {
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        let fg = Color::rgb(255, 255, 255);
        let bg = Color::rgb(0, 0, 0);
        self.print_attr(s, fg, bg);
        Ok(())
    }
}

/// Twili IPipe implementation on a Vi Terminal.
#[derive(Clone)]
pub struct TerminalPipe {
    /// Inner terminal.
    terminal: Arc<Mutex<Terminal>>
}

impl TerminalPipe {
    /// Create a new TerminalPipe from an existing Terminal.
    pub fn new(terminal: Terminal) -> TerminalPipe {
        TerminalPipe {
            terminal: Arc::new(Mutex::new(terminal))
        }
    }
}

impl sunrise_libuser::twili::IPipe for TerminalPipe {
    fn read(&mut self, _manager: WorkQueue<'static>, _buf: &mut [u8]) -> Result<u64, Error> {
        // TODO: Connect to keyboard, read a line.
        unimplemented!()
    }
    fn write(&mut self, _manager: WorkQueue<'static>, data: &[u8]) -> Result<(), Error> {
        log::info!("Do we get here?");
        // TODO: Parse data for ANSI codes.
        // BODY: It'd be nice to parse ANSI codes so we can move the cursor
        // BODY: around 'n stuff.
        // BODY:
        // BODY: Check out https://docs.rs/ansi-parser/
        let s = core::str::from_utf8(data).or(Err(ViError::InvalidUtf8))?;
        let mut locked = self.terminal.lock();
        locked.write_str(s);
        locked.draw();
        Ok(())
    }
}