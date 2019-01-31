//! Terminal rendering APIs
//!
//! Some simple APIs to handle CLIs.
//!
//! Currently only handles printing, but will eventually support reading as well.

use alloc::prelude::*;
use font_rs::{font, font::{Font, GlyphBitmap}};
use hashbrown::HashMap;
use crate::window::{Window, Color};
use crate::error::Error;

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
    framebuffer: Window,
    /// Cursor pos, in pixels. Does not account for bpp. Reprensents the pen
    /// position on the baseline.
    cursor_pos: Pos,
    /// The font in use for this terminal.
    font: Font<'static>,
    /// We cache ascii glyphs to avoid rendering them every time.
    cached_glyphs: HashMap<char, GlyphBitmap>,
    /// Expected to be the same for every glyph since it should be a monospaced
    /// font.
    advance_width:  usize,
    /// The distance between two baselines.
    linespace: usize,
    /// The maximum ascent in the font.
    ascent: usize,
    /// The maximum descent in the font.
    descent: usize,
}

/// The font we choose to render in
static FONT:  &'static [u8] = include_bytes!("../fonts/Monaco.ttf");

/// The size we choose to render in
const FONT_SIZE: u32 = 10;

/// Window creation requested size.
#[derive(Debug, Clone, Copy)]
pub enum WindowSize {
    /// Takes the full screen.
    Fullscreen,
    /// Takes a given amount of lines.
    ///
    /// The boolean controls whether we draw from the top or the bottom.
    ///
    /// If the amount of lines is negative, then the window will take the whole
    /// screen size, minus the given amount of lines.
    FontLines(i32, bool),
    /// Manually position the window at the given x/y, with a given width and
    /// height.
    Manual(i32, i32, u32, u32)
}

impl Terminal {
    /// Creates a new Window of the requested size for terminal usage.
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn new(size: WindowSize) -> Result<Self, Error> {
        let my_font = font::parse(FONT)
            .expect("Failed parsing provided font");

        let my_ascent        =  my_font.max_ascent(FONT_SIZE).unwrap() as usize;
        let my_descent       = -my_font.max_descent(FONT_SIZE).unwrap() as usize;
        let my_advance_width =  my_font.max_advance_width(FONT_SIZE).unwrap() as usize;

        let my_linespace = my_descent + my_ascent;

        // TODO: Terminal - Get window size from vi
        // BODY: Terminal defines a fullscreen size as 1280 * 800, but should
        // BODY: really get it from vi instead. 
        let framebuffer = match size {
            WindowSize::Fullscreen => Window::new(0, 0, 1280, 800)?,
            WindowSize::FontLines(lines, is_bottom) => {
                let height = if lines < 0 {
                    let max_lines = 800 / my_linespace;
                    my_linespace * ((max_lines as i32) + lines) as usize
                } else if lines == 1 {
                    // Orycterope's fault. Scrolling expects at least one line
                    // available above it.
                    (my_linespace + 1) as usize
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
            WindowSize::Manual(top, left, width, height) => Window::new(top, left, width, height)?
        };

        Ok(Terminal {
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

    /// Ask the compositor to redraw the window.
    pub fn draw(&mut self) -> Result<(), Error> {
        self.framebuffer.draw()
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
        let _ = self.draw();
        // Are we already on the last line ?
        if self.cursor_pos.y + self.linespace + self.descent >= self.framebuffer.height() {
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
        if self.cursor_pos.x + self.advance_width >= self.framebuffer.width() {
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
        self.framebuffer.clear();
        self.cursor_pos = Pos { x: 0, y: self.ascent };
    }

    /// Prints a string to the screen with attributes
    fn print_attr(&mut self, string: &str, fg: Color, bg: Color) {
        for mychar in string.chars() {
            match mychar {
                '\n'   => { self.line_feed(); }
                '\x08' => {
                    self.move_pos_back();
                    let empty_glyph = GlyphBitmap { width: 0, height: 0, top: 0, left: 0, data: Vec::new() };
                    Self::display_glyph_in_box(&empty_glyph, &mut self.framebuffer,
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
                            Self::display_glyph_in_box(glyph, &mut self.framebuffer,
                                                       *advance_width, *ascent, *descent,
                                                       fg, bg, *cursor_pos);
                        } else {
                            // Simply render the glyph and display it ...
                            let glyph = font.lookup_glyph_id(mychar as u32)
                                .and_then(|glyphid| font.render_glyph(glyphid, FONT_SIZE))
                                .unwrap_or(GlyphBitmap { width: 0, height: 0, top: 0, left: 0, data: Vec::new() });
                            Self::display_glyph_in_box(&glyph, &mut self.framebuffer,
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
    fn display_glyph_in_box(glyph: &GlyphBitmap, framebuffer: &mut Window,
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
                framebuffer.write_px_at((pos.x as i32 + x) as usize,
                                             (pos.y as i32 + y) as usize,
                                             to_display);
            }
        }
    }
}

impl ::core::fmt::Write for Terminal {
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        let fg = Color::rgb(255, 255, 255);
        let bg = Color::rgb(0, 0, 0);
        self.print_attr(s, fg, bg);
        Ok(())
    }
}
