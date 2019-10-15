//! VESA Bios Extensions Framebuffer

use spin::Mutex;
use crate::syscalls;
use crate::libuser::error::Error;
use core::slice;

/// A rgb color
#[derive(Copy, Clone, Debug)]
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct VBEColor {
    pub b: u8,
    pub g: u8,
    pub r: u8,
    pub a: u8, // Unused
}

/// Some colors for the vbe
impl VBEColor {
    /// Creates a VBEColor from the given red/green/blue component. Alpha is set
    /// to 0.
    pub const fn rgb(r: u8, g: u8, b: u8) -> VBEColor {
        VBEColor {r, g, b, a: 0 }
    }
}

/// A wrapper around a linear framebuffer. The framebuffer is usually acquired
/// through the [map_framebuffer](syscalls::map_framebuffer) syscall.
#[allow(clippy::missing_docs_in_private_items)]
pub struct Framebuffer<'a> {
    buf: &'a mut [VBEColor],
    width: usize,
    height: usize,
    /// Bits-per-pixel. Usually 8.
    bpp: usize
}


impl<'a> Framebuffer<'a> {
    /// Creates an instance of the linear framebuffer.
    ///
    /// # Safety
    ///
    /// This function should only be called once, to ensure there is only a
    /// single mutable reference to the underlying framebuffer.
    pub fn new() -> Result<Framebuffer<'static>, Error> {
        let (buf, width, height, bpp) = syscalls::map_framebuffer()?;

        let mut fb = Framebuffer {
            buf: unsafe { slice::from_raw_parts_mut(buf as *mut _ as *mut _ as *mut VBEColor, buf.len() / 4) },
            width,
            height,
            bpp
        };
        fb.clear();
        Ok(fb)
    }

    /// Creates a backbuffer backed by an in-memory array.
    ///
    /// This is useful to avoid flickering and other display artifact.
    /// Compositing should happen in such a backbuffer, and the final result
    /// should then be copied into the actual framebuffer.
    pub fn new_buffer(buf: &'a mut [VBEColor], width: usize, height: usize, bpp: usize) -> Framebuffer<'a> {
        Framebuffer { buf, width, height, bpp }
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
    #[allow(dead_code)]
    pub fn bpp(&self) -> usize {
        self.bpp
    }

    /// Gets the offset in memory of a pixel based on an x and y.
    ///
    /// # Panics
    ///
    /// Panics if `y >= self.height()` or `x >= self.width()`
    #[inline]
    pub fn get_px_offset(&self, x: usize, y: usize) -> usize {
        assert!(y < self.height());
        assert!(x < self.width());
        (y * self.width() + x)
    }

    /// Writes a pixel in the framebuffer respecting the bgr pattern
    ///
    /// # Panics
    ///
    /// Panics if offset is invalid
    #[inline]
    pub fn write_px(&mut self, offset: usize, color: VBEColor) {
        self.buf[offset] = color;
    }

    /// Writes a pixel in the framebuffer respecting the bgr pattern
    /// Computes the offset in the framebuffer from x and y
    ///
    /// # Panics
    ///
    /// Panics if coords are invalid
    #[inline]
    pub fn write_px_at(&mut self, x: usize, y: usize, color: VBEColor) {
        let offset = self.get_px_offset(x, y);
        self.write_px(offset, color);
    }

    /// Gets the underlying framebuffer
    pub fn get_fb(&mut self) -> &mut [VBEColor] {
        self.buf
    }

    /// Clears the whole screen
    pub fn clear(&mut self) {
        let fb = self.get_fb();
        for i in fb.iter_mut() { *i = VBEColor::rgb(0, 0, 0); }
    }

    /// Clears a segment of the screen.
    ///
    /// # Panics
    ///
    /// Panics if x + width or y + height falls outside the framebuffer.
    pub fn clear_at(&mut self, x: usize, y: usize, width: usize, height: usize) {
        for y in y..y + height {
            for x in x..x + width {
                self.write_px_at(x, y, VBEColor::rgb(0, 0, 0));
            }
        }
    }
}

lazy_static! {
    pub static ref FRAMEBUFFER: Mutex<Framebuffer<'static>> = Mutex::new(Framebuffer::new().unwrap());
}
