//! Window creation and drawing APIs
//!
//! APIs allowing the creation of a window, and drawing inside of it.

use types::{SharedMemory, MappedSharedMemory};
use vi::{ViInterface, IBuffer};
use syscalls::MemoryPermissions;
use kfs_libutils::align_up;
use error::Error;

/// A rgb color
#[derive(Copy, Clone, Debug)]
pub struct Color {
    pub b: u8,
    pub g: u8,
    pub r: u8,
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
        let addr = ::find_free_address(size as _, 0x1000)?;
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
    pub fn write_px(&mut self, offset: usize, color: &Color) {
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
    pub fn write_px_at(&mut self, x: usize, y: usize, color: &Color) {
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

/// Some colors for the vbe
impl Color {
    pub fn rgb(r: u8, g: u8, b: u8) -> Color {
        Color {r, g, b }
    }
}
