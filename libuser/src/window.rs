//! Window creation and drawing APIs
//!
//! APIs allowing the creation of a window, and drawing inside of it.

use crate::types::{SharedMemory, MappedSharedMemory};
use crate::vi::{ViInterface, IBuffer};
use crate::syscalls::MemoryPermissions;
use crate::mem::{find_free_address, PAGE_SIZE};
use kfs_libutils::align_up;
use crate::error::Error;
use core::slice;

/// A rgb color
#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Color {
    /// Blue component
    pub b: u8,
    /// Green component
    pub g: u8,
    /// Red component
    pub r: u8,
    /// Alpha component
    pub a: u8,
}

/// Some colors for the vbe
impl Color {
    /// Creates a color from the r/g/b components. Alpha will be set to 0xFF.
    pub fn rgb(r: u8, g: u8, b: u8) -> Color {
        Color {r, g, b, a: 0xFF }
    }
}

/// A managed window.
#[derive(Debug)]
pub struct Window {
    /// The framebuffer memory shared with Vi. Drawing to this buffer will take
    /// effect on the next call to [IBuffer::draw].
    buf: MappedSharedMemory,
    /// Vi handle for this window.
    handle: IBuffer,
    /// Width of the window.
    width: usize,
    /// Height of the window.
    height: usize,
    /// Bits per pixel for the framebuffer.
    bpp: usize
}

impl Window {
    /// Creates a window in the vi compositor.
    pub fn new(vi: &mut ViInterface, top: i32, left: i32, width: u32, height: u32) -> Result<Window, Error> {
        let bpp = 32;
        let size = height * width * bpp / 8;

        let sharedmem = SharedMemory::new(align_up(size, PAGE_SIZE as _) as _, MemoryPermissions::READABLE | MemoryPermissions::WRITABLE, MemoryPermissions::READABLE)?;
        let addr = find_free_address(size as _, PAGE_SIZE)?;
        let buf = sharedmem.map(addr, align_up(size as _, PAGE_SIZE), MemoryPermissions::READABLE | MemoryPermissions::WRITABLE)?;
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

    /// Ask the compositor to redraw the window.
    pub fn draw(&mut self) -> Result<(), Error> {
        self.handle.draw()
    }

    /// window width in pixels. Does not account for bpp
    #[inline]
    pub fn width(&self) -> usize {
        self.width
    }

    /// window height in pixels. Does not account for bpp
    #[inline]
    pub fn height(&self) -> usize {
        self.height
    }

    /// The number of bits that forms a pixel.
    /// Used to compute offsets in window memory to corresponding pixel
    /// px_offset = px_nbr * bpp
    #[inline]
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
        assert!(y < self.height(), "{} {}", y, self.height());
        assert!(x < self.width());
        (y * self.width() + x)
    }

    /// Writes a pixel in the window respecting the bgr pattern
    ///
    /// # Panics
    ///
    /// Panics if offset is invalid
    #[inline]
    pub fn write_px(&mut self, offset: usize, color: Color) {
        unsafe {
            self.get_buffer()[offset] = color;
        }
    }

    /// Writes a pixel in the window respecting the bgr pattern
    /// Computes the offset in the window from x and y.
    ///
    /// # Panics
    ///
    /// Panics if coords are invalid
    #[inline]
    pub fn write_px_at(&mut self, x: usize, y: usize, color: Color) {
        let offset = self.get_px_offset(x, y);
        self.write_px(offset, color);
    }

    /// Gets the underlying framebuffer
    pub fn get_buffer(&mut self) -> &mut [Color] {
        unsafe {
            slice::from_raw_parts_mut(self.buf.get_mut().as_ptr() as *mut Color, self.buf.len() / 4)
        }
    }

    /// Clears the whole window, making it black.
    pub fn clear(&mut self) {
        let fb = self.get_buffer();
        for i in fb.iter_mut() { *i = Color::rgb(0, 0, 0); }
    }
}
