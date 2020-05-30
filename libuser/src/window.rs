//! Window creation and drawing APIs
//!
//! APIs allowing the creation of a window, and drawing inside of it.

use crate::types::{SharedMemory, MappedSharedMemory};
use crate::vi::{ViInterfaceProxy, IBufferProxy};
use crate::syscalls::MemoryPermissions;
use crate::mem::{find_free_address, PAGE_SIZE};
use sunrise_libutils::align_up;
use crate::error::Error;
use core::slice;
use core::sync::atomic::{AtomicU32, Ordering};

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
    pub const fn rgb(r: u8, g: u8, b: u8) -> Color {
        Color {r, g, b, a: 0xFF }
    }
}

/// A managed window.
#[derive(Debug)]
pub struct Window {
    /// The framebuffer memory shared with Vi. Drawing to this buffer will take
    /// effect on the next call to [IBufferProxy::draw].
    buf: MappedSharedMemory,
    /// Vi handle for this window.
    handle: IBufferProxy,
    /// Width of the window.
    width: usize,
    /// Height of the window.
    height: usize,
    /// Bits per pixel for the framebuffer.
    bpp: usize
}

impl Window {
    /// Creates a window in the vi compositor.
    pub fn new(top: i32, left: i32, width: u32, height: u32) -> Result<Window, Error> {
        let vi = ViInterfaceProxy::raw_new()?;
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
        core::sync::atomic::fence(Ordering::Release);
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
        y * self.width() + x
    }

    /// Writes a pixel in the window respecting the bgr pattern
    ///
    /// # Panics
    ///
    /// Panics if offset is invalid
    #[inline]
    pub fn write_px(&mut self, offset: usize, color: Color) {
        unsafe {
            // Safety: Color can safely be cast to an u32.
            self.get_buffer()[offset].store(core::mem::transmute(color), Ordering::Relaxed);
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
    #[allow(clippy::cast_ptr_alignment)] // See safety note.
    pub fn get_buffer(&mut self) -> &[AtomicU32] {
        unsafe {
            // Safety: buf is guaranteed to be valid for len bytes (so len / 4
            // u32s). The lifetime is tied to the MappedSharedMemory. Buf is
            // guaranteed to be page-aligned.
            slice::from_raw_parts(self.buf.as_ptr() as *const AtomicU32, self.buf.len() / 4)
        }
    }

    /// Clears the whole window, making it black.
    pub fn clear(&mut self) {
        let fb = self.get_buffer();
        for i in fb.iter() { i.store(0, Ordering::Relaxed); }
    }
}
