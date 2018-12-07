//! VESA Bios Extensions Framebuffer
//! and VBE logger

use alloc::prelude::*;
//use utils;
//use i386::mem::paging::{self, EntryFlags, PageTablesSet};
//use frame_alloc::PhysicalAddress;
//use multiboot2::{BootInformation, FramebufferInfoTag};
//use logger::{Logger, LogAttributes, LogColor};
//use font_rs::{font, font::{Font, GlyphBitmap}};
use spin::{Mutex, MutexGuard, Once};
use hashmap_core::HashMap;
use syscalls;
use libuser::error::Error;

/// A rgb color
#[derive(Copy, Clone, Debug)]
pub struct VBEColor {
    b: u8,
    g: u8,
    r: u8,
}

pub struct Framebuffer {
    buf: &'static mut [u8],
    width: usize,
    height: usize,
    bpp: usize
}


impl Framebuffer {
    /// Creates an instance of the linear framebuffer from a multiboot2 BootInfo.
    ///
    /// # Safety
    ///
    /// This function should only be called once, to ensure there is only a
    /// single mutable reference to the underlying framebuffer.
    pub fn new() -> Result<Framebuffer, Error> {
        let (buf, width, height, bpp) = syscalls::map_framebuffer()?;

        //debug!("VBE vaddr: {:#010x}", buf.as_ptr() as usize);
        let mut fb = Framebuffer {
            buf,
            width,
            height,
            bpp
        };
        fb.clear();
        Ok(fb)
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
        self.buf[offset + 0] = color.b;
        self.buf[offset + 1] = color.g;
        self.buf[offset + 2] = color.r;
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
        if offset == 4096000 {
            syscalls::output_debug_string(&format!("What the fuck: {} {}", x, y));
        }
        self.write_px(offset, color);
    }

    pub fn get_fb(&mut self) -> &mut [u8] {
        self.buf
    }

    /// Clears the whole screen
    pub fn clear(&mut self) {
        let fb = self.get_fb();
        for i in fb.iter_mut() { *i = 0x00; }
    }

    pub fn clear_at(&mut self, x: usize, y: usize, width: usize, height: usize) {
        for y in y..y + height {
            for x in x..x + width {
                self.write_px_at(x, y, &VBEColor::rgb(0, 0, 0));
            }
        }
    }
}

lazy_static! {
    pub static ref FRAMEBUFFER: Mutex<Framebuffer> = Mutex::new(Framebuffer::new().unwrap());
}

/// Some colors for the vbe
impl VBEColor {
    pub fn rgb(r: u8, g: u8, b: u8) -> VBEColor {
        VBEColor {r, g, b }
    }
}
