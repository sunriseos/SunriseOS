//! Terminal rendering APIs
//!
//! A wrapper around vi's Terminal API to make it easier to use.

use arrayvec::ArrayVec;
use sunrise_libkern::MemoryPermissions;

use crate::error::Error;
use crate::mem::PAGE_SIZE;
use crate::types::SharedMemory;
use crate::vi::ViInterfaceProxy;
use crate::utils::align_up;

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

/// A struct for logging text to the window.
///
/// Writes to the Terminal are buffered until either a \n is sent, or more than
/// 256 bytes are written. To immediately draw a write, use [fn draw].
///
/// Reads are similarly buffered until a \n is received by vi.
#[derive(Debug)]
pub struct Terminal {
    /// Internal write buffer.
    buffer: ArrayVec<[u8; 256]>,
    /// The vi pipe backing this terminal.
    pipe: crate::twili::IPipeProxy
}

impl Terminal {
    /// Creates a new Window of the requested size for terminal usage.
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_possible_wrap)]
    pub fn new(size: WindowSize) -> Result<Terminal, Error> {
        let vi_interface = ViInterfaceProxy::raw_new()?;
        let (fullscreen_width, fullscreen_height) = vi_interface.get_screen_resolution()?;

        let (top, left, width, height) = match size {
            WindowSize::Fullscreen => (0, 0, fullscreen_width, fullscreen_height),
            WindowSize::FontLines(lines, is_bottom) => {
                let my_linespace = vi_interface.get_font_height()? as usize;
                let height = if lines < 0 {
                    let max_lines = (fullscreen_height as usize) / my_linespace;
                    my_linespace * ((max_lines as i32) + lines) as usize
                } else if lines == 1 {
                    // Orycterope's fault. Scrolling expects at least one line
                    // available above it.
                    (my_linespace + 1) as usize
                } else {
                    my_linespace * lines as usize
                };
                let top = if is_bottom {
                    (fullscreen_height as usize) - height
                } else {
                    0
                };
                (top as i32, 0, fullscreen_width, height as u32)
            }
            WindowSize::Manual(top, left, width, height) => (top, left, width, height)
        };

        let vi = ViInterfaceProxy::raw_new()?;
        let bpp = 32;
        let size = height * width * bpp / 8;

        let sharedmem = SharedMemory::new(align_up(size, PAGE_SIZE as _) as _, MemoryPermissions::READABLE | MemoryPermissions::WRITABLE, MemoryPermissions::READABLE)?;
        let pipe = vi.create_terminal(&sharedmem, top, left, width, height)?;

        Ok(Terminal {
            pipe,
            buffer: ArrayVec::new()
        })
    }

    /// Flush the write buffer and draw the text.
    pub fn draw(&mut self) -> Result<(), Error> {
        if !self.buffer.is_empty() {
            self.pipe.write(&self.buffer[..])?;
            self.buffer.clear();
        }
        Ok(())
    }

    /// Clone this terminal's pipe.
    pub fn clone_pipe(&self) -> Result<crate::twili::IPipeProxy, Error> {
        self.pipe.clone_current_object()
    }

    /// Read a line of text. Note that it might return without reading an entire
    /// line if the buffer is not big enough. The user should check if a \n is
    /// present in data.
    pub fn read(&mut self, data: &mut [u8]) -> Result<u64, Error> {
        self.pipe.read(data)
    }
}

impl core::fmt::Write for Terminal {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.buffer.extend(s.as_bytes().iter().cloned());
        if s.contains('\n') {
            if let Err(err) = self.draw() {
                log::error!("{:?}", err);
                return Err(core::fmt::Error);
            }
        }
        Ok(())
    }
}