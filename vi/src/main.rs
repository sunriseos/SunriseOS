//! Visual Compositor
//!
//! This process takes care of compositing multiple windows on the framebuffer.
//! In the future, it will also be capable of talking to the GPU to provide an
//! OpenGL abstraction layer.

#![feature(const_vec_new)]
#![no_std]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate sunrise_libuser as libuser;

extern crate alloc;


#[macro_use]
extern crate lazy_static;

mod vbe;

use crate::vbe::{VBEColor, FRAMEBUFFER, Framebuffer};
use core::cmp::{min, max};
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use crate::libuser::syscalls;
use crate::libuser::ipc::server::{WaitableManager, PortHandler, IWaitable, SessionWrapper};
use crate::libuser::types::*;
use spin::Mutex;
use crate::libuser::error::Error;
use crate::libuser::syscalls::MemoryPermissions;
use sunrise_libutils::align_up;
use libuser::mem::{find_free_address, PAGE_SIZE};
use crate::libuser::ipc::server::Object;

/// Entry point interface.
#[derive(Default, Debug)]
struct ViInterface;

object! {
    impl ViInterface {
        /// Create a window.
        ///
        /// This creates a window at the given coordinates, with the given
        /// height. The passed handle should be a SharedMemory handle containing
        /// a framebuffer of type `[[u8; width]; height]`.
        ///
        /// It is allowed to place the framebuffer outside the field of view.
        #[cmdid(0)]
        fn create_buffer(&mut self, manager: &WaitableManager, handle: Handle<copy>, top: i32, left: i32, width: u32, height: u32,) -> Result<(Handle,), Error> {
            let sharedmem = SharedMemory(handle);
            let size = align_up(width * height * 4, PAGE_SIZE as _);
            let addr = find_free_address(size as _, PAGE_SIZE)?;
            let mapped = sharedmem.map(addr, size as _, MemoryPermissions::READABLE)?;
            let buf = IBuffer {
                buffer: Arc::new(Buffer {
                    mem: mapped,
                    top,
                    left,
                    width,
                    height
                })
            };
            BUFFERS.lock().push(Arc::downgrade(&buf.buffer));
            let (server, client) = syscalls::create_session(false, 0)?;
            let wrapper = SessionWrapper::new(server, buf, IBuffer::dispatch);
            manager.add_waitable(Box::new(wrapper) as Box<dyn IWaitable>);
            Ok((client.into_handle(),))
        }

        /// Gets the screen (width, height) in pixels.
        ///
        /// Cannot fail.
        #[cmdid(1)]
        fn get_screen_resolution(&mut self,) -> Result<(u32, u32,), Error> {
            let fb = FRAMEBUFFER.lock();
            Ok((fb.width() as _, fb.height() as _))
        }
    }
}

/// A list of the buffers currently alive.
///
/// Used to draw the framebuffer.
static BUFFERS: Mutex<Vec<Weak<Buffer>>> = Mutex::new(Vec::new());

/// The backbuffer to draw into.
///
/// This is an array residing in the .bss, big enough to hold a UHD 4K screen.
///
/// Most of the time, the actual screen will be much smaller, and only
/// `BACKBUFFER_ARR[0..(screen_height * screen_width)]` should be accessed.
///
/// Its actual size is irrelevant.
static BACKBUFFER_ARR: Mutex<[VBEColor; 3840 * 2160]> = Mutex::new([VBEColor::rgb(0, 0, 0); 3840 * 2160]);

/// Gets the intersection between two rectangles.
fn get_intersect((atop, aleft, awidth, aheight): (u32, u32, u32, u32), (btop, bleft, bwidth, bheight): (u32, u32, u32, u32)) -> Option<(u32, u32, u32, u32)> {
    if atop > (btop + bheight) || btop > atop + aheight {
        return None
    };

    if aleft > (bleft + bwidth) || bleft > aleft + awidth {
        return None
    };

    let top = max(atop, btop);
    let left = max(aleft, bleft);
    let height = min(atop + aheight, btop + bheight) - top;
    let width = min(aleft + awidth, bleft + bwidth) - left;

    Some((top, left, width, height))
}

/// Draw a portion of a buffer onto the framebuffer.
///
/// # Panics
///
/// Panics if buf.width * buf.height * bpp (4) >= 2^sizeof(usize).
#[allow(clippy::cast_sign_loss)] // Code panics when shit hits the fan
#[allow(clippy::cast_possible_wrap)]
fn draw(buf: &Buffer, framebuffer: &mut Framebuffer<'_>, top: u32, left: u32, width: u32, height: u32) {
    unsafe {
        // TODO: Safety of the vi::draw IPC method
        // BODY: When calling vi::draw, vi reads from the shared memory. There is
        // BODY: no borrow-checking mechanism in place to ensure that the other
        // BODY: process does not mutate it while this happens. Maybe we should
        // BODY: have some kind of cross-process mutex? How to implement this
        // BODY: properly?
        let data = buf.mem.get();
        let (dtop, dleft, dwidth, dheight) = buf.get_real_bounds(framebuffer.width() as u32, framebuffer.height() as u32);
        // Calculate first offset in data
        if let Some(intersect) = get_intersect((dtop, dleft, dwidth, dheight), (top, left, width, height)) {
            let (top, left, width, height) = intersect;
            let mut curtop = top;
            while curtop < top + height {
                let mut curleft = left;
                while curleft < left + width {
                    // This overflows when buf.width * buf.height * 4 >= sizeof(usize)
                    let dataidx = (((curtop as i32 - buf.top) as u32 * buf.width + (curleft as i32 - buf.left) as u32) * 4) as usize;
                    let fbidx = framebuffer.get_px_offset(curleft as usize, curtop as usize) as usize;
                    // TODO: Vi: Implement alpha blending
                    // BODY: Vi currently does not do alpha blending at all.
                    // BODY: In the interest of pretty transparent window, this
                    // BODY: needs fixing!
                    framebuffer.get_fb()[fbidx] = VBEColor::rgb(data[dataidx + 2], data[dataidx + 1], data[dataidx + 0]);
                    curleft += 1;
                }
                curtop += 1;
            }
        }
        // for each line
        // memcpy
    }
}

/// See [Buffer::get_real_bounds].
///
/// Panics if width or height are >= i32::max_value()
#[allow(clippy::cast_sign_loss)] // max(x, 0) is always u32
#[allow(clippy::cast_possible_wrap)] // Protected by the assert
fn get_real_bounds((top, left, width, height): (i32, i32, u32, u32), framebuffer_width: u32, framebuffer_height: u32) -> (u32, u32, u32, u32) {
    let dtop = min(max(top, 0) as u32, framebuffer_height);
    let dleft = min(max(left, 0) as u32, framebuffer_width);
    assert!(width < i32::max_value() as u32);
    assert!(height < i32::max_value() as u32);
    let dwidth = min(max(left + width as i32, 0) as u32, framebuffer_width) - dleft;
    let dheight = min(max(top + height as i32, 0) as u32, framebuffer_height) - dtop;
    (dtop, dleft, dwidth, dheight)
}

/// Internal representation of a window.
#[derive(Debug)]
#[allow(clippy::missing_docs_in_private_items)]
struct Buffer {
    top: i32,
    left: i32,
    width: u32,
    height: u32,
    mem: MappedSharedMemory
}

impl Buffer {
    /// Returns the buffer's bounds within the given width/height, cropping as
    /// necessary.
    ///
    /// # Panics
    ///
    /// Panics on overflow if top + height overflows.
    fn get_real_bounds(&self, framebuffer_width: u32, framebuffer_height: u32) -> (u32, u32, u32, u32) {
        get_real_bounds((self.top, self.left, self.width, self.height), framebuffer_width, framebuffer_height)
    }
}

/// IPC Window object
#[derive(Debug)]
struct IBuffer {
    /// The Buffer linked with this window object instance.
    buffer: Arc<Buffer>,
}

impl Drop for IBuffer {
    /// Redraw the zone where the buffer was when dropping it, to make sure it
    /// disappears.
    fn drop(&mut self) {
        let (fullscreen_width, fullscreen_height, bpp) = {
            let fb = FRAMEBUFFER.lock();
            (fb.width(), fb.height(), fb.bpp())
        };
        // create a fake Framebuffer that writes to BACKBUFFER_ARR,
        // and copy it to actual screen only when we're done composing all layers in it.
        let mut backbuffer_arr = BACKBUFFER_ARR.lock();
        let mut framebuffer = Framebuffer::new_buffer(&mut *backbuffer_arr, fullscreen_width, fullscreen_height, bpp);
        let (dtop, dleft, dwidth, dheight) = self.buffer.get_real_bounds(framebuffer.width() as u32, framebuffer.height() as u32);
        framebuffer.clear_at(dleft as _, dtop as _, dwidth as _, dheight as _);
        BUFFERS.lock().retain(|buffer| {
            if let Some(buffer) = buffer.upgrade() {
                if Arc::ptr_eq(&self.buffer, &buffer) {
                    false
                } else {
                    draw(&*buffer, &mut framebuffer, dtop, dleft, dwidth, dheight);
                    true
                }
            } else {
                false
            }
        });
        // BACKBUFFER_ARR is often bigger than our screen, take only the first pixels.
        let screen_in_backbuffer = &mut framebuffer.get_fb()[0..(fullscreen_width * fullscreen_height)];
        FRAMEBUFFER.lock().get_fb().copy_from_slice(screen_in_backbuffer);
    }
}

object! {
    impl IBuffer {
        /// Blit the buffer to the framebuffer.
        #[cmdid(0)]
        #[inline(never)]
        fn draw(&mut self, ) -> Result<(), Error> {
            let (fullscreen_width, fullscreen_height, bpp) = {
                let fb = FRAMEBUFFER.lock();
                (fb.width(), fb.height(), fb.bpp())
            };
            // create a fake Framebuffer that writes to BACKBUFFER_ARR,
            // and copy it to actual screen only when we're done composing all layers in it.
            let mut backbuffer_arr = BACKBUFFER_ARR.lock();
            let mut framebuffer = Framebuffer::new_buffer(&mut *backbuffer_arr, fullscreen_width, fullscreen_height, bpp);
            let (dtop, dleft, dwidth, dheight) = self.buffer.get_real_bounds(framebuffer.width() as u32, framebuffer.height() as u32);
            framebuffer.clear_at(dleft as _, dtop as _, dwidth as _, dheight as _);
            BUFFERS.lock().retain(|buffer| {
                if let Some(buffer) = buffer.upgrade() {
                    draw(&*buffer, &mut framebuffer, dtop, dleft, dwidth, dheight);
                    true
                } else {
                    false
                }
            });
            // BACKBUFFER_ARR is often bigger than our screen, take only the first pixels.
            let screen_in_backbuffer = &mut framebuffer.get_fb()[0..(fullscreen_width * fullscreen_height)];
            FRAMEBUFFER.lock().get_fb().copy_from_slice(screen_in_backbuffer);
            Ok(())
        }
    }
}

fn main() {
    let man = WaitableManager::new();
    let handler = Box::new(PortHandler::new("vi:\0", ViInterface::dispatch).unwrap());
    man.add_waitable(handler as Box<dyn IWaitable>);

    man.run();
}
capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,

        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,
        sunrise_libuser::syscalls::nr::CreateSession,

        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,

        sunrise_libuser::syscalls::nr::SetHeapSize,

        sunrise_libuser::syscalls::nr::QueryMemory,

        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,

        sunrise_libuser::syscalls::nr::MapFramebuffer,
    ],
});

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensure we don't crop when the data fits the framebuffer
    #[test]
    fn check_get_real_bounds_normal() {
        assert_eq!(get_real_bounds((0, 0, 1280, 800), 1280, 800), (0, 0, 1280, 800));
        assert_eq!(get_real_bounds((500, 700, 20, 150), 1280, 800), (500, 700, 20, 150));
    }

    /// Ensure we properly crop the width when it is too high.
    #[test]
    fn check_get_real_bounds_width() {
        assert_eq!(get_real_bounds((0, 0, 1500, 800), 1280, 800), (0, 0, 1280, 800));
    }

    /// Ensure we properly crop the height when it is too high.
    #[test]
    fn check_get_real_bounds_height() {
        assert_eq!(get_real_bounds((0, 0, 1280, 1000), 1280, 800), (0, 0, 1280, 800));
    }

    /// Ensure we properly crop the top bound when it is negative, reducing the
    /// height appropriately.
    #[test]
    fn check_get_real_bounds_top() {
        assert_eq!(get_real_bounds((-15, 0, 1280, 50), 1280, 800), (0, 0, 1280, 35));
        assert_eq!(get_real_bounds((-15, 0, 1280, 800), 1280, 800), (0, 0, 1280, 785));
    }

    /// Ensure we properly crop the left bound when it is negative, reducing the
    /// width appropriately.
    #[test]
    fn check_get_real_bounds_left() {
        assert_eq!(get_real_bounds((0, -15, 50, 800), 1280, 800), (0, 0, 35, 800));
        assert_eq!(get_real_bounds((0, -15, 1280, 800), 1280, 800), (0, 0, 1265, 800));
    }

    /// Check that cropping on negative left bound does not result in an out of
    /// bounds width.
    #[test]
    fn check_get_real_bounds_leftwidth() {
        assert_eq!(get_real_bounds((0, -15, 1580, 800), 1280, 800), (0, 0, 1280, 800));
    }

    /// Check that cropping on negative top bound does not result in an out of
    /// bounds height.
    #[test]
    fn check_get_real_bounds_topheight() {
        assert_eq!(get_real_bounds((-15, 0, 1280, 1000), 1280, 800), (0, 0, 1280, 800));
    }

    /// Checks that cropping works if we are faaaaaaaar to the left.
    #[test]
    fn check_get_real_bounds_pedantic() {
        assert_eq!(get_real_bounds((-5000, 0, 1280, 1000), 1280, 800), (0, 0, 1280, 0));
    }
}
