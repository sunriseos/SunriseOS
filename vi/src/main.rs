//! Visual Compositor
//!
//! This process takes care of compositing multiple windows on the framebuffer.
//! In the future, it will also be capable of talking to the GPU to provide an
//! OpenGL abstraction layer.

#![feature(alloc, const_vec_new, const_let)]
#![no_std]

#![warn(missing_docs)]
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate kfs_libuser as libuser;
extern crate kfs_libutils;
#[macro_use]
extern crate alloc;
extern crate spin;
extern crate hashmap_core;
#[macro_use]
extern crate lazy_static;

mod vbe;

use vbe::{VBEColor, FRAMEBUFFER, Framebuffer};
use core::cmp::{min, max};
use alloc::prelude::*;
use alloc::sync::{Arc, Weak};
use libuser::syscalls;
use libuser::ipc::server::{WaitableManager, PortHandler, IWaitable, SessionWrapper};
use libuser::types::*;
use spin::Mutex;
use libuser::error::Error;
use libuser::syscalls::MemoryPermissions;
use kfs_libutils::align_up;

/// Entry point interface.
#[derive(Default)]
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
            let size = align_up(width * height * 4, 0x1000);
            let addr = libuser::find_free_address(size as _, 0x1000)?;
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
            let wrapper = SessionWrapper::new(server, buf);
            manager.add_waitable(Box::new(wrapper) as Box<dyn IWaitable>);
            Ok((client.into_handle(),))
        }

        /// Gets the screen resolution.
        #[cmdid(1)]
        fn get_resolution(&mut self,) -> Result<(u32, u32,), Error> {
            Ok((1280, 800))
        }
    }
}

/// A list of the buffers currently alive.
///
/// Used to draw the framebuffer.
static BUFFERS: Mutex<Vec<Weak<Buffer>>> = Mutex::new(Vec::new());

/// The backbuffer to draw into.
static BACKBUFFER_ARR: Mutex<[VBEColor; 1280 * 800]> = Mutex::new([VBEColor::rgb(0, 0, 0); 1280 * 800]);

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
fn draw(buf: &Buffer, framebuffer: &mut Framebuffer, top: u32, left: u32, width: u32, height: u32) {
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
                    let dataidx = (((curtop as i32 - buf.top) as u32 * width + (curleft as i32 - buf.left) as u32) * 4) as usize;
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

/// See Buffer::get_real_bounds.
fn get_real_bounds((top, left, width, height): (i32, i32, u32, u32), framebuffer_width: u32, framebuffer_height: u32) -> (u32, u32, u32, u32) {
    let dtop = min(max(top, 0) as u32, framebuffer_height);
    let dleft = min(max(left, 0) as u32, framebuffer_width);
    let dwidth = min(max(left + width as i32, 0) as u32, framebuffer_width) - dleft;
    let dheight = min(max(top + height as i32, 0) as u32, framebuffer_height) - dtop;
    (dtop, dleft, dwidth, dheight)
}

/// Internal representation of a window.
#[derive(Debug)]
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
struct IBuffer {
    buffer: Arc<Buffer>,
}

impl Drop for IBuffer {
    /// Redraw the zone where the buffer was when dropping it, to make sure it
    /// disappears.
    fn drop(&mut self) {
        let mut backbuffer_arr = BACKBUFFER_ARR.lock();
        let mut framebuffer = Framebuffer::new_buffer(&mut *backbuffer_arr, 1280, 800, 32);
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
        FRAMEBUFFER.lock().get_fb().copy_from_slice(framebuffer.get_fb());
    }
}

object! {
    impl IBuffer {
        /// Blit the buffer to the framebuffer.
        #[cmdid(0)]
        #[inline(never)]
        fn draw(&mut self, ) -> Result<(), Error> {
            let mut backbuffer_arr = BACKBUFFER_ARR.lock();
            let mut framebuffer = Framebuffer::new_buffer(&mut *backbuffer_arr, 1280, 800, 32);
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
            FRAMEBUFFER.lock().get_fb().copy_from_slice(framebuffer.get_fb());
            Ok(())
        }
    }
}

fn main() {
    let man = WaitableManager::new();
    let handler = Box::new(PortHandler::<ViInterface>::new("vi:\0").unwrap());
    man.add_waitable(handler as Box<dyn IWaitable>);

    man.run();
}
capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        kfs_libuser::syscalls::nr::SleepThread,
        kfs_libuser::syscalls::nr::ExitProcess,
        kfs_libuser::syscalls::nr::CloseHandle,
        kfs_libuser::syscalls::nr::WaitSynchronization,
        kfs_libuser::syscalls::nr::OutputDebugString,

        kfs_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        kfs_libuser::syscalls::nr::AcceptSession,
        kfs_libuser::syscalls::nr::CreateSession,

        kfs_libuser::syscalls::nr::ConnectToNamedPort,
        kfs_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,

        kfs_libuser::syscalls::nr::SetHeapSize,

        kfs_libuser::syscalls::nr::QueryMemory,

        kfs_libuser::syscalls::nr::MapSharedMemory,
        kfs_libuser::syscalls::nr::UnmapSharedMemory,

        kfs_libuser::syscalls::nr::MapFramebuffer,
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
