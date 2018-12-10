#![feature(alloc, const_vec_new)]
#![no_std]

#![warn(missing_docs)]

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

use vbe::{VBEColor, FRAMEBUFFER};
use core::cmp::{min, max};
use alloc::prelude::*;
use alloc::sync::{Arc, Weak};
use libuser::syscalls;
use libuser::ipc::server::{WaitableManager, PortHandler, IWaitable, SessionWrapper};
use libuser::types::*;
use hashmap_core::map::{HashMap, Entry};
use spin::Mutex;
use libuser::error::{KernelError, Error};
use libuser::syscalls::MemoryPermissions;
use kfs_libutils::align_up;

#[derive(Default)]
struct ViInterface;

object! {
    impl ViInterface {
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

        #[cmdid(1)]
        fn get_resolution(&mut self,) -> Result<(u32, u32,), Error> {
            Ok((1280, 800))
        }
    }
}

static BUFFERS: Mutex<Vec<Weak<Buffer>>> = Mutex::new(Vec::new());

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

fn draw(buf: &Buffer, top: u32, left: u32, width: u32, height: u32) {
    unsafe {
        // TODO: Safety of the vi::draw IPC method
        // BODY: When calling vi::draw, vi reads from the shared memory. There is
        // BODY: no borrow-checking mechanism in place to ensure that the other
        // BODY: process does not mutate it while this happens. Maybe we should
        // BODY: have some kind of cross-process mutex? How to implement this
        // BODY: properly?
        let data = buf.mem.get();
        let (dtop, dleft, dwidth, dheight) = buf.get_real_bounds(width, height);
        // Calculate first offset in data
        let mut framebuffer = FRAMEBUFFER.lock();
        if let Some(intersect) = get_intersect((dtop, dleft, dwidth, dheight), (top, left, width, height)) {
            let (top, left, width, height) = intersect;
            let mut curtop = top;
            while curtop < top + height {
                let mut curleft = left;
                while curleft < left + width {
                    let dataidx = ((curtop as i32 - buf.top) as u32 * width + (curleft as i32 - buf.left) as u32) * 4;
                    let fbidx = framebuffer.get_px_offset(curleft as usize, curtop as usize);
                    // TODO: Vi: Implement alpha blending
                    // BODY: Vi currently does not do alpha blending at all.
                    // BODY: In the interest of pretty transparent window, this
                    // BODY: needs fixing!
                    framebuffer.get_fb()[fbidx as usize + 0] = data[dataidx as usize + 0];
                    framebuffer.get_fb()[fbidx as usize + 1] = data[dataidx as usize + 1];
                    framebuffer.get_fb()[fbidx as usize + 2] = data[dataidx as usize + 2];
                    curleft += 1;
                }
                curtop += 1;
            }
        }
        // for each line
        // memcpy
    }
}

#[derive(Debug)]
struct Buffer {
    top: i32,
    left: i32,
    width: u32,
    height: u32,
    mem: MappedSharedMemory
}

impl Buffer {
    fn get_real_bounds(&self, framebuffer_width: u32, framebuffer_height: u32) -> (u32, u32, u32, u32) {
        let dtop = min(max(self.top, 0) as u32, framebuffer_height);
        let dleft = min(max(self.left, 0) as u32, framebuffer_width);
        let dwidth = min(framebuffer_height - dtop, self.height);
        let dheight = min(framebuffer_width - dleft, self.width);
        (dtop, dleft, dwidth, dheight)
    }
}

struct IBuffer {
    buffer: Arc<Buffer>,
}

impl Drop for IBuffer {
    fn drop(&mut self) {
        let (dtop, dleft, dwidth, dheight) = self.buffer.get_real_bounds(FRAMEBUFFER.lock().width() as u32, FRAMEBUFFER.lock().height() as u32);
        FRAMEBUFFER.lock().clear_at(dleft as _, dtop as _, dwidth as _, dheight as _);
        BUFFERS.lock().retain(|buffer| {
            if let Some(buffer) = buffer.upgrade() {
                if Arc::ptr_eq(&self.buffer, &buffer) {
                    false
                } else {
                    draw(&*buffer, dtop, dleft, dwidth, dheight);
                    true
                }
            } else {
                false
            }
        });
    }
}

object! {
    impl IBuffer {
        #[cmdid(0)]
        #[inline(never)]
        fn draw(&mut self, ) -> Result<(), Error> {
            // TODO: Vi: Heavy flickering.
            // BODY: When drawing the whole screen, we can see some extreme
            // BODY: amount of flickering on the screen. We should look into
            // BODY: better compositing algorithms, maybe we don't need to redraw
            // BODY: the whole screen all the time? And also, look into VSYNC.
            let (dtop, dleft, dwidth, dheight) = self.buffer.get_real_bounds(FRAMEBUFFER.lock().width() as u32, FRAMEBUFFER.lock().height() as u32);
            FRAMEBUFFER.lock().clear_at(dleft as _, dtop as _, dwidth as _, dheight as _);
            BUFFERS.lock().retain(|buffer| {
                if let Some(buffer) = buffer.upgrade() {
                    draw(&*buffer, dtop, dleft, dwidth, dheight);
                    true
                } else {
                    false
                }
            });
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
