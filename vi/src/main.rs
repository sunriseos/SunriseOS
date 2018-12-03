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
            Ok((client.0,))
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
        // TODO: Safety. We need to guarantee that, while this slice exists, the
        // other owner of the sharedmem does not mutate it. How?
        let data = buf.mem.get();
        let (dtop, dleft, dwidth, dheight) = buf.get_real_bounds();
        // Calculate first offset in data
        if let Some(intersect) = get_intersect((dtop, dleft, dwidth, dheight), (top, left, width, height)) {
            let (top, left, width, height) = intersect;
            syscalls::output_debug_string(&format!("Intersection is {} {} {} {}", top, left, width, height));
            let mut curtop = top;
            while curtop < top + height {
                let mut curleft = left;
                while curleft < left + width {
                    let dataidx = ((curtop as i32 - buf.top) as u32 * width + (curleft as i32 - buf.left) as u32) * 4;
                    let r = data[dataidx as usize + 0];
                    let g = data[dataidx as usize + 1];
                    let b = data[dataidx as usize + 2];
                    let a = data[dataidx as usize + 3];
                    if (r != 0 || g != 0 || b != 0 || a != 0) {
                        let _ = syscalls::output_debug_string(&format!("Non-black pixel {:02X}{:02X}{:02X} at {} {}", r, g, b, curleft, curtop));
                    }
                    //let pixel = FRAMEBUFFER.read_px_at(curleft, curtop);
                    // TODO: Alpha blend!
                    FRAMEBUFFER.lock().write_px_at(curleft as usize, curtop as usize, &VBEColor::rgb(r, g, b));
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
    fn get_real_bounds(&self) -> (u32, u32, u32, u32) {
        let dtop = max(self.top, 0) as u32;
        let dleft = max(self.left, 0) as u32;
        let dwidth = min(self.width as i32, self.left + (self.width as i32)) as u32;
        let dheight = min(self.height as i32, self.top + (self.height as i32)) as u32;
        (dtop, dleft, dwidth, dheight)
    }
}

struct IBuffer {
    buffer: Arc<Buffer>,
}

object! {
    impl IBuffer {
        #[cmdid(0)]
        #[inline(never)]
        fn draw(&mut self, ) -> Result<(), Error> {
            let (dtop, dleft, dwidth, dheight) = self.buffer.get_real_bounds();
            FRAMEBUFFER.lock().clear_at(dleft as _, dtop as _, dwidth as _, dheight as _);
            for buffer in BUFFERS.lock().iter() {
                if let Some(buffer) = buffer.upgrade() {
                    let _ = syscalls::output_debug_string(&format!("Drawing {:?}, {} {} {} {}", buffer, dtop, dleft, dwidth, dheight));
                    draw(&*buffer, dtop, dleft, dwidth, dheight)
                }
            }
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
