#![feature(asm, const_fn, alloc, panic_implementation, core_intrinsics, lang_items, used)]
#![no_std]

extern crate gif;
extern crate font_rs;
extern crate spin;
extern crate hashmap_core;
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate libuser;

mod vbe;
mod ps2;
mod logger;
use libuser::syscalls;
use libuser::io;

use vbe::{Framebuffer, FRAMEBUFFER, VBELogger};
use core::fmt::Write;
use alloc::vec::Vec;
use logger::Loggers;

static mut VBE_LOGGER: VBELogger = VBELogger;

pub fn main() {
    //let mut framebuffer = Framebuffer::new().unwrap();

    //log_impl::early_init();

    // TODO: Avoid allocating two framebuffers.
    Loggers::register_logger("VBE", unsafe { &mut VBE_LOGGER });
    writeln!(&mut VBELogger, "Registered VBE logger");


    loop {
        match &*ps2::get_next_line() {
            "gif3" => show_gif(&mut *FRAMEBUFFER.lock(), &LOUIS3[..]),
            "gif4" => show_gif(&mut *FRAMEBUFFER.lock(), &LOUIS4[..]),
            "connect" => {
                let handle = syscalls::connect_to_named_port("sm:\0").unwrap();
                writeln!(&mut VBELogger, "Got handle {:?}", handle);
            },
            "exit" => return,
            //"stackdump" => unsafe { stack::KernelStack::dump_current_stack() },
            "help" => {
                writeln!(&mut VBELogger, "COMMANDS:");
                writeln!(&mut VBELogger, "exit: Exit this process");
                writeln!(&mut VBELogger, "gif3: Print the KFS-3 meme");
                writeln!(&mut VBELogger, "gif4: Print the KFS-4 meme");
            }
            _ => { writeln!(&mut VBELogger, "Unknown command"); }
        }
    }
}

fn show_gif(fb: &mut Framebuffer, louis: &[u8]) {
    let mut reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
    let mut buf = Vec::new();
    let keyboard_event = ps2::get_waitable();

    let events = [keyboard_event.0.as_ref()];

    loop {
        {
            let end = reader.next_frame_info().unwrap().is_none();
            if end {
                reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
                let _ = reader.next_frame_info().unwrap().unwrap();
            }
        }
        buf.resize(reader.buffer_size(), 0);
        // simulate read into buffer
        reader.read_into_buffer(&mut buf[..]);
        for y in 0..(reader.height() as usize) {
            for x in 0..(reader.width() as usize) {
                let frame_coord = (y * reader.width() as usize + x) * 4;
                let vbe_coord = (y * fb.width() + x) * 4;
                fb.get_fb()[vbe_coord] = buf[frame_coord + 2];
                fb.get_fb()[vbe_coord + 1] = buf[frame_coord + 1];
                fb.get_fb()[vbe_coord + 2] = buf[frame_coord];
                fb.get_fb()[vbe_coord + 3] = 0xFF;
            }
        }
        match syscalls::wait_synchronization(&events, Some(100 * 1_000_000)) {
            Ok(idx) if ps2::try_read_key().is_some() => return,
            Ok(idx) => (),
            Err(err) => {
                // timeout
            }
        }
    }
}

static LOUIS3: &'static [u8; 1318100] = include_bytes!("../img/meme3.gif");
static LOUIS4: &'static [u8; 103803] = include_bytes!("../img/meme4.gif");

#[link_section = ".kernel_ioports"]
#[used]
pub static IOPORTS_PERMS: [u16; 2] = [0x60, 0x64];
