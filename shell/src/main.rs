#![feature(alloc, asm)]
#![no_std]

#![warn(missing_docs)]

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
extern crate kfs_libuser as libuser;
extern crate byteorder;

mod vbe;
mod ps2;
mod logger;
use libuser::syscalls;
use libuser::io;
use libuser::sm;

use vbe::{Framebuffer, FRAMEBUFFER, VBELogger};
use core::fmt::Write;
use alloc::vec::Vec;
use logger::Loggers;
use byteorder::{ByteOrder, LE};
use alloc::prelude::*;
use syscalls::{create_thread, sleep_thread, exit_thread};

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
            "test_threads" => test_threads(),
            "test_divide_by_zero" => test_divide_by_zero(),
            "test_page_fault" => test_page_fault(),
            "connect" => {
                let handle = sm::IUserInterface::raw_new().unwrap().get_service(LE::read_u64(b"vi:\0\0\0\0\0"));
                writeln!(&mut VBELogger, "Got handle {:?}", handle);
            },
            "exit" => return,
            //"stackdump" => unsafe { stack::KernelStack::dump_current_stack() },
            "help" => {
                writeln!(&mut VBELogger, "COMMANDS:");
                writeln!(&mut VBELogger, "exit: Exit this process");
                writeln!(&mut VBELogger, "gif3: Print the KFS-3 meme");
                writeln!(&mut VBELogger, "gif4: Print the KFS-4 meme");
                writeln!(&mut VBELogger, "test_threads: Run threads that concurrently print As and Bs");
                writeln!(&mut VBELogger, "test_divide_by_zero: Check exception handling by throwing a divide by zero");
                writeln!(&mut VBELogger, "test_page_fault: Check exception handling by throwing a page_fault");
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

fn test_threads() {

    fn thread_a() {
        for _ in 0..10 {
            writeln!(&mut VBELogger, "A");
            sleep_thread(0);
        }
    }

    fn thread_b() -> ! {
        for _ in 0..10 {
            writeln!(&mut VBELogger, "B");
            sleep_thread(0);
        }
        exit_thread()
    }

    const THREAD_STACK_SIZE: usize = 0x2000;

    let stack = Box::new([0u8; THREAD_STACK_SIZE]);
    let sp = (Box::into_raw(stack) as *const u8).wrapping_offset(THREAD_STACK_SIZE as isize);
    let ip = thread_b;
    let thread_handle = create_thread(ip, 0, sp, 0, 0)
        .expect("svcCreateThread returned an error");
    thread_handle.start()
        .expect("svcStartThread returned an error");

    // thread is running b, run a meanwhile
    thread_a();
}

fn test_divide_by_zero() {
    // don't panic, we want to actually divide by zero
    unsafe {
        asm!("
        mov eax, 42
        mov ecx, 0
        div ecx" :::: "volatile", "intel")
    }
}

fn test_page_fault() {
    let ptr = 0x00000000 as *const u8;
    let res = unsafe { *ptr };
}

static LOUIS3: &'static [u8; 1318100] = include_bytes!("../img/meme3.gif");
static LOUIS4: &'static [u8; 103803] = include_bytes!("../img/meme4.gif");

#[link_section = ".kernel_ioports"]
#[used]
pub static IOPORTS_PERMS: [u16; 2] = [0x60, 0x64];
