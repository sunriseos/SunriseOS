#![feature(asm, const_fn, alloc, panic_implementation, core_intrinsics, lang_items)]
#![no_std]
#![no_main]

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
extern crate linked_list_allocator;

mod vbe;
mod ps2;
mod io;
mod logger;
mod syscalls;

use vbe::{Framebuffer, FRAMEBUFFER, VBELogger};
use core::fmt::Write;
use alloc::vec::Vec;
use logger::Loggers;

static mut VBE_LOGGER: VBELogger = VBELogger;

#[no_mangle]
pub fn main() {
    init_heap();

    //let mut framebuffer = Framebuffer::new().unwrap();

    //log_impl::early_init();

    // TODO: Avoid allocating two framebuffers.
    Loggers::register_logger("VBE", unsafe { &mut VBE_LOGGER });
    writeln!(&mut VBELogger, "Registered VBE logger");


    loop {
        match &*ps2::get_next_line() {
            "gif3" => show_gif(&mut *FRAMEBUFFER.lock(), &LOUIS3[..]),
            "gif4" => show_gif(&mut *FRAMEBUFFER.lock(), &LOUIS4[..]),
            //"stackdump" => unsafe { stack::KernelStack::dump_current_stack() },
            "help" => {
                writeln!(&mut VBELogger, "COMMANDS:");
                writeln!(&mut VBELogger, "gif3: Print the KFS-3 meme");
                writeln!(&mut VBELogger, "gif4: Print the KFS-4 meme");
                writeln!(&mut VBELogger, "stackdump: Print a dump of the current stack");
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

#[cfg(target_os = "none")]
#[no_mangle]
pub unsafe extern fn start() -> ! {
    asm!("
        // Memset the bss. Hopefully memset doesn't actually use the bss...
        mov eax, BSS_END
        sub eax, BSS_START
        push eax
        push 0
        push BSS_START
        call memset
        add esp, 12

        call main" : : : : "intel", "volatile");
    core::intrinsics::unreachable()
}

static LOUIS3: &'static [u8; 1318100] = include_bytes!("../img/meme3.gif");
static LOUIS4: &'static [u8; 103803] = include_bytes!("../img/meme4.gif");

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// Let's grant ourselves 10MB of heap
static mut ALLOCATOR_BUF: [u8; 10_000_000] = [0; 10_000_000];

pub fn init_heap() {
    unsafe {
        let heap_start = ALLOCATOR_BUF.as_ptr() as usize;
        let heap_size = ALLOCATOR_BUF.len();
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

use core::panic::PanicInfo;


#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

#[cfg(target_os = "none")]
#[panic_implementation] #[no_mangle]
pub extern fn panic_fmt(p: &::core::panic::PanicInfo) -> ! {
    loop { unsafe { asm!("HLT"); } }
}

use core::alloc::Layout;

// required: define how Out Of Memory (OOM) conditions should be handled
// *if* no other crate has already defined `oom`
#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_: Layout) -> ! {
    panic!("OOM")
}
