//! KFS
//!
//! A small kernel written in rust for shit and giggles. Also, hopefully the
//! last project I'll do before graduating from 42 >_>'.
//!
//! Currently doesn't do much, besides booting and printing Hello World on the
//! screen. But hey, that's a start.

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, naked_functions, core_intrinsics, const_fn, abi_x86_interrupt, iterator_step_by, used, allocator_api, alloc, panic_implementation, box_syntax, no_more_cas, option_replace, const_vec_new)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![allow(unused)]
#[cfg(not(target_os = "none"))]
use std as core;

extern crate arrayvec;
extern crate ascii;
extern crate bit_field;
#[macro_use]
extern crate lazy_static;
extern crate spin;
extern crate multiboot2;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate static_assertions;
#[macro_use]
extern crate alloc;
extern crate linked_list_allocator;
extern crate gif;
#[macro_use]
extern crate log;
extern crate smallvec;
extern crate font_rs;
extern crate hashmap_core;

use ascii::AsAsciiStr;
use core::fmt::Write;
use alloc::prelude::*;

use event::{Waitable, MultiWaiter};

mod event;
mod logger;
mod log_impl;
use i386::mem::paging;
use i386::mem::frame_alloc;
pub use logger::*;
pub use devices::vgatext::VGATextLogger;
pub use devices::rs232::SerialLogger;
pub use devices::vbe::VBELogger;
use i386::mem::PhysicalAddress;
use i386::mem::frame_alloc::Frame;
use paging::KernelLand;

mod i386;
#[cfg(target_os = "none")]
mod gdt;
mod interrupts;

mod utils;
mod heap_allocator;
mod io;
mod devices;
mod sync;
mod process;
mod scheduler;

// Make rust happy about rust_oom being no_mangle...
pub use heap_allocator::rust_oom;

#[global_allocator]
static ALLOCATOR: heap_allocator::Allocator = heap_allocator::Allocator::new();

pub use frame_alloc::FrameAllocator;
pub use i386::stack;
use paging::{InactivePageTables, PageTablesSet, EntryFlags};

unsafe fn force_double_fault() {
    loop {
        asm!("push 0" :::: "intel", "volatile");
    }
}

fn main() {
    let loggers = &mut Loggers;
    loggers.println("Hello world!      ");
    loggers.println_attr("Whoah, nice color",
                      LogAttributes::new_fg_bg(LogColor::Pink, LogColor::Cyan));
    loggers.println_attr("such hues",
                          LogAttributes::new_fg_bg(LogColor::Magenta, LogColor::LightGreen));
    loggers.println_attr("very polychromatic",
                           LogAttributes::new_fg_bg(LogColor::Yellow, LogColor::LightMagenta));

    {
        let mymem = FrameAllocator::alloc_frame();
        info!("Allocated frame {:x?}", mymem);
    }

    info!("Freed frame");

    writeln!(Loggers, "----------");

    let page1 = ::paging::get_page::<::paging::UserLand>();
    info!("Got page {:#x}", page1.addr());
    let page2 = ::paging::get_page::<::paging::UserLand>();
    info!("Got page {:#x}", page2.addr());

    info!("----------");

    let mut inactive_pages = InactivePageTables::new();
    info!("Created new tables");
    let page_innactive = inactive_pages.get_page::<paging::UserLand>();
    info!("Mapped inactive page {:#x}", page_innactive.addr());
    unsafe { inactive_pages.switch_to() };
    info!("Switched to new tables");
    let page_active = ::paging::get_page::<::paging::UserLand>();
    info!("Got page {:#x}", page_active.addr());

    info!("Testing some string heap alloc: {}", String::from("Hello World"));

    info!("Testing syscalls");
    let syscall_result =
    unsafe { interrupts::syscall(42, 1, 2, 3, 4, 5, 6) };
    info!("Syscall result: {}", syscall_result);
	
	info!("Creating a new process");
    let p1 = process::ProcessStruct::new();
    info!("Created process {:#?}", p1);

    info!("Adding it to the schedule queue");
    ::scheduler::add_to_schedule_queue(p1);

    info!("Scheduling to it");
    ::scheduler::schedule();

    // wow we came back from the dead :o
    info!("Process 0 scheduled again !");

    info!("Starting the shell");
    shell();
}

fn shell() -> ! {
    loop {
        match &*devices::ps2::get_next_line() {
            "gif3" => show_gif(&LOUIS3[..]),
            "gif4" => show_gif(&LOUIS4[..]),
            "stackdump" => unsafe { stack::KernelStack::dump_current_stack() },
            "help" => {
                info!("COMMANDS:");
                info!("gif3: Print the KFS-3 meme");
                info!("gif4: Print the KFS-4 meme");
                info!("stackdump: Print a dump of the current stack");
            }
            _ => info!("Unknown command")
        }
    }
}

fn show_gif(louis: &[u8]) {
    let mut vbe = unsafe {
        devices::vbe::Framebuffer::new(i386::multiboot::get_boot_information())
    };
    let mut reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
    let mut buf = Vec::new();
    let timer_event = devices::pit::wait_ms(100);
    let keyboard_event = devices::ps2::get_waitable();

    let events = [&timer_event, keyboard_event as &dyn Waitable];

    let waiter = MultiWaiter::new(&events);
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
                let vbe_coord = (y * vbe.width() + x) * 4;
                vbe.get_fb()[vbe_coord] = buf[frame_coord + 2];
                vbe.get_fb()[vbe_coord + 1] = buf[frame_coord + 1];
                vbe.get_fb()[vbe_coord + 2] = buf[frame_coord];
                vbe.get_fb()[vbe_coord + 3] = 0xFF;
            }
        }
        let waitable = waiter.wait();
        if waitable as *const _ == events[1] as *const _ && devices::ps2::try_read_key().is_some() {
            return;
        }
    }
}

static LOUIS3: &'static [u8; 1318100] = include_bytes!("../img/meme3.gif");
static LOUIS4: &'static [u8; 103803] = include_bytes!("../img/meme4.gif");

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

        // Save multiboot infos addr present in ebx
        push ebx
        call common_start" : : : : "intel", "volatile");
    core::intrinsics::unreachable()
}

/// CRT0 starts here.
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn common_start(multiboot_info_addr: usize) -> ! {
    log_impl::early_init();

    // Register some loggers
    static mut SERIAL: SerialLogger = SerialLogger;
    Loggers::register_logger("Serial", unsafe { &mut SERIAL });


    let loggers = &mut Loggers;
    // Say hello to the world
    write!(Loggers, "\n# Welcome to ");
    loggers.print_attr("KFS",
                             LogAttributes::new_fg(LogColor::LightCyan));
    writeln!(Loggers, "!\n");

    // Parse the multiboot infos
    let boot_info = unsafe { multiboot2::load(multiboot_info_addr) };
    info!("Parsed multiboot informations");

    // Setup frame allocator
    FrameAllocator::init(&boot_info);
    info!("Initialized frame allocator");

    // Create a set of pages where the bootstrap is not mapped
    let mut kernel_pages = paging::InactivePageTables::new();
    info!("Created kernel pages");

    // Start using these page tables
    let bootstrap_pages = unsafe { kernel_pages.switch_to() };
    info!("Switched to kernel pages");
    bootstrap_pages.delete();

    // Set up (read: inhibit) the GDT.
    info!("Initializing gdt...");
    gdt::init_gdt();
    info!("Gdt initialized");

    // Initialize the VGATEXT logger now that paging is in a stable state
    static mut VGATEXT: VGATextLogger = VGATextLogger;
    Loggers::register_logger("VGA text mode", unsafe { &mut VGATEXT });
    info!("Initialized VGATEXT logger");

    i386::multiboot::init(boot_info);

    log_impl::init();

    let new_stack = stack::KernelStack::allocate_boot_stack()
        .expect("Failed to allocate new kernel stack");
    unsafe { new_stack.switch_to(common_start_continue_stack) }
    unreachable!()
}

/// When we switch to a new valid kernel stack during init, we can't return now that the stack is empty
/// so we need to call some function that will proceed with the end of the init procedure
/// This is some function
#[cfg(target_os = "none")]
#[no_mangle]
pub fn common_start_continue_stack() -> ! {
    info!("Switched to new kernel stack");

    unsafe { devices::pit::init_channel_0() };
    info!("Initialized PIT");

    info!("Enabling interrupts");
    unsafe { interrupts::init(); }

    //info!("Disable timer interrupt");
    //devices::pic::get().mask(0);

    info!("Registering VBE logger");
    static mut VBE_LOGGER: VBELogger = VBELogger;
    Loggers::register_logger("VBE", unsafe { &mut VBE_LOGGER });

    info!("Becoming the first process");
    unsafe { scheduler::create_first_process() };

    info!("Calling main()");

    writeln!(SerialLogger, "= Calling main()");
    main();
    // Die !
    // We shouldn't reach this...
    loop {
        #[cfg(target_os = "none")]
        unsafe { asm!("HLT"); }
    }
}

#[cfg(target_os = "none")]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

#[cfg(target_os = "none")]
#[panic_implementation] #[no_mangle]
pub extern fn panic_fmt(p: &::core::panic::PanicInfo) -> ! {

    unsafe { Loggers.force_unlock(); }
    let _ = writeln!(Loggers, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
                               ! Panic! at the disco\n\
                               ! {}\n\
                               !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
                     p);

    loop { unsafe { asm!("HLT"); } }
}
