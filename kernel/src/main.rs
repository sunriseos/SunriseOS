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
extern crate xmas_elf;

use ascii::AsAsciiStr;
use core::fmt::Write;
use alloc::prelude::*;

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
use process::{ProcessStruct, ProcessMemory};

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
mod mem;
mod elf_loader;

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
    info!("Loading all the init processes");
    for module in i386::multiboot::get_boot_information().module_tags().skip(1) {
        info!("Loading {}", module.name());
        let proc = ProcessStruct::new();
        {
            let mut plock = proc.write();
            let ep = {
                let pmem = if let ProcessMemory::Inactive(ref pmem) = plock.pmemory {
                    pmem
                } else {
                    panic!("newly created process has active pages?")
                };

                let mut pmem_lock = pmem.lock();

                elf_loader::load_builtin(&mut *pmem_lock, module)
            };
            unsafe { plock.set_entrypoint(ep); }
        }

        scheduler::add_to_schedule_queue(proc);
    }

    loop {
        // TODO: Exit process.
        scheduler::unschedule();
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
    //static mut VGATEXT: VGATextLogger = VGATextLogger;
    //Loggers::register_logger("VGA text mode", unsafe { &mut VGATEXT });
    //info!("Initialized VGATEXT logger");

    i386::multiboot::init(boot_info);

    log_impl::init();

    unsafe { devices::pit::init_channel_0() };
    info!("Initialized PIT");

    info!("Enabling interrupts");
    unsafe { interrupts::init(); }

    //info!("Disable timer interrupt");
    //devices::pic::get().mask(0);

    //info!("Registering VBE logger");
    //static mut VBE_LOGGER: VBELogger = VBELogger;
    //Loggers::register_logger("VBE", unsafe { &mut VBE_LOGGER });

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
