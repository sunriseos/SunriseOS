//! Sunrise kernel
//!
//! > Writing an Operating System is easy. Explaining how to write one isn't.
//!
//! - PoC||GTFO, 4:3.
//!
//! A small kernel written in rust for shit and giggles. Also, hopefully the
//! last project I'll do before graduating from 42 >_>'.
//!
//! Currently doesn't do much, besides booting and printing Hello World on the
//! screen. But hey, that's a start.

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, naked_functions, core_intrinsics, const_fn, abi_x86_interrupt, allocator_api, box_syntax, no_more_cas, const_vec_new, step_trait, thread_local, nll, doc_cfg, exclusive_range_pattern, optin_builtin_traits)]
#![no_std]
#![cfg_attr(target_os = "none", no_main)]
#![recursion_limit = "1024"]

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

#[cfg(not(target_os = "none"))]
extern crate std;


#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate static_assertions;
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate bitfield;
#[cfg(test)]
#[macro_use]
extern crate mashup;

use core::fmt::Write;
use alloc::string::String;
use crate::utils::io;

pub mod paging;
pub mod event;
pub mod error;
pub mod log_impl;
#[cfg(any(target_arch = "x86", test, rustdoc))]
#[macro_use]
pub mod i386;
pub mod syscalls;
pub mod frame_allocator;

pub mod heap_allocator;
pub mod devices;
pub mod sync;
pub mod timer;
pub mod process;
pub mod scheduler;
pub mod mem;
pub mod ipc;
pub mod elf_loader;
pub mod utils;
pub mod checks;
pub mod cpu_locals;
pub mod panic;

#[cfg(target_os = "none")]
// Make rust happy about rust_oom being no_mangle...
pub use crate::heap_allocator::rust_oom;

/// The global heap allocator.
///
/// Creation of a Box, Vec, Arc, ... will use its API.
/// See the [heap_allocator] module for more info.
#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: heap_allocator::Allocator = heap_allocator::Allocator::new();

use crate::i386::stack;
use crate::paging::{PAGE_SIZE, MappingAccessRights};
use crate::mem::VirtualAddress;
use crate::process::{ProcessStruct, ThreadStruct};
use sunrise_libkern::MemoryType;
use crate::cpu_locals::init_cpu_locals;

/// Forces a double fault by stack overflowing.
///
/// Can be used to manually check the double fault task gate is configured correctly.
///
/// Works by purposely creating a KernelStack overflow.
///
/// When we reach the top of the stack and attempt to write to the guard page following it, it causes a PageFault Execption.
///
/// CPU will attempt to handle the exception, and push some values at `$esp`, which still points in the guard page.
/// This triggers the DoubleFault exception.
unsafe fn force_double_fault() {
    loop {
        asm!("push 0" :::: "intel", "volatile");
    }
}

/// The kernel's `main`.
///
/// # State
///
/// Called after the arch-specific initialisations are done.
///
/// At this point the scheduler is initialized, and we are running as process `init`.
///
/// # Goal
///
/// Our job is to launch all the Kernel Internal Processes.
///
/// These are the minimal set of sysmodules considered essential to system bootup (`filesystem`, `loader`, `sm`, `pm`, `boot`),
/// which either provide necessary services for loading a process, or may define the list of other processes to launch (`boot`).
///
/// We load their elf with a minimal [elf_loader], add them to the schedule queue, and run them as regular userspace processes.
///
/// # Afterwards
///
/// After this, our job here is done. We mark the `init` process (ourselves) as killed, unschedule, and kernel initialisation is
/// considered finished.
///
/// From now on, the kernel's only job will be to respond to IRQs and serve syscalls.
fn main() {
    info!("Loading all the init processes");
    for module in i386::multiboot::get_boot_information().module_tags().skip(1) {
        info!("Loading {}", module.name());
        let mapped_module = elf_loader::map_grub_module(module)
            .unwrap_or_else(|_| panic!("Unable to find available memory for module {}", module.name()));
        let proc = ProcessStruct::new(String::from(module.name()), elf_loader::get_kacs(&mapped_module)).unwrap();
        let (ep, sp) = {
                let mut pmemlock = proc.pmemory.lock();

                let ep = elf_loader::load_builtin(&mut pmemlock, &mapped_module);

                let stack = pmemlock.find_available_space(20 * PAGE_SIZE)
                    .unwrap_or_else(|_| panic!("Cannot create a stack for process {:?}", proc));
                pmemlock.guard(stack, PAGE_SIZE, MemoryType::Reserved).unwrap();
                pmemlock.create_regular_mapping(stack + PAGE_SIZE, 19 * PAGE_SIZE, MemoryType::Stack, MappingAccessRights::u_rw()).unwrap();

                (VirtualAddress(ep), stack + 20 * PAGE_SIZE)
        };
        let thread = ThreadStruct::new(&proc, ep, sp, None)
            .expect("failed creating thread for service");
        ThreadStruct::start(thread)
            .expect("failed starting thread for service");
    }

    let lock = sync::SpinLockIRQ::new(());
    loop {
        // TODO: Exit process.
        let _ = scheduler::unschedule(&lock, lock.lock());
    }
}

/// The entry point of our kernel.
///
/// This function is jump'd into from the bootstrap code, which:
///
/// * enabled paging,
/// * gave us a valid KernelStack,
/// * mapped grub's multiboot information structure in KernelLand (its address in $ebx),
///
/// What we do is just bzero the .bss, and call a rust function, passing it the content of $ebx.
#[cfg(any(target_os = "none", rustdoc))]
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
///
/// This function takes care of initializing the kernel, before calling the main function.
#[cfg(any(target_os = "none", rustdoc))]
#[no_mangle]
pub extern "C" fn common_start(multiboot_info_addr: usize) -> ! {
    use crate::devices::rs232::{SerialAttributes, SerialColor};

    log_impl::early_init();


    let log = &mut devices::rs232::SerialLogger;
    // Say hello to the world
    let _ = writeln!(log, "\n# Welcome to {}SunriseOS{}!\n",
        SerialAttributes::fg(SerialColor::LightCyan),
        SerialAttributes::default());

    // Parse the multiboot infos
    let boot_info = unsafe { multiboot2::load(multiboot_info_addr) };
    info!("Parsed multiboot informations");

    // Setup frame allocator
    frame_allocator::init(&boot_info);
    info!("Initialized frame allocator");

    // Set up (read: inhibit) the GDT.
    info!("Initializing gdt...");
    i386::gdt::init_gdt();
    info!("Gdt initialized");

    i386::multiboot::init(boot_info);

    log_impl::init();

    info!("Start ACPI detection");
    unsafe { i386::acpi::init(); }

    info!("Allocating cpu_locals");
    init_cpu_locals(1);

    info!("Enabling interrupts");
    unsafe { i386::interrupt_service_routines::init(); }

    devices::init_timer();

    //info!("Disable timer interrupt");
    //devices::pic::get().mask(0);

    info!("Becoming the first process");
    unsafe { scheduler::create_first_process() };

    info!("Calling main()");

    main();
    // Die !
    // We shouldn't reach this...
    loop {
        #[cfg(target_os = "none")]
        unsafe { asm!("HLT"); }
    }
}

/// The exception handling personality function for use in the bootstrap.
///
/// We have no exception handling in the kernel, so make it do nothing.
#[cfg(target_os = "none")]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

/// Function called on `panic!` invocation.
///
/// Kernel panics.
#[cfg(target_os = "none")]
#[panic_handler] #[no_mangle]
pub extern fn panic_fmt(p: &::core::panic::PanicInfo<'_>) -> ! {
    panic::kernel_panic(&panic::PanicOrigin::KernelAssert {
        panic_message: format_args!("{}", p)
    });
}
