//! Sunrise kernel
//!
//! A small kernel written in rust for shit and giggles. Also, hopefully the
//! last project I'll do before graduating from 42 >_>'.
//!
//! Currently doesn't do much, besides booting and printing Hello World on the
//! screen. But hey, that's a start.

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, naked_functions, core_intrinsics, const_fn, abi_x86_interrupt, allocator_api, box_syntax, no_more_cas, const_vec_new, step_trait, thread_local, nll, underscore_const_names, doc_cfg)]
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
pub mod interrupts;
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

                let stack = pmemlock.find_available_space(5 * PAGE_SIZE)
                    .unwrap_or_else(|_| panic!("Cannot create a stack for process {:?}", proc));
                pmemlock.guard(stack, PAGE_SIZE, MemoryType::Reserved).unwrap();
                pmemlock.create_regular_mapping(stack + PAGE_SIZE, 4 * PAGE_SIZE, MemoryType::Stack, MappingAccessRights::u_rw()).unwrap();

                (VirtualAddress(ep), stack + 5 * PAGE_SIZE)
        };
        let thread = ThreadStruct::new(&proc, ep, sp, 0)
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

    devices::init_timer();

    info!("Enabling interrupts");
    unsafe { interrupts::init(); }

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

/// The kernel panic function.
///
/// Executed on a `panic!`, but can also be called directly.
/// Will print some useful debugging information, and never return.
///
/// This function will print a stack dump, from `stackdump_source`.
/// If `None` is passed, it will dump the current KernelStack instead, this is the default for a panic!.
/// It is usefull being able to debug another stack that our own, especially when we double-faulted.
///
/// # Safety
///
/// When a `stackdump_source` is passed, this function cannot check the requirements of
/// [dump_stack], it is the caller's job to do it.
///
/// Note that if `None` is passed, this function is safe.
///
/// [dump_stack]: crate::stack::dump_stack
unsafe fn do_panic(msg: core::fmt::Arguments<'_>, stackdump_source: Option<stack::StackDumpSource>) -> ! {

    // Disable interrupts forever!
    unsafe { sync::permanently_disable_interrupts(); }
    // Don't deadlock in the logger
    unsafe { SerialLogger.force_unlock(); }

    //todo: force unlock the KernelMemory lock
    //      and also the process memory lock for userspace stack dumping (only if panic-on-excetpion ?).

    use crate::devices::rs232::SerialLogger;

    let _ = writeln!(SerialLogger, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
                                    ! Panic! at the disco\n\
                                    ! {}\n\
                                    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
                     msg);

    // Parse the ELF to get the symbol table.
    // We must not fail, so this means a lot of Option checking :/
    use xmas_elf::symbol_table::Entry32;
    use xmas_elf::sections::SectionData;
    use xmas_elf::ElfFile;
    use crate::elf_loader::MappedGrubModule;

    let mapped_kernel_elf = i386::multiboot::try_get_boot_information()
        .and_then(|info| info.module_tags().nth(0))
        .and_then(|module| elf_loader::map_grub_module(module).ok());

    /// Gets the symbol table of a mapped module.
    fn get_symbols<'a>(mapped_kernel_elf: &'a Option<MappedGrubModule<'_>>) -> Option<(&'a ElfFile<'a>, &'a[Entry32])> {
        let module = mapped_kernel_elf.as_ref()?;
        let elf = module.elf.as_ref().ok()?;
        let data = elf.find_section_by_name(".symtab")?
            .get_data(elf).ok()?;
        let st = match data {
            SectionData::SymbolTable32(st) => st,
            _ => return None
        };
        Some((elf, st))
    }

    let elf_and_st = get_symbols(&mapped_kernel_elf);

    if elf_and_st.is_none() {
        let _ = writeln!(SerialLogger, "Panic handler: Failed to get kernel elf symbols");
    }

    // Then print the stack
    if let Some(sds) = stackdump_source {
        unsafe {
            // this is unsafe, caller must check safety
            crate::stack::dump_stack(&sds, elf_and_st)
        }
    } else {
        crate::stack::KernelStack::dump_current_stack(elf_and_st)
    }

    let _ = writeln!(SerialLogger, "Thread : {:#x?}", scheduler::try_get_current_thread());

    let _ = writeln!(SerialLogger, "!!!!!!!!!!!!!!!END PANIC!!!!!!!!!!!!!!");

    loop { unsafe { asm!("HLT"); } }
}

/// Function called on `panic!` invocation.
///
/// Kernel panics.
#[cfg(target_os = "none")]
#[panic_handler] #[no_mangle]
pub extern fn panic_fmt(p: &::core::panic::PanicInfo<'_>) -> ! {
    unsafe {
        // safe: we're not passing a stackdump_source
        //       so it will use our current stack, which is safe.
        do_panic(format_args!("{}", p), None);
    }
}
