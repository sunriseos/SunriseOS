//! Bootstrap stage
//!
//! This stage is executed right after bootloader, and before we pass control to the kernel.
//! Its main goal is to enable paging with the kernel mapped at the end of address space,
//! and jump to kernel after that.
//!
//! ## Virtual memory
//!
//! What the bootstrap stage does is :
//! 1. create a set of pages
//! 2. identity map bootstrap sections
//! 4. load kernel at the end of address space
//! 5. copy the multiboot2 info to be page aligned.
//! 6. Map the multiboot2 info in kernel land.
//! 7. construct a map of kernel sections that will be passed to kernel
//! 8. create a kernel stack
//! 9. jump to kernel
//!
//! ## Logging
//!
//! We implement a really dumb serial logger for the bootstrap stage. We don't use any of the
//! fancy logging interfaces that the kernel has.
//!

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, naked_functions, core_intrinsics, const_fn, abi_x86_interrupt)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

// rustc warnings
#![warn(unused)]
#![allow(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![allow(missing_docs, clippy::missing_docs_in_private_items)]
#![deny(intra_doc_link_resolution_failure)]

// clippy override
#![allow(clippy::cast_lossless)]

#[cfg(not(target_os = "none"))]
use std as core;

#[cfg(not(any(target_arch = "x86", test)))]
compile_error!("WTF");

extern crate arrayvec;
extern crate bit_field;
#[macro_use]
extern crate lazy_static;
extern crate spin;
extern crate multiboot2;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate static_assertions;
extern crate xmas_elf;
extern crate kfs_libutils;

use core::fmt::Write;

pub mod bootstrap_logging;
pub mod gdt;
pub mod address;
pub mod paging;
pub mod frame_alloc;
pub mod elf_loader;
pub mod bootstrap_stack;

use bootstrap_logging::Serial;
use frame_alloc::FrameAllocator;
use paging::{PageTablesSet, KernelLand};
use bootstrap_stack::BootstrapStack;

/// 4 pages, PAGE_SIZE aligned.
#[repr(align(4096))]
pub struct AlignedStack([u8; 4096 * 4]);

/// The stack we start on.
///
/// The first thing we do is to make $esp point to it.
pub static mut STACK: AlignedStack = AlignedStack([0; 4096 * 4]);

/// Prints raw hexdump of the stack.
/// Use this if everything went wrong and you're really hopeless.
pub fn print_stack() {
    unsafe {
        let sp: usize;
        asm!("mov $0, esp" : "=r"(sp) : : : "intel");
        let sp_start = sp - ::STACK.0.as_ptr() as usize;
        kfs_libutils::print_hexdump(&mut Serial, &::STACK.0[sp_start..]);
    }
}

/// The very start.
///
/// We are called from grub, with the address of the multiboot informations in $ebx.
///
/// What we do is :
///
/// * bzero the .bss.
/// * make $esp and $ebp point to [STACK].
/// * call [do_bootstrap], passing it $ebx.
#[cfg(target_os = "none")]
#[no_mangle]
pub unsafe extern fn bootstrap_start() -> ! {
    asm!("
        // Memset the bss. Hopefully memset doesn't actually use the bss...
        mov eax, BSS_END
        sub eax, BSS_START
        push eax
        push 0
        push BSS_START
        call memset
        add esp, 12

        // Create the stack
        mov esp, $0
        add esp, 16383
        mov ebp, esp
        // Save multiboot infos addr present in ebx
        push ebx
        call do_bootstrap" : : "m"(&STACK) : : "intel", "volatile");
    core::intrinsics::unreachable()
}

/// bootstrap stage and call kernel
#[no_mangle]
pub extern "C" fn do_bootstrap(multiboot_info_addr: usize) -> ! {
    unsafe { bootstrap_logging::init_bootstrap_log() };
    let _ = writeln!(Serial, "Bootstrap starts...");

    // Set up (read: inhibit) the GDT.
    gdt::init_gdt();
    let _ = writeln!(Serial, "= Gdt initialized");

    // Parse the multiboot infos
    let boot_info = unsafe { multiboot2::load(multiboot_info_addr) };
    write!(Serial, "{:?}", boot_info);
    let _ = writeln!(Serial, "= Parsed multiboot informations");

    // Setup frame allocator
    FrameAllocator::init(&boot_info);
    let _ = writeln!(Serial, "= Initialized frame allocator");

    // Create a set of page tables
    let mut page_tables = unsafe { paging::map_bootstrap(&boot_info) };
    let _ = writeln!(Serial, "= Created page tables");

    let kernel_entry_point = elf_loader::load_kernel(&mut page_tables, &boot_info);
    let _ = writeln!(Serial, "= Loaded kernel");

    // Move the multiboot_header to a single page in kernel space. This simplifies some
    // things in the kernel.
    let multiboot_info_page = page_tables.get_page::<KernelLand>();
    let multiboot_phys_page = page_tables.get_phys(multiboot_info_page).unwrap();
    let total_size = boot_info.total_size();
    assert!(total_size <= paging::PAGE_SIZE, "Expected multiboot info to fit in a page");
    unsafe {
        // Safety: We just allocated this page. What could go wrong?
        core::ptr::copy(multiboot_info_addr as *const u8,
                        multiboot_phys_page.addr() as *mut u8,
                        total_size);
    }
    let _ = writeln!(Serial, "= Copied multiboot info to page {:#010x}", multiboot_info_page.addr());

    // Start using these page tables
    unsafe { page_tables.enable_paging() }
    let _ = writeln!(Serial, "= Paging on");

    // Allocate a stack for the kernel
    let new_stack = BootstrapStack::allocate_stack()
        .expect("Cannot allocate bootstrap stack");
    let _ = writeln!(Serial, "= Created kernel stack");

    let new_ebp_esp = new_stack.get_stack_start();

    let _ = writeln!(Serial, "= Jumping to kernel");

    #[cfg(not(test))]
    unsafe {
    asm!("
        // save multiboot info pointer
        mov ebx, $0

        // switch to the new stack
        mov ebp, $1
        mov esp, $1

        // jump to the kernel
        jmp $2"
        :
        : "r"(multiboot_info_page), "r"(new_ebp_esp), "r"(kernel_entry_point)
        : "memory", "ebx"
        : "intel", "volatile");
    }

    unreachable!()
}

#[cfg(target_os = "none")]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

/// The bootstrap panic function.
///
/// Something went really wrong, just print a message on serial output, and spin indefinitely.
#[cfg(target_os = "none")]
#[panic_handler] #[no_mangle]
pub extern fn panic_fmt(p: &::core::panic::PanicInfo) -> ! {

    let _ = writeln!(Serial,
                              "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
                               ! Bootstrap panic!\n\
                               ! {}\n\
                               !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
                     p);

    loop { unsafe { asm!("HLT"); } }
}

macro_rules! multiboot_header {
    //($($expr:tt)*) => {
    ($($name:ident: $tagty:ident :: $method:ident($($args:expr),*)),*) => {
        #[repr(C)]
        #[allow(dead_code)]
        pub struct MultiBootHeader {
            magic: u32,
            architecture: u32,
            header_length: u32,
            checksum: u32,
            $($name: $tagty),*
        }

        #[used]
        #[cfg_attr(target_os = "none", link_section = ".multiboot_header")]
        pub static MULTIBOOT_HEADER: MultiBootHeader = MultiBootHeader {
            magic: 0xe85250d6,
            architecture: 0,
            header_length: core::mem::size_of::<MultiBootHeader>() as u32,
            checksum: u32::max_value() - (0xe85250d6 + 0 + core::mem::size_of::<MultiBootHeader>() as u32) + 1,
            $($name: $tagty::$method($($args),*)),*
        };
    }
}

#[repr(C, align(8))]
struct EndTag {
    tag: u16,
    flag: u16,
    size: u32
}

impl EndTag {
    const fn default() -> EndTag {
        EndTag {
            tag: 0,
            flag: 0,
            size: ::core::mem::size_of::<Self>() as u32
        }
    }
}

#[repr(C, align(8))]
struct FramebufferTag {
    tag: u16,
    flags: u16,
    size: u32,
    width: u32,
    height: u32,
    depth: u32
}

impl FramebufferTag {
    const fn new(width: u32, height: u32, depth: u32) -> FramebufferTag {
        FramebufferTag {
            tag: 5,
            flags: 0,
            size: ::core::mem::size_of::<Self>() as u32,
            width: width,
            height: height,
            depth: depth
        }
    }
}

#[repr(C, align(8))]
struct ModuleAlignmentTag {
    tag: u16,
    flags: u16,
    size: u32,
}

impl ModuleAlignmentTag {
    const fn new() -> ModuleAlignmentTag {
        ModuleAlignmentTag {
            tag: 6,
            flags: 0,
            size: ::core::mem::size_of::<Self>() as u32,
        }
    }
}

multiboot_header! {
    framebuffer: FramebufferTag::new(1280, 800, 32),
    //module_alignment: ModuleAlignmentTag::new(),
    end: EndTag::default()
}
