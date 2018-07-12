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
//! 2. enable paging
//! 3. load kernel at the end of address space
//! 5. construct a map of kernel sections that will be passed to kernel
//! 4. jump to kernel
//!
//! ## Logging
//!
//! We implement a really dumb serial logger for the bootstrap stage. We don't use any of the
//! fancy logging interfaces that the kernel has.
//!

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, naked_functions, core_intrinsics, const_fn, abi_x86_interrupt, iterator_step_by, used, panic_implementation)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]
#![allow(unused)]
#[cfg(not(target_os = "none"))]
use std as core;

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

use core::fmt::Write;

mod utils;
mod bootstrap_logging;
mod gdt;
mod address;
mod paging;
mod frame_alloc;
mod elf_loader;

use bootstrap_logging::Serial;
use frame_alloc::FrameAllocator;
use paging::KernelLand;

#[repr(align(4096))]
pub struct AlignedStack([u8; 4096 * 4]);

pub static mut STACK: AlignedStack = AlignedStack([0; 4096 * 4]);

/// The very start
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
    writeln!(Serial, "Bootstrap starts...");

    // Set up (read: inhibit) the GDT.
    gdt::init_gdt();
    writeln!(Serial, "= Gdt initialized");

    // Parse the multiboot infos
    let boot_info = unsafe { multiboot2::load(multiboot_info_addr) };
    write!(Serial, "{:?}", boot_info);
    writeln!(Serial, "= Parsed multiboot informations");

    // Setup frame allocator
    FrameAllocator::init(&boot_info);
    writeln!(Serial, "= Initialized frame allocator");

    // Create a set of page tables
    let mut page_tables = unsafe { paging::map_bootstrap(&boot_info) };
    writeln!(Serial, "= Created page tables");

    // Start using these page tables
    unsafe { page_tables.enable_paging() }
    writeln!(Serial, "= Paging on");

    let kernel_entry_point = elf_loader::load_kernel(&boot_info);
    writeln!(Serial, "= Loaded kernel");

    // Move the multiboot_header to a single page in kernel space.
    let multiboot_info_page = paging::get_page::<KernelLand>();
    let total_size = unsafe {
        // Safety: multiboot_info_addr should always be valid, provided the
        // bootloader ಠ_ಠ
        *(multiboot_info_addr as *const u32) as usize
    };
    assert!(total_size <= paging::PAGE_SIZE, "Expected multiboot info to fit in a page");
    unsafe {
        // Safety: We just allocated this page. What could go wrong?
        core::ptr::copy(multiboot_info_addr as *const u8,
                        multiboot_info_page.addr() as *mut u8,
                        total_size);
    }
    writeln!(Serial, "= Copied multiboot info");

    writeln!(Serial, "= Jumping to kernel");
    unsafe {
        asm!("mov ebx, $0
              jmp $1"
              : // no output
              : "r"(multiboot_info_page.addr()), "r"(kernel_entry_point)
              : "ebx", "memory"
              : "intel"
              );
    }

    unsafe { ::core::intrinsics::unreachable() }
}

#[cfg(target_os = "none")]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

#[cfg(target_os = "none")]
#[panic_implementation] #[no_mangle]
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

multiboot_header! {
    framebuffer: FramebufferTag::new(1280, 800, 32),
    end: EndTag::default()
}
