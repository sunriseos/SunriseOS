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

use core::fmt::Write;

mod bootstrap_logging;
use bootstrap_logging::Serial;

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
    bootstrap_logging::bootstrap_log("Bootstrap logs !");
    loop {};
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
