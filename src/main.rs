//! KFS
//!
//! A small kernel written in rust for shit and giggles. Also, hopefully the
//! last project I'll do before graduating from 42 >_>'.
//!
//! Currently doesn't do much, besides booting and printing Hello World on the
//! screen. But hey, that's a start.

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, repr_transparent, naked_functions)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
use std as core;

extern crate arrayvec;
extern crate ascii;
extern crate bit_field;
#[cfg(target_os = "none")]
extern crate compiler_builtins;
#[macro_use]
extern crate lazy_static;
extern crate spin;

use ascii::AsAsciiStr;
use core::fmt::Write;

mod print;
pub use print::*;

mod i386;
#[cfg(target_os = "none")]
mod gdt;

fn main() {
    Printer::println(b"Hello world!      ".as_ascii_str().expect("ASCII"));
    Printer::println(b"the cake is a lie\nand so is love".as_ascii_str().expect("ASCII"));
    Printer::println(b"A very long line that goes like this : Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor.".as_ascii_str().expect("ASCII"));
    Printer::println_attr(b"Whoah, nice color".as_ascii_str().expect("ASCII"),
                                  PrintAttribute::new(Color::Pink, Color::Cyan, false));
    Printer::println_attr(b"such hues".as_ascii_str().expect("ASCII"),
                                  PrintAttribute::new(Color::Magenta, Color::LightGreen, true));
    Printer::println_attr(b"very polychromatic".as_ascii_str().expect("ASCII"),
                           PrintAttribute::new(Color::Yellow, Color::Pink, true));
}

#[no_mangle]
pub static mut STACK: [u8; 4096 * 4] = [0; 4096 * 4];

#[cfg(target_os = "none")]
#[no_mangle]
#[naked]
pub unsafe extern fn start() -> ! {
    asm!("lea esp, STACK" : : : : "intel");
    asm!("add esp, 16383" : : : : "intel");
    common_start();
}

/// CRT0 starts here.
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_start() -> ! {
    // Do whatever is necessary to have a proper environment here.

    // Set up (read: inhibit) the GDT.
    gdt::init_gdt();

    main();
    // Die !
    #[cfg(target_os = "none")]
    unsafe { asm!("HLT"); }
    // We shouldn't reach this...
    loop {}
}

#[cfg(target_os = "none")]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

#[cfg(target_os = "none")]
#[lang = "panic_fmt"] #[no_mangle]
pub extern fn panic_fmt(msg: core::fmt::Arguments,
                        file: &'static str,
                        line: u32,
                        column: u32) -> ! {

    let _ = writeln!(Printer, "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\
                               ! Panic! at the disco\n\
                               ! file {} - line {} - col {}\n\
                               ! {}\n\
                               !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
                     file, line, column, msg);
    loop { }
}

#[repr(C, packed)]
#[allow(dead_code)]
pub struct MultiBootHeader {
    magic: u32,
    architecture: u32,
    header_length: u32,
    checksum: u32,

    // TODO: This is technically a DST array...
    tag: u16,
    flags: u16,
    size: u32
}

#[cfg_attr(target_os = "none", link_section = ".multiboot_header")]
pub static MULTIBOOT_HEADER : MultiBootHeader = MultiBootHeader {
    magic: 0xe85250d6,
    architecture: 0,
    header_length: core::mem::size_of::<MultiBootHeader>() as u32,
    checksum: u32::max_value() - (0xe85250d6 + 0 + core::mem::size_of::<MultiBootHeader>() as u32) + 1,
    tag: 0,
    flags: 0,
    size: 8
};
