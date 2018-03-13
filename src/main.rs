#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib)]
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(not(target_os = "none"))]
use std as core;

#[cfg(target_os = "none")]
extern crate compiler_builtins;
extern crate ascii;
#[macro_use]
extern crate lazy_static;
extern crate spin;

use ascii::AsAsciiStr;

mod print;
use print::*;

fn main() {
    //let hello = b"Hello World!";
    //let color_byte = 0x1f; // white foreground, blue background

    //let mut hello_colored = [color_byte; 24];
    //for (i, char_byte) in hello.into_iter().enumerate() {
    //    hello_colored[i*2] = *char_byte;
    //}

    // write `Hello World!` to the center of the VGA text buffer
    //let buffer_ptr = (0xb8000 + 1988) as *mut _;
    //unsafe { *buffer_ptr = hello_colored };
    let mut printer = Print::new();
    printer.println(b"Hello world!      ".as_ascii_str().expect("ASCII"));
    printer.println(b"the cake is a lie\nand so is love".as_ascii_str().expect("ASCII"));
    printer.println(b"A very long line that goes like this : Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor.".as_ascii_str().expect("ASCII"));
    printer.println(b"Let's count now :\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20".as_ascii_str().expect("ASCII"));
    printer.print_attr(b"Whoah, nice color".as_ascii_str().expect("ASCII"),
                       PrintAttribute::new(Color::Pink, Color::Cyan, false));
    printer.print_attr(b"such blink".as_ascii_str().expect("ASCII"),
                       PrintAttribute::new(Color::Magenta, Color::LightGreen, true));
    printer.print_attr(b"such blink".as_ascii_str().expect("ASCII"),
                       PrintAttribute::new(Color::White, Color::Black, true));
    printer.print_attr(b"such blink".as_ascii_str().expect("ASCII"),
                       PrintAttribute::new(Color::White, Color::Black, false));
}

#[cfg(target_os = "none")]
#[no_mangle]
pub extern fn start() -> ! {
    // Do whatever is necessary to have a proper environment here.
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
#[lang = "panic_fmt"] #[no_mangle] pub extern fn panic_fmt() -> ! { loop {} }

#[repr(packed)]
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
