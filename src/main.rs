#![feature(lang_items, start, asm, global_asm)]
#![no_std]
#![no_main]

fn main() {
    
}

#[no_mangle]
pub extern fn start() -> ! {
    // Do whatever is necessary to have a proper environment here.
    main();
    // Die !
    unsafe { asm!("HLT"); }
    // We shouldn't reach this...
    loop {}
}

#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}
#[lang = "panic_fmt"] #[no_mangle] pub extern fn panic_fmt() -> ! { loop {} }

#[repr(packed)]
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

#[link_section = ".multiboot_header"]
pub static MULTIBOOT_HEADER : MultiBootHeader = MultiBootHeader {
    magic: 0xe85250d6,
    architecture: 0,
    header_length: core::mem::size_of::<MultiBootHeader>() as u32,
    checksum: u32::max_value() - (0xe85250d6 + 0 + core::mem::size_of::<MultiBootHeader>() as u32) + 1,
    tag: 0,
    flags: 0,
    size: 8
};
