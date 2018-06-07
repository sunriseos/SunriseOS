//! KFS
//!
//! A small kernel written in rust for shit and giggles. Also, hopefully the
//! last project I'll do before graduating from 42 >_>'.
//!
//! Currently doesn't do much, besides booting and printing Hello World on the
//! screen. But hey, that's a start.

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, repr_transparent, naked_functions, core_intrinsics, const_fn, abi_x86_interrupt, iterator_step_by)]
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
use ascii::AsAsciiStr;
use core::fmt::Write;

mod print;
pub use print::*;

mod i386;
#[cfg(target_os = "none")]
mod gdt;
mod utils;
mod frame_alloc;
pub use frame_alloc::FrameAllocator;
pub use i386::paging;
pub use i386::stack;
use i386::paging::{InactivePageTables, PageTablesSet, EntryFlags};

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

    writeln!(Printer, "----------");

    let mymem = FrameAllocator::alloc_frame();
    writeln!(Printer, "Allocated address {:?}", mymem);
    FrameAllocator::free_frame(mymem);
    writeln!(Printer, "Freed address {:?}", mymem);

    writeln!(Printer, "----------");

    let mymem = FrameAllocator::alloc_frame();
    writeln!(Printer, "Allocated address {:?}", mymem);
    FrameAllocator::free_frame(mymem);
    writeln!(Printer, "Freed address {:?}", mymem);

    writeln!(Printer, "----------");

    let mymem1 = FrameAllocator::alloc_frame();
    writeln!(Printer, "Allocated address {:?}", mymem1);
    let mymem2 = FrameAllocator::alloc_frame();
    writeln!(Printer, "Allocated address {:?}", mymem2);
    let mymem3 = FrameAllocator::alloc_frame();
    writeln!(Printer, "Allocated address {:?}", mymem3);
    FrameAllocator::free_frame(mymem1);
    writeln!(Printer, "Freed address {:?}", mymem1);
    FrameAllocator::free_frame(mymem2);
    writeln!(Printer, "Freed address {:?}", mymem2);
    FrameAllocator::free_frame(mymem3);
    writeln!(Printer, "Freed address {:?}", mymem3);

    writeln!(Printer, "----------");

    let page1 = ::paging::get_page::<::paging::UserLand>();
    writeln!(Printer, "Got page {:x}", page1.addr());
    let page2 = ::paging::get_page::<::paging::UserLand>();
    writeln!(Printer, "Got page {:x}", page2.addr());

    let mut inactive_pages = InactivePageTables::new();
    let page4 = inactive_pages.get_page::<paging::UserLand>(EntryFlags::PRESENT | EntryFlags::WRITABLE);
    writeln!(Printer, "Got inactive page {:x}", page4.addr());

}

#[repr(align(4096))]
pub struct AlignedStack([u8; 4096 * 4]);

#[link_section = ".stack"]
pub static mut STACK: AlignedStack = AlignedStack([0; 4096 * 4]);

#[cfg(target_os = "none")]
#[no_mangle]
pub unsafe extern fn start() -> ! {
    asm!("
        // Create the stack
        mov esp, $0
        add esp, 16383
        mov ebp, esp
        // Save multiboot infos addr present in ebx
        push ebx
        call common_start" : : "m"(&STACK) : : "intel", "volatile");
    core::intrinsics::unreachable()
}

/// CRT0 starts here.
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn common_start(multiboot_info_addr: usize) -> ! {
    // Do whatever is necessary to have a proper environment here.

    // Say hello to the world
    write!(Printer, "\n# Welcome to ");
    Printer::print_attr("KFS".as_ascii_str().expect("ASCII"),
                        PrintAttribute::new(Color::LightCyan, Color::Black, false));
    writeln!(Printer, "!\n");

    // Set up (read: inhibit) the GDT.
    gdt::init_gdt();
    writeln!(Printer, "= Gdt initialized");

    // Parse the multiboot infos
    let boot_info = unsafe { multiboot2::load(multiboot_info_addr) };
    writeln!(Printer, "= Parsed multiboot informations");

    // Setup frame allocator
    FrameAllocator::init(&boot_info);
    writeln!(Printer, "= Initialized frame allocator");

    // Setup paging, poorly identity map the first 4Mb of memory
    unsafe { paging::init_paging() }
    writeln!(Printer, "= Paging on");

    // Create page tables with the right access rights for each kernel section
    unsafe { paging::remap_kernel(&boot_info) }
    writeln!(Printer, "= Remapped the kernel");

    let new_stack = stack::KernelStack::allocate_stack(&mut paging::ACTIVE_PAGE_TABLES.lock())
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
    writeln!(Printer, "= Switched to new kernel stack");

    writeln!(Printer, "= Calling main()");
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
