//! KFS
//!
//! A small kernel written in rust for shit and giggles. Also, hopefully the
//! last project I'll do before graduating from 42 >_>'.
//!
//! Currently doesn't do much, besides booting and printing Hello World on the
//! screen. But hey, that's a start.

#![feature(lang_items, start, asm, global_asm, compiler_builtins_lib, repr_transparent, naked_functions, core_intrinsics, const_fn, abi_x86_interrupt, iterator_step_by, used, global_allocator, allocator_api, alloc)]
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
extern crate alloc;
extern crate linked_list_allocator;

use ascii::AsAsciiStr;
use core::fmt::Write;
use alloc::*;

mod print;
pub use print::*;

mod i386;
#[cfg(target_os = "none")]
mod gdt;
mod utils;
mod frame_alloc;
mod heap_allocator;

#[global_allocator]
static ALLOCATOR: heap_allocator::Allocator = heap_allocator::Allocator::new();

pub use frame_alloc::FrameAllocator;
pub use i386::paging;
pub use i386::stack;
use i386::paging::{InactivePageTables, PageTablesSet, EntryFlags};

fn main() {
    Printer::println(b"Hello world!      ".as_ascii_str().expect("ASCII"));
    Printer::println_attr(b"Whoah, nice color".as_ascii_str().expect("ASCII"),
                                  PrintAttribute::new(Color::Pink, Color::Cyan, false));
    Printer::println_attr(b"such hues".as_ascii_str().expect("ASCII"),
                                  PrintAttribute::new(Color::Magenta, Color::LightGreen, true));
    Printer::println_attr(b"very polychromatic".as_ascii_str().expect("ASCII"),
                           PrintAttribute::new(Color::Yellow, Color::Pink, true));

    let mymem = FrameAllocator::alloc_frame();
    writeln!(Printer, "Allocated frame {:x?}", mymem);
    FrameAllocator::free_frame(mymem);
    writeln!(Printer, "Freed frame {:x?}", mymem);

    writeln!(Printer, "----------");

    let page1 = ::paging::get_page::<::paging::UserLand>();
    writeln!(Printer, "Got page {:#x}", page1.addr());
    let page2 = ::paging::get_page::<::paging::UserLand>();
    writeln!(Printer, "Got page {:#x}", page2.addr());

    writeln!(Printer, "----------");

    let mut inactive_pages = InactivePageTables::new();
    writeln!(Printer, "Created new tables");
    let page_innactive = inactive_pages.get_page::<paging::UserLand>();
    writeln!(Printer, "Mapped inactive page {:#x}", page_innactive.addr());
    unsafe { inactive_pages.switch_to() };
    writeln!(Printer, "Switched to new tables");
    let page_active = ::paging::get_page::<::paging::UserLand>();
    writeln!(Printer, "Got page {:#x}", page_active.addr());

    writeln!(Printer, "Testing some string heap alloc: {}", String::from("Hello World"));
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


    write!(Printer, "Clearing screen...");
    Printer::clear_screen();

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

    // Create page tables with the right access rights for each kernel section
    let page_tables =
    unsafe { paging::map_kernel(&boot_info) };
    writeln!(Printer, "= Mapped the kernel");

    // Start using these page tables
    unsafe { page_tables.enable_paging() }
    writeln!(Printer, "= Paging on");

    let new_stack = stack::KernelStack::allocate_stack()
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
