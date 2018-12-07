//! Userspace library
//!
//! Provides an allocator, various lang items.

#![no_std]
#![warn(missing_docs)]
#![allow(unused_unsafe)]
#![feature(global_asm, asm, start, lang_items, core_intrinsics, const_fn, alloc)]

extern crate linked_list_allocator;
#[macro_use]
extern crate alloc;
extern crate byteorder;
extern crate arrayvec;
#[macro_use]
extern crate bitfield;
extern crate bit_field;
extern crate spin;
#[macro_use]
extern crate kfs_libutils;
extern crate kfs_libkern;
#[macro_use]
extern crate failure;
extern crate font_rs;
extern crate hashmap_core;

pub mod syscalls;
pub mod io;
pub mod types;
pub mod ipc;
pub mod sm;
pub mod vi;
pub mod error;
pub mod allocator;
pub mod terminal;
pub mod window;

use kfs_libutils as utils;
use error::{Error, LibuserError};

// TODO: report #[cfg(not(test))] and #[global_allocator]
// BODY: `#[cfg(not(test))]` still compiles this item with cargo test,
// BODY: but `#[cfg(target_os = "none")] does not. I think this is a bug,
// BODY: we should report it.
#[cfg(target_os = "none")]
#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator::new();

/// # Panics
///
/// Panics on underflow when size = 0.
///
/// Panics on underflow when align = 0.
///
pub fn find_free_address(size: usize, align: usize) -> Result<usize, Error> {
    let mut addr = 0;
    // Go over the address space.
    loop {
        let (meminfo, _) = syscalls::query_memory(addr)?;
        if meminfo.memtype == kfs_libkern::MemoryType::Unmapped {
            let alignedbaseaddr = kfs_libutils::align_up_checked(meminfo.baseaddr, align).ok_or(LibuserError::AddressSpaceExhausted)?;

            let alignment = alignedbaseaddr - meminfo.baseaddr;
            if alignment.checked_add(size - 1).ok_or(LibuserError::AddressSpaceExhausted)? < meminfo.size {
                return Ok(alignedbaseaddr)
            }
        }
        addr = meminfo.baseaddr.checked_add(meminfo.size).ok_or(LibuserError::AddressSpaceExhausted)?;
    }
}

#[cfg(target_os = "none")]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

#[cfg(target_os = "none")]
#[panic_handler] #[no_mangle]
pub extern fn panic_fmt(p: &core::panic::PanicInfo) -> ! {
    syscalls::output_debug_string(&format!("{}", p));
    syscalls::exit_process();
}

use core::alloc::Layout;

// required: define how Out Of Memory (OOM) conditions should be handled
// *if* no other crate has already defined `oom`
#[cfg(target_os = "none")]
#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_: Layout) -> ! {
    panic!("OOM")
}

#[cfg(target_os = "none")]
#[no_mangle]
pub unsafe extern fn start() -> ! {
    asm!("
        // Memset the bss. Hopefully memset doesn't actually use the bss...
        lea eax, BSS_END
        lea ebx, BSS_START
        sub eax, ebx
        push eax
        push 0
        push ebx
        call memset
        add esp, 12
        " : : : : "intel", "volatile");

    extern {
        fn main(argc: isize, argv: *const *const u8) -> i32;
    }

    let _ret = main(0, core::ptr::null());
    syscalls::exit_process();
}

#[cfg(target_os = "none")]
#[lang = "termination"]
trait Termination {
    fn report(self) -> i32;
}

#[cfg(target_os = "none")]
impl Termination for () {
    #[inline]
    fn report(self) -> i32 { 0 }
}

#[cfg(target_os = "none")]
#[lang = "start"]
fn main<T: Termination>(main: fn(), _argc: isize, _argv: *const *const u8) -> isize {
    main().report() as isize
}
