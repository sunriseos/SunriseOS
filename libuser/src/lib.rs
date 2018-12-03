//! Userspace library
//!
//! Provides an allocator, various lang items.

#![no_std]
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

pub mod syscalls;
pub mod io;
pub mod types;
pub mod ipc;
pub mod sm;
pub mod error;

use kfs_libutils as utils;
use linked_list_allocator::LockedHeap;
use error::{Error, LibuserError};

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

// Let's grant ourselves 10MB of heap
static mut ALLOCATOR_BUF: [u8; 10_000_000] = [0; 10_000_000];

fn init_heap() {
    unsafe {
        let heap_start = ALLOCATOR_BUF.as_ptr() as usize;
        let heap_size = ALLOCATOR_BUF.len();
        ALLOCATOR.lock().init(heap_start, heap_size);
    }
}

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

    init_heap();
    let _ret = main(0, core::ptr::null());
    syscalls::exit_process();
}

#[lang = "termination"]
trait Termination {
    fn report(self) -> i32;
}

impl Termination for () {
    #[inline]
    fn report(self) -> i32 { 0 }
}

#[lang = "start"]
fn main<T: Termination>(main: fn(), _argc: isize, _argv: *const *const u8) -> isize {
    main().report() as isize
}
