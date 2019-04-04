//! Userspace library
//!
//! Provides an allocator, various lang items.

#![no_std]
#![feature(global_asm, asm, start, lang_items, core_intrinsics, const_fn, alloc, box_syntax, untagged_unions, naked_functions)]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

#![allow(non_upper_case_globals)] // I blame roblabla.

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate alloc;


#[macro_use]
extern crate bitfield;


#[macro_use]
extern crate sunrise_libutils;
#[macro_use]
extern crate failure;


#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

pub mod caps;
pub mod syscalls;
pub mod mem;
pub mod types;
pub mod ipc;
pub mod sm;
pub mod vi;
pub mod ahci;
pub mod error;
pub mod allocator;
pub mod terminal;
pub mod window;
pub mod zero_box;
mod crt0;
mod log_impl;

pub use sunrise_libutils::io;

use sunrise_libutils as utils;

/// Global allocator. Every implicit allocation in the rust liballoc library (for
/// instance for Vecs, Arcs, etc...) are allocated with this allocator.
#[cfg(all(target_os = "none", not(test)))]
#[global_allocator]
static ALLOCATOR: allocator::Allocator = allocator::Allocator::new();

// Runtime functions
//
// Functions beyond this lines are required by the rust compiler when building
// for no_std. Care should be exercised when changing them, as lang items are
// extremely picky about how their types or implementation.

/// The exception handling personality function for use in the bootstrap.
///
/// We currently have no userspace exception handling, so make it do nothing.
#[cfg(all(target_os = "none", not(test)))]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

/// Function called on `panic!` invocation. Prints the panic information to the
/// kernel debug logger, and exits the process.
#[cfg(all(target_os = "none", not(test)))]
#[panic_handler] #[no_mangle]
pub extern fn panic_fmt(p: &core::panic::PanicInfo<'_>) -> ! {
    let _ = syscalls::output_debug_string(&format!("{}", p));
    syscalls::exit_process();
}

use core::alloc::Layout;

// TODO: Don't panic in the oom handler, exit instead.
// BODY: Panicking may allocate, so calling panic in the OOM handler is a
// BODY: terrible idea.
/// OOM handler. Causes a panic.
#[cfg(all(target_os = "none", not(test)))]
#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_: Layout) -> ! {
    panic!("OOM")
}

/// calls logger initialization, main, and finally exits the
/// process.
#[cfg(all(target_os = "none", not(test)))]
#[no_mangle]
pub unsafe extern fn real_start() -> ! {
    extern {
        fn main(argc: isize, argv: *const *const u8) -> i32;
    }

    log_impl::init();
    let _ret = main(0, core::ptr::null());
    syscalls::exit_process();
}

/// A trait for implementing arbitrary return types in the `main` function.
///
/// The c-main function only supports to return integers as return type.
/// So, every type implementing the `Termination` trait has to be converted
/// to an integer.
///
/// The default implementations are returning 0 to indicate a successful
/// execution. In case of a failure, 1 is returned.
#[cfg(all(target_os = "none", not(test)))]
#[lang = "termination"]
trait Termination {
    /// Is called to get the representation of the value as status code.
    /// This status code is returned to the operating system.
    fn report(self) -> i32;
}

#[cfg(all(target_os = "none", not(test)))]
impl Termination for () {
    #[inline]
    fn report(self) -> i32 { 0 }
}

#[cfg(all(target_os = "none", not(test)))]
#[lang = "start"]
#[allow(clippy::unit_arg)]
fn main<T: Termination>(main: fn(), _argc: isize, _argv: *const *const u8) -> isize {
    main().report() as isize
}
