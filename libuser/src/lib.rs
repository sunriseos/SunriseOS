//! Userspace library
//!
//! Provides an allocator, various lang items.

#![no_std]
#![feature(global_asm, asm, start, lang_items, core_intrinsics, const_fn, box_syntax, untagged_unions, naked_functions, proc_macro_hygiene, doc_cfg, async_await, unboxed_closures, fn_traits, thread_local)]

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

// Marked public for use in the object macro.
#[macro_use]
#[doc(hidden)]
pub extern crate log as __log;

use swipc_gen::gen_ipc;

pub mod argv;
pub mod caps;
pub mod syscalls;
pub mod mem;
pub mod types;
pub mod ipc;
pub mod threads;
pub mod thread_local_storage;
pub mod futures;

#[gen_ipc(path = "../../ipcdefs/sm.id", prefix = "sunrise_libuser")]
pub mod sm {}
#[gen_ipc(path = "../../ipcdefs/vi.id", prefix = "sunrise_libuser")]
pub mod vi {}
#[gen_ipc(path = "../../ipcdefs/ahci.id", prefix = "sunrise_libuser")]
pub mod ahci {}
#[gen_ipc(path = "../../ipcdefs/time.id", prefix = "sunrise_libuser")]
pub mod time {}
#[gen_ipc(path = "../../ipcdefs/filesystem.id", prefix = "sunrise_libuser")]
pub mod fs {}
#[gen_ipc(path = "../../ipcdefs/example.id", prefix = "sunrise_libuser")]
pub mod example {}

pub mod error;
pub mod allocator;
pub mod terminal;
pub mod window;
pub mod zero_box;
mod crt0;
mod log_impl;
pub use sunrise_libutils::loop_future;

pub use sunrise_libutils::io;

use sunrise_libutils as utils;

/// Global allocator. Every implicit allocation in the rust liballoc library (for
/// instance for Vecs, Arcs, etc...) are allocated with this allocator.
#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
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
#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

/// Function called on `panic!` invocation. Prints the panic information to the
/// kernel debug logger, and exits the process.
#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
#[panic_handler] #[no_mangle]
pub extern fn panic_fmt(p: &core::panic::PanicInfo<'_>) -> ! {
    let _ = syscalls::output_debug_string(&format!("{}", p), 10, "sunrise_libuser::panic_fmt");
    syscalls::exit_process();
}

use core::alloc::Layout;

// TODO: Don't panic in the oom handler, exit instead.
// BODY: Panicking may allocate, so calling panic in the OOM handler is a
// BODY: terrible idea.
/// OOM handler. Causes a panic.
#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_: Layout) -> ! {
    panic!("OOM")
}

/// calls logger initialization, main, and finally exits the
/// process.
#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
#[no_mangle]
pub unsafe extern fn real_start() -> ! {
    extern {
        fn main(argc: isize, argv: *const *const u8) -> i32;
    }

    log_impl::init();
    let (argc, argv) = (argv::argc(), argv::argv());
    let _ret = main(argc, argv);
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
#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
#[lang = "termination"]
trait Termination {
    /// Is called to get the representation of the value as status code.
    /// This status code is returned to the operating system.
    fn report(self) -> i32;
}

#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
impl Termination for () {
    #[inline]
    fn report(self) -> i32 { 0 }
}

#[cfg(any(all(target_os = "sunrise", not(test)), rustdoc))]
#[lang = "start"]
#[allow(clippy::unit_arg)]
fn main<T: Termination>(main: fn(), _argc: isize, _argv: *const *const u8) -> isize {
    main().report() as isize
}
