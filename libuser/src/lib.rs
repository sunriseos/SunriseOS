//! Userspace library
//!
//! Provides an allocator, various lang items.

#![no_std]
#![feature(start, lang_items, core_intrinsics, box_syntax, naked_functions, proc_macro_hygiene, unboxed_closures, fn_traits, thread_local)]

#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

#![allow(non_upper_case_globals)] // I blame roblabla.

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(rustdoc::broken_intra_doc_links)]

#[macro_use]
extern crate alloc;


#[macro_use]
extern crate bitfield;


#[macro_use]
extern crate sunrise_libutils;

// Marked public for use in the object macro.
#[macro_use]
#[doc(hidden)]
pub extern crate log as __log;

pub mod argv;
pub mod caps;
pub mod syscalls;
pub mod mem;
pub mod types;
pub mod ipc;
pub mod threads;
pub mod thread_local_storage;
pub mod futures;

//#[gen_ipc(path = "../../ipcdefs/sm.id", prefix = "sunrise_libuser")]
//pub mod sm {}
//#[gen_ipc(path = "../../ipcdefs/vi.id", prefix = "sunrise_libuser")]
//pub mod vi {}
//#[gen_ipc(path = "../../ipcdefs/ahci.id", prefix = "sunrise_libuser")]
//pub mod ahci {}
//#[gen_ipc(path = "../../ipcdefs/time.id", prefix = "sunrise_libuser")]
//pub mod time {}
//#[gen_ipc(path = "../../ipcdefs/filesystem.id", prefix = "sunrise_libuser")]
//pub mod fs {}
//#[gen_ipc(path = "../../ipcdefs/keyboard.id", prefix = "sunrise_libuser")]
//pub mod keyboard {}
//#[gen_ipc(path = "../../ipcdefs/loader.id", prefix = "sunrise_libuser")]
//pub mod ldr {}
//#[gen_ipc(path = "../../ipcdefs/twili.id", prefix = "sunrise_libuser")]
//pub mod twili {}
//#[gen_ipc(path = "../../ipcdefs/example.id", prefix = "sunrise_libuser")]
//pub mod example {}
include!(concat!(env!("OUT_DIR"), "/ipc_code.rs"));

pub mod error;
pub mod allocator;
pub mod terminal;
pub mod ps2;
pub mod window;
pub mod zero_box;

#[cfg(all(target_os = "sunrise", not(feature = "build-for-std-app")))]
mod crt0;
mod log_impl;
pub use sunrise_libutils::loop_future;

pub use sunrise_libutils::io;

use sunrise_libutils as utils;

pub use ::futures as futures_rs;

/// Global allocator. Every implicit allocation in the rust liballoc library (for
/// instance for Vecs, Arcs, etc...) are allocated with this allocator.
#[cfg(all(target_os = "sunrise", not(test), not(doc)))]
#[cfg_attr(feature = "lang-items", global_allocator)]
pub static ALLOCATOR: allocator::Allocator = allocator::Allocator::new();

// Runtime functions
//
// Functions beyond this lines are required by the rust compiler when building
// for no_std. Care should be exercised when changing them, as lang items are
// extremely picky about how their types or implementation.

/// The exception handling personality function for use in the bootstrap.
///
/// We currently have no userspace exception handling, so make it do nothing.
#[cfg(all(target_os = "sunrise", not(test), feature = "lang-items", not(doc)))]
#[lang = "eh_personality"] #[no_mangle] pub extern fn eh_personality() {}

/// Function called on `panic!` invocation. Prints the panic information to the
/// kernel debug logger, and exits the process.
#[cfg(all(target_os = "sunrise", not(test), feature = "lang-items", not(doc)))]
#[panic_handler] #[no_mangle]
pub extern fn panic_fmt(p: &core::panic::PanicInfo<'_>) -> ! {
    let _ = syscalls::output_debug_string(&format!("{}", p), 10, "sunrise_libuser::panic_fmt");
    syscalls::exit_process();
}

// TODO: Don't panic in the oom handler, exit instead.
// BODY: Panicking may allocate, so calling panic in the OOM handler is a
// BODY: terrible idea.
/// OOM handler. Causes a panic.
#[cfg(all(target_os = "sunrise", not(test), feature = "lang-items", not(doc)))]
#[lang = "oom"]
#[no_mangle]
pub fn rust_oom(_: core::alloc::Layout) -> ! {
    panic!("OOM")
}

/// calls logger initialization, main, and finally exits the
/// process.
///
/// # Safety
///
///
#[cfg(any(all(target_os = "sunrise", not(test), not(feature = "build-for-std-app")), doc))]
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
#[cfg(all(target_os = "sunrise", not(test), feature = "lang-items", not(doc)))]
#[lang = "termination"]
trait Termination {
    /// Is called to get the representation of the value as status code.
    /// This status code is returned to the operating system.
    fn report(self) -> i32;
}

#[cfg(all(target_os = "sunrise", not(test), feature = "lang-items", not(doc)))]
impl Termination for () {
    #[inline]
    fn report(self) -> i32 { 0 }
}

#[cfg(all(target_os = "sunrise", not(test), feature = "lang-items", not(doc)))]
#[lang = "start"]
#[allow(clippy::unit_arg)]
fn main<T: Termination>(main: fn(), _argc: isize, _argv: *const *const u8) -> isize {
    main().report() as isize
}
