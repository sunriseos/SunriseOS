//! Shell
//!
//! Creates an interactive terminal window, providing a few functions useful to
//! test KFS. Type help followed by enter to get a list of allowed commands.

#![feature(alloc, asm, naked_functions)]
#![feature(const_let)]
#![no_std]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(intra_doc_link_resolution_failure)]

use gif;
extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate kfs_libuser as libuser;



mod ps2;
use crate::libuser::io;
use crate::libuser::sm;
use crate::libuser::window::{Window, Color};
use crate::libuser::terminal::{Terminal, WindowSize};

use core::fmt::Write;
use alloc::prelude::*;
use alloc::sync::Arc;
use byteorder::{ByteOrder, LE};
use spin::Mutex;

fn main() {
    let mut terminal = Terminal::new(WindowSize::FontLines(-1, false)).unwrap();
    loop {
        match &*ps2::get_next_line(&mut terminal) {
            "gif3" => show_gif(&LOUIS3[..]),
            "gif4" => show_gif(&LOUIS4[..]),
            "test_threads" => terminal = test_threads(terminal),
            "test_divide_by_zero" => test_divide_by_zero(),
            "test_page_fault" => test_page_fault(),
            "connect" => {
                let handle = sm::IUserInterface::raw_new().unwrap().get_service(LE::read_u64(b"vi:\0\0\0\0\0"));
                let _ = writeln!(&mut terminal, "Got handle {:?}", handle);
            },
            "exit" => return,
            //"stackdump" => unsafe { stack::KernelStack::dump_current_stack() },
            "help" => {
                let _ = writeln!(&mut terminal, "COMMANDS:");
                let _ = writeln!(&mut terminal, "exit: Exit this process");
                let _ = writeln!(&mut terminal, "gif3: Print the KFS-3 meme");
                let _ = writeln!(&mut terminal, "gif4: Print the KFS-4 meme");
                let _ = writeln!(&mut terminal, "test_threads: Run threads that concurrently print As and Bs");
                let _ = writeln!(&mut terminal, "test_divide_by_zero: Check exception handling by throwing a divide by zero");
                let _ = writeln!(&mut terminal, "test_page_fault: Check exception handling by throwing a page_fault");
            }
            _ => { let _ = writeln!(&mut terminal, "Unknown command"); }
        }
    }
}

/// Shows a GIF in a new window, blocking the caller. When a key is pressed, the
/// window is closed and control is given back to the caller.
fn show_gif(louis: &[u8]) {
    let mut window = Window::new(0, 0, 1280, 800).unwrap();
    let mut reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
    let mut buf = Vec::new();

    loop {
        {
            let end = reader.next_frame_info().unwrap().is_none();
            if end {
                reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
                let _ = reader.next_frame_info().unwrap().unwrap();
            }
        }
        buf.resize(reader.buffer_size(), 0);
        // simulate read into buffer
        reader.read_into_buffer(&mut buf[..]).unwrap();
        for y in 0..(reader.height() as usize) {
            for x in 0..(reader.width() as usize) {
                let frame_coord = (y * reader.width() as usize + x) * 4;
                window.write_px_at(x, y, Color::rgb(buf[frame_coord], buf[frame_coord + 1], buf[frame_coord + 2]));
            }
        }
        window.draw().unwrap();
        if ps2::try_read_key().is_some() {
            return
        }
    }
}

/// Test function ensuring threads are working properly.
fn test_threads(terminal: Terminal) -> Terminal {
    #[doc(hidden)]
    fn thread_a(terminal: usize) {
        let terminal = unsafe {
            Arc::from_raw(terminal as *const Mutex<Terminal>)
        };
        for _ in 0..10 {
            if let Some(mut lock) = terminal.try_lock() {
                let _ = writeln!(lock, "A");
            }
            let _ = libuser::syscalls::sleep_thread(0);
        }
    }

    #[doc(hidden)]
    fn thread_b(terminal: usize) -> ! {
        // Wrap in a block to forcibly call Arc destructor before exiting the thread.
        {
            let terminal = unsafe {
                Arc::from_raw(terminal as *const Mutex<Terminal>)
            };
            for _ in 0..10 {
                if let Some(mut lock) = terminal.try_lock() {
                    let _ = writeln!(lock, "B");
                }
                let _ = libuser::syscalls::sleep_thread(0);
            }
        }
        libuser::syscalls::exit_thread()
    }

    /// Small wrapper around thread_b fixing the thread calling convention.
    #[naked]
    extern fn function_wrapper() {
        unsafe {
            asm!("
            push eax
            call $0
            " :: "i"(thread_b as *const u8) :: "intel");
        }
    }

    /// Size of the test_threads stack.
    const THREAD_STACK_SIZE: usize = 0x2000;

    let mut terminal = Arc::new(Mutex::new(terminal));
    let stack = Box::new([0u8; THREAD_STACK_SIZE]);
    let sp = (Box::into_raw(stack) as *const u8).wrapping_add(THREAD_STACK_SIZE);
    let ip : extern fn() -> ! = unsafe {
        // Safety: This is changing the return type from () to !. It's safe. It
        // sucks though. This is, yet again, an instance of "naked functions are
        // fucking horrible".
        // Also, fun fact about the Rust Type System. Every function has its own
        // type, that's zero-sized. Those usually get casted automatically into
        // fn() pointers, but of course transmute is special. So we need to help
        // it a bit.
        let fn_wrapper: extern fn() = function_wrapper;
        core::mem::transmute(fn_wrapper)
    };
    let thread_handle = libuser::syscalls::create_thread(ip, Arc::into_raw(terminal.clone()) as usize, sp, 0, 0)
        .expect("svcCreateThread returned an error");
    thread_handle.start()
        .expect("svcStartThread returned an error");

    // thread is running b, run a meanwhile
    thread_a(Arc::into_raw(terminal.clone()) as usize);

    // Wait for thread_b to terminate.
    loop {
        match Arc::try_unwrap(terminal) {
            Ok(terminal) => break terminal.into_inner(),
            Err(x) => terminal = x
        }
        let _ = libuser::syscalls::sleep_thread(0);
    }
}

/// Test function ensuring divide by zero interruption kills only the current
/// process.
fn test_divide_by_zero() {
    // don't panic, we want to actually divide by zero
    unsafe {
        asm!("
        mov eax, 42
        mov ecx, 0
        div ecx" :::: "volatile", "intel")
    }
}

/// Test function ensuring pagefaults kills only the current process.
fn test_page_fault() {
    let ptr: *const u8 = core::ptr::null();
    let _res = unsafe { *ptr };
}

/// Meme for KFS3
static LOUIS3: &'static [u8; 1318100] = include_bytes!("../img/meme3.gif");
/// Meme for KFS4
static LOUIS4: &'static [u8; 103803] = include_bytes!("../img/meme4.gif");
// TODO: Meme for KFS5.
// BODY: We cannot give KFS5 until we have a meme. It is of utmost importance
// BODY: that a meme is found and placed here.

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        libuser::syscalls::nr::SleepThread,
        libuser::syscalls::nr::ExitProcess,
        libuser::syscalls::nr::CloseHandle,
        libuser::syscalls::nr::WaitSynchronization,
        libuser::syscalls::nr::OutputDebugString,

        libuser::syscalls::nr::SetHeapSize,
        libuser::syscalls::nr::QueryMemory,
        libuser::syscalls::nr::CreateThread,
        libuser::syscalls::nr::StartThread,
        libuser::syscalls::nr::ExitThread,
        libuser::syscalls::nr::MapSharedMemory,
        libuser::syscalls::nr::UnmapSharedMemory,
        libuser::syscalls::nr::ConnectToNamedPort,
        libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        libuser::syscalls::nr::CreateSharedMemory,
        libuser::syscalls::nr::CreateInterruptEvent,
    ],
    raw_caps: [libuser::caps::ioport(0x60), libuser::caps::ioport(0x64), libuser::caps::irq_pair(1, 0x3FF)]
});
