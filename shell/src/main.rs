//! Shell
//!
//! Creates an interactive terminal window, providing a few functions useful to
//! test Sunrise. Type help followed by enter to get a list of allowed commands.

#![feature(asm, naked_functions)]
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
extern crate sunrise_libuser as libuser;



mod ps2;
use crate::libuser::io;
use crate::libuser::sm;
use crate::libuser::window::{Window, Color};
use crate::libuser::terminal::{Terminal, WindowSize};
use crate::libuser::threads::Thread;

use core::fmt::Write;
use alloc::vec::Vec;
use alloc::sync::Arc;
use byteorder::{ByteOrder, LE};
use spin::Mutex;

fn main() {
    let mut terminal = Terminal::new(WindowSize::FontLines(-1, false)).unwrap();
    loop {
        match &*ps2::get_next_line(&mut terminal) {
            "meme1" => show_gif(&LOUIS1[..]),
            "meme2" => show_gif(&LOUIS2[..]),
            "meme3" => show_gif(&LOUIS3[..]),
            "meme4" => show_gif(&LOUIS4[..]),
            "meme5" => show_gif(&LOUIS5[..]),
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
                let _ = writeln!(&mut terminal, "meme1: Display the KFS-1 meme");
                let _ = writeln!(&mut terminal, "meme2: Display the KFS-2 meme");
                let _ = writeln!(&mut terminal, "meme3: Display the KFS-3 meme");
                let _ = writeln!(&mut terminal, "meme4: Display the KFS-4 meme");
                let _ = writeln!(&mut terminal, "meme5: Display the KFS-5 meme");
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
    let mut reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
    let mut window = Window::new(0, 0, u32::from(reader.width()), u32::from(reader.height())).unwrap();
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
        let mut i = 0;
        while i < 10 {
            if let Some(mut lock) = terminal.try_lock() {
                let _ = writeln!(lock, "A");
                i += 1;
            }
            let _ = libuser::syscalls::sleep_thread(0);
        }
    }

    #[doc(hidden)]
    fn thread_b(terminal: usize) {
        // Wrap in a block to forcibly call Arc destructor before exiting the thread.
        {
            let terminal = unsafe {
                Arc::from_raw(terminal as *const Mutex<Terminal>)
            };
            let mut i = 0;
            while i < 10 {
                if let Some(mut lock) = terminal.try_lock() {
                    let _ = writeln!(lock, "B");
                    i += 1;
                }
                let _ = libuser::syscalls::sleep_thread(0);
            }
        }
    }

    let mut terminal = Arc::new(Mutex::new(terminal));

    let t = Thread::create(thread_b, Arc::into_raw(terminal.clone()) as usize)
        .expect("Failed to create thread B");
    t.start()
        .expect("Failed to start thread B");

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
    // dereference the null pointer.
    // doing this in rust is so UB, it's optimized out, so we do it in asm.
    unsafe {
        asm!("
        mov al, [0]
        " ::: "eax" : "volatile", "intel")
    }
}

/// Meme for KFS1
static LOUIS1: &'static [u8; 89915] = include_bytes!("../img/meme1.gif");
/// Meme for KFS2
static LOUIS2: &'static [u8; 93818] = include_bytes!("../img/meme2.gif");
/// Meme for KFS3
static LOUIS3: &'static [u8; 1318100] = include_bytes!("../img/meme3.gif");
/// Meme for KFS4
static LOUIS4: &'static [u8; 103803] = include_bytes!("../img/meme4.gif");
/// Meme for KFS5
static LOUIS5: &'static [u8; 106140] = include_bytes!("../img/meme5.gif");

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
