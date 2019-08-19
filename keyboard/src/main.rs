//! Keyboard Service
//!
//! This service takes care of anything related to keyboard inputs.

#![feature(untagged_unions, async_await)]
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

#[macro_use]
extern crate sunrise_libuser;

extern crate alloc;

mod ps2;

use alloc::boxed::Box;

use sunrise_libuser::futures::{WaitableManager, WorkQueue};
use sunrise_libuser::ipc::server::port_handler;
use futures::future::FutureObj;
use sunrise_libuser::keyboard::StaticService as _;
use sunrise_libuser::types::*;
use sunrise_libuser::error::{Error, HidError};
use log::info;
use sunrise_libuser::types::{SharedMemory, MappedSharedMemory, ReadableEvent, WritableEvent};
use sunrise_libuser::syscalls::MemoryPermissions;
use sunrise_libuser::mem::{find_free_address, PAGE_SIZE};
use sunrise_libuser::syscalls;
use sunrise_libutils::align_up;
use spin::{Once, Mutex};
use sunrise_libuser::keyboard::HidKeyboardState;

use alloc::collections::VecDeque;

kip_header!(HEADER = sunrise_libuser::caps::KipHeader {
    magic: *b"KIP1",
    name: *b"keyboard\0\0\0\0",
    title_id: 0x0200000000001050,
    process_category: sunrise_libuser::caps::ProcessCategory::KernelBuiltin,
    main_thread_priority: 0,
    default_cpu_core: 0,
    flags: 0,
    reserved: 0,
    stack_page_count: 16,
});

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::SetThreadArea,
        sunrise_libuser::syscalls::nr::ClearEvent,

        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,
        sunrise_libuser::syscalls::nr::CreateSession,

        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::CreateInterruptEvent,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,

        sunrise_libuser::syscalls::nr::CreateSharedMemory,
        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,

        sunrise_libuser::syscalls::nr::CreateEvent,
        sunrise_libuser::syscalls::nr::SignalEvent,

        sunrise_libuser::syscalls::nr::SetHeapSize,

        sunrise_libuser::syscalls::nr::QueryMemory,
    ],
    raw_caps: [
        sunrise_libuser::caps::ioport(0x60),
        sunrise_libuser::caps::ioport(0x64),
        sunrise_libuser::caps::irq_pair(1, 0x3FF)
    ]
});

/// Keyboard handling structure.
struct Keyboard {
    /// The shared memory used by the keyboard to store state changes.
    shared_memory: MappedSharedMemory,

    /// The event used to signal changes in the shared memory.
    writable_event: Option<WritableEvent>,

    /// The event returned to the client when requested via IPC.
    readable_event: ReadableEvent,

    /// The queue containing the keyboard state received by the driver.
    keys_queue: VecDeque<HidKeyboardState>
}

impl Keyboard {
    /// The size of the Keyboard state contained in the shared memory.
    pub const KEYBOARD_STATE_SIZE: usize = 0x20;

    /// Create a new instance of Keyboard.
    pub fn new() -> Result<Self, Error> {
        let size = Self::KEYBOARD_STATE_SIZE;

        let shared_memory = SharedMemory::new(align_up(size, PAGE_SIZE as _) as _, MemoryPermissions::READABLE | MemoryPermissions::WRITABLE, MemoryPermissions::READABLE)?;
        let addr = find_free_address(size as _, PAGE_SIZE)?;
        let shared_memory = shared_memory.map(addr, align_up(size as _, PAGE_SIZE), MemoryPermissions::READABLE | MemoryPermissions::WRITABLE)?;

        let (writable_event, readable_event) = syscalls::create_event()?;

        Ok(Keyboard {
            shared_memory,
            writable_event: Some(writable_event),
            readable_event,
            keys_queue: VecDeque::new()
        })
    }

    /// Get the shared memory of the Keyboard.
    pub fn get_shared_memory(&self) -> HandleRef<'static> {
        self.shared_memory.as_shared_mem().0.as_ref_static()
    }

    /// Get the readable update event of the Keyboard.
    pub fn get_readable_event(&self) -> HandleRef<'static> {
        self.readable_event.0.as_ref_static()
    }

    /// Get the writeable update event of the Keyboard.
    /// 
    /// # Note:
    /// 
    /// This consume the internal writable_event.q
    pub fn take_writable_event(&mut self) -> Option<WritableEvent> {
        self.writable_event.take()
    }

    /// Handle a PS2 IRQ and push a new key state to the internal queue if needed.
    pub fn handle_ps2_irq(&mut self) -> bool {
        let res = ps2::try_read_keyboard_state();

        if let Some(res) = res {
            self.keys_queue.push_back(res);
        }

        res.is_some()
    }

    /// Get the last key states on the internal queue.
    pub fn read_keyboard_states(&mut self, states: &mut [HidKeyboardState]) -> Result<u64, Error> {
        let mut count = 0;

        if self.keys_queue.is_empty() {
            return Err(HidError::NoKeyboardStateUpdate.into())
        }

        for entry in states.iter_mut() {
            if let Some(state) = self.keys_queue.pop_front() {
                *entry = state;
                count += 1;
            } else {
                break;
            }
        }

        Ok(count)
    }
}

/// Global instance of Keyboard.
static KEYBOARD_INSTANCE: Once<Mutex<Keyboard>> = Once::new();

/// Entry point interface.
#[derive(Default, Debug)]
struct StaticService;

impl sunrise_libuser::keyboard::StaticService for StaticService {
    fn get_shared_memory(&mut self, _manager: WorkQueue) -> Result<HandleRef<'static>, Error> {
        Ok(KEYBOARD_INSTANCE.r#try().and_then(|x| Some(x.lock())).expect("Keyboard instance not initialized").get_shared_memory())
    }

    fn get_keyboard_event(&mut self, _manager: WorkQueue) -> Result<HandleRef<'static>, Error> {
        Ok(KEYBOARD_INSTANCE.r#try().and_then(|x| Some(x.lock())).expect("Keyboard instance not initialized").get_readable_event())
    }

    fn read_keyboard_states(&mut self,  _manager: WorkQueue, states: &mut [HidKeyboardState]) -> Result<u64, Error> {
        KEYBOARD_INSTANCE.r#try().and_then(|x| Some(x.lock())).expect("Keyboard instance not initialized").read_keyboard_states(states)
    }
}

/// Task responsible for signaling KEYBOARD_INSTANCE's event at every keyboard update.
// https://github.com/rust-lang/rust-clippy/issues/3988
// Should remove on next toolchain upgrade.
#[allow(clippy::needless_lifetimes)]
async fn update_keyboard(work_queue: WorkQueue<'_>) {
    let writable_event = KEYBOARD_INSTANCE.r#try().and_then(|x| x.lock().take_writable_event()).expect("Keyboard instance not initialized");
    let irq_event = ps2::get_event();

    loop {
        irq_event.wait_async_cb(work_queue.clone(), move || {
                KEYBOARD_INSTANCE.r#try().and_then(|x| Some(x.lock())).expect("Keyboard instance not initialized").handle_ps2_irq()
            }).await;
        let _ = writable_event.signal();
        let _ = sunrise_libuser::syscalls::sleep_thread(0);
    }
}

fn main() {
    info!("Hello World");

    KEYBOARD_INSTANCE.call_once(|| Mutex::new(Keyboard::new().expect("Cannot initialize Keyboard!")));

    let mut man = WaitableManager::new();
    let handler = port_handler(man.work_queue(), "kbrd:u", StaticService::dispatch).unwrap();

    man.work_queue().spawn(FutureObj::new(Box::new(handler)));

    let keyboard_future = update_keyboard(man.work_queue());

    man.work_queue().spawn(FutureObj::new(Box::new(keyboard_future)));
    man.run();
}
