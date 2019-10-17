//! PS2 Keyboard APIs
//!
//! APIs allowing to read input from a ps2 keyboard.

use alloc::collections::VecDeque;
use crate::types::ReadableEvent;
use crate::keyboard::*;
use crate::error::Error;
use crate::syscalls;
use crate::futures::WorkQueue;

/// Inner state of a managed keyboard.
#[derive(Debug)]
pub struct InnerKeyboard {
    /// The session to kbrd:u
    ipc_session: StaticServiceProxy,

    /// The queue containing the keyboard state received from IPC.
    keys_queue: VecDeque<HidKeyboardState>
}

/// A managed keyboard.
#[derive(Debug)]
pub struct Keyboard {
    /// Inner state
    inner: InnerKeyboard,

    /// An event triggered on keyboard update.
    readable_event: ReadableEvent,
}

impl Keyboard {
    /// Creates a keyboard by connecting to the ipc service.
    pub fn new() -> Result<Self, Error> {
        let ipc_session = StaticServiceProxy::raw_new()?;
        let readable_event = ReadableEvent(ipc_session.get_keyboard_event()?);

        Ok(Keyboard {
            readable_event,
            inner: InnerKeyboard {
                ipc_session,
                keys_queue: VecDeque::new()
            }
        })
    }

    /// Waits for a single key press, and return its unicode representation.
    pub fn read_key(&mut self) -> char {
        if let Some(key) = self.try_read_key() {
            return key;
        }

        loop {
            let handle = self.readable_event.0.as_ref();
            syscalls::wait_synchronization(&[handle], None).expect("wait_synchronization returned an error");

            self.readable_event.clear().expect("Cannot clear readable event");

            let res = self.try_read_key();

            if let Some(res) = res {
                return res;
            }
        }
    }

    /// Asynchronously waits for a single key press, and return its unicode
    /// representation.
    pub fn read_key_async<'a>(&'a mut self, queue: WorkQueue<'_>) -> impl core::future::Future<Output = char> + Unpin + 'a {
        let Keyboard { ref mut inner, ref mut readable_event } = self;
        readable_event.wait_async_cb(queue, move || {
            inner.try_read_key()
        })
    }

    /// If a key press is pending, return its unicode representation. This can be
    /// used to implement poll-based or asynchronous reading from keyboard.
    pub fn try_read_key(&mut self) -> Option<char> {
        self.inner.try_read_key()
    }
}

impl InnerKeyboard {
    /// Update keys from the keyboard service.
    pub fn update_keys(&mut self) {
        loop {
            let mut states = [HidKeyboardState {
                data: 0,
                additional_data: 0,
                state_type: HidKeyboardStateType::Unknown,
                modifiers: 0
            }; 0x80];

            match self.ipc_session.read_keyboard_states(&mut states) {
                Ok(count) => {
                    let states = &states[..count as usize];

                    for state in states {
                        self.keys_queue.push_back(*state);
                    }
                },
                _ => break
            }
        }
    }

    /// Try to read a key from the internal cache queue.
    fn try_read_cached_key(&mut self) -> Option<char> {
        loop {
            match self.keys_queue.pop_front() {
                Some(state) => {
                    if let HidKeyboardStateType::Ascii = state.state_type {
                        let lower_case = char::from(state.data);
                        let upper_case = char::from(state.additional_data);
                        let is_upper = state.modifiers & 1 == 1 || state.modifiers & (1 << 1) == (1 << 1) || state.modifiers & (1 << 2) == (1 << 2);
                        let is_pressed = (state.modifiers & (1 << 7)) == (1 << 7);

                        if is_pressed {
                            if is_upper {
                                return Some(upper_case)
                            } else {
                                return Some(lower_case)
                            }
                        }
                    }
                },
                _ => return None
            }
        }
    }

    /// If a key press is pending, return its unicode representation. This can be
    /// used to implement poll-based or asynchronous reading from keyboard.
    pub fn try_read_key(&mut self) -> Option<char> {
        // Try to read a key from the cache
        match self.try_read_cached_key() {
            // In the case we don't find anything, we force an IPC update and retry to read in the cache.
            None => {
                self.update_keys();
                self.try_read_cached_key()
            }
            res => res
        }
    }
}