//! PS/2 Keyboard Driver
//!
//! Allows interacting with an IBM/PC PS/2 Driver. Requires next to no
//! configuration: the user can just call the functions in this module right
//! away.
//!
//! # Required Capabilities
//!
//! - SVC create_interrupt_event
//! - SVC wait_synchronization
//! - IOPort 60
//! - IOPort 64
//! - IRQ 1

#![allow(clippy::match_bool)] // more readable

use sunrise_libuser::io::{Io, Pio};
use core::sync::atomic::{AtomicBool, Ordering::SeqCst};
use sunrise_libuser::syscalls;
use sunrise_libuser::types::ReadableEvent;

use sunrise_libuser::keyboard::HidKeyboardState;
use sunrise_libuser::keyboard::HidKeyboardStateType;
use sunrise_libuser::keyboard::HidKeyboardScancode;
use lazy_static::lazy_static;
use log::debug;

/// PS2 keyboard state.
struct PS2 {
    /// Status Register address
    status_port: Pio<u8>,
    /// Data Register address
    data_port: Pio<u8>,
    /// IRQEvent for the PS/2 keyboard. Triggered each time the user presses a
    /// key.
    event: ReadableEvent,
    /// Flips when the user has toggled the caps lock key. When set to true, all
    /// letters are returned in uppercase.
    is_capslocked:  AtomicBool,
    /// Set to true if the user is currently holding the left shift key. When set to
    /// true, all letters are returned in uppercase.
    is_left_shift:  AtomicBool,
    /// Set to true if the user is currently holding the right shift key. When set to
    /// true, all letters are returned in uppercase.
    is_right_shift: AtomicBool,
    /// Set to true if the user is currently holding the left ctrl key.
    is_left_ctrl:  AtomicBool,
    /// Set to true if the user is currently holding the right ctrl key.
    is_right_ctrl:  AtomicBool,
    /// Set to true if the user is currently holding the left alt key.
    is_left_alt:    AtomicBool,
    /// Set to true if the user is currently holding the right alt key.
    is_right_alt:    AtomicBool
}

/// A non-control key
/// (lowercase_ascii, uppercase_ascii)
#[derive(Copy, Clone, Debug)]
#[allow(clippy::missing_docs_in_private_items)]
struct LetterKey {
    lower_case: u8,
    upper_case: u8
}

/// A control key (ctrl, shift, alt, arrows, end, ...)
#[derive(Copy, Clone, Debug)]
struct ControlKey(&'static str);

/// A key is either a letter key, a control key, or not attributed
#[derive(Copy, Clone, Debug)]
#[allow(clippy::missing_docs_in_private_items)]
enum Key {
    Letter(LetterKey),
    Control(ControlKey),
    Scancode(HidKeyboardScancode),
    Empty // not a scancode
}

impl Key {
    /// Create a control key with the given human-readable name.
    const fn ctrl(s: &'static str) -> Key {
        Control(ControlKey(s))
    }

    /// Create a letter key with the given lowercase and uppercase
    /// representations.
    const fn letter(l: u8, u: u8) -> Key {
        Letter(LetterKey {lower_case: l, upper_case: u})
    }

    /// Create a scancode key with the given scancode.
    const fn scancode(scancode: HidKeyboardScancode) -> Key {
        Scancode(scancode)
    }
}

use self::Key::*;

/// State of a key on the keyboard.
#[allow(clippy::missing_docs_in_private_items)]
#[derive(Copy, Clone, PartialEq)]
enum State {
    Pressed,
    Released
}

use self::State::*;

/// A KeyEvent is the combination of a key and its state
#[allow(clippy::missing_docs_in_private_items)]
struct KeyEvent {
    key: Key,
    state: State,
}

impl KeyEvent {

    /// Reads one or more bytes from the port until it matches a known scancode sequence
    #[allow(clippy::cognitive_complexity)] // sorry clippy, but you don't how terrible ps2 scancodes are.
    fn read_key_event(port: Pio<u8>) -> KeyEvent {
        let scancode = port.read();
        let mut state = Pressed;

        let key = match scancode {

            // multibyte scancodes
            0xe0 => {
                match port.read() {
                    // The print screen pressed sequence, 0xe0 0x2a 0xe0 0x37
                    0x2A => { match port.read() {
                           0xe0 => { match port.read() {
                                   0x37 => { state = Pressed; Key::scancode(HidKeyboardScancode::SysRQ) },
                                   unknown => { debug!("Unknown sequence 0xe0, 0x2a, 0xe0, {:#04x}", unknown); Key::Empty }
                           }},
                           unknown => { debug!("Unknown sequence 0xe0, 0x2a, {:#04x}", unknown); Key::Empty }
                    }},

                    // The print screen released sequence, 0xe0 0xb7 0xe0 0xaa
                    // 0xb7 & 0x7F = 0x37
                    0x37 => { match port.read() {
                            0xe0 => { match port.read() {
                                   0xaa => { state = Released; Key::scancode(HidKeyboardScancode::SysRQ) },
                                   unknown => { debug!("Unknown sequence 0xe0, 0x37, 0xe0, {:#04x}", unknown); Key::Empty }
                           }},
                           unknown => { debug!("Unknown sequence 0xe0, 0x37, {:#04x}", unknown); Key::Empty }
                    }},

                    // regular multibytes scancodes
                    second_byte => {
                        // first bit is state
                        state = match second_byte & 0x80 == 0 {
                            true  => State::Pressed,
                            false => State::Released
                        };
                        // strip the first bit
                        match second_byte & 0x7F {
                            0x10 => Key::scancode(HidKeyboardScancode::MediaPreviousSong),
                            0x19 => Key::scancode(HidKeyboardScancode::MediaNextSong),
                            0x1C => Key::letter(b'\n', b'\n'), // keypad enter
                            0x1D => Key::scancode(HidKeyboardScancode::RightCtrl),
                            0x20 => Key::scancode(HidKeyboardScancode::MediaMute),
                            0x21 => Key::scancode(HidKeyboardScancode::MediaCalc),
                            0x22 => Key::scancode(HidKeyboardScancode::MediaPlayPause),
                            0x24 => Key::scancode(HidKeyboardScancode::MediaStop),
                            0x2E => Key::scancode(HidKeyboardScancode::MediaVolumeDown),
                            0x30 => Key::scancode(HidKeyboardScancode::MediaVolumeUp),
                            0x32 => Key::scancode(HidKeyboardScancode::MediaWWW),
                            0x35 => Key::letter(b'/', b'/'), // keypad /
                            0x38 => Key::scancode(HidKeyboardScancode::RightAlt),
                            0x47 => Key::scancode(HidKeyboardScancode::Home),
                            0x48 => Key::scancode(HidKeyboardScancode::Up),
                            0x49 => Key::scancode(HidKeyboardScancode::PageUp),
                            0x4B => Key::scancode(HidKeyboardScancode::Left),
                            0x4D => Key::scancode(HidKeyboardScancode::Right),
                            0x4F => Key::scancode(HidKeyboardScancode::End),
                            0x50 => Key::scancode(HidKeyboardScancode::Down),
                            0x51 => Key::scancode(HidKeyboardScancode::PageDown),
                            0x52 => Key::scancode(HidKeyboardScancode::Insert),
                            0x53 => Key::scancode(HidKeyboardScancode::Delete),
                            0x5B => Key::scancode(HidKeyboardScancode::LeftMeta),
                            0x5C => Key::scancode(HidKeyboardScancode::RightMeta),
                            0x5D => Key::ctrl("Apps"), // WTF is this !?
                            0x5E => Key::scancode(HidKeyboardScancode::Power),
                            0x5F => Key::scancode(HidKeyboardScancode::MediaSleep),
                            0x63 => Key::ctrl("Wake"),
                            0x65 => Key::scancode(HidKeyboardScancode::MediaFind),
                            0x66 => Key::ctrl("WWW Favorites"),
                            0x67 => Key::scancode(HidKeyboardScancode::MediaRefresh),
                            0x68 => Key::scancode(HidKeyboardScancode::MediaStop),
                            0x69 => Key::scancode(HidKeyboardScancode::MediaForward),
                            0x6A => Key::scancode(HidKeyboardScancode::MediaBack),
                            0x6B => Key::ctrl("Computer"), // WTF is this !?
                            0x6C => Key::ctrl("Email"),
                            0x6D => Key::ctrl("Media"),

                            unknown => { debug!("Unknown sequence 0xe0, {:#04x}", unknown); Key::Empty }
                        }
                    } // end match _
                } // end match second_byte
            } // end match 0xe0


            // The pause sequence, 0xe1 0x1d 0x45 0xe1 0x9d 0xc5 (fuck)
            0xe1 => { match port.read() {
                0x1d => { match port.read() {
                    0x45 => { match port.read() {
                        0xe1 => { match port.read() {
                            0x9d => { match port.read() {
                                0xc5 => { state = Pressed; Key::ctrl("Pause") },
                                unknown => { debug!("Unknown sequence 0xe1, 0x1d, 0x45, 0xe1, 0x9d {:#04x}", unknown); Key::Empty }
                            }},
                            unknown => { debug!("Unknown sequence 0xe1, 0x1d, 0x45, 0xe1 {:#04x}", unknown); Key::Empty }
                        }},
                        unknown => { debug!("Unknown sequence 0xe1, 0x1d, 0x45, {:#04x}", unknown); Key::Empty }
                    }},
                    unknown => { debug!("Unknown sequence 0xe1, 0x1d, {:#04x}", unknown); Key::Empty }
                }},
                unknown => { debug!("Unknown sequence 0xe1, {:#04x}", unknown); Key::Empty }
            }}, // end match 0xe1


            // regular, single byte, scancodes
            scancode => {

                // first bit is state
                state = match scancode & 0x80 == 0 {
                    true  => State::Pressed,
                    false => State::Released
                };
                // Strip the first bit
                match scancode & 0x7F {

                    0x01 => Key::scancode(HidKeyboardScancode::Esc),

                    0x02 => Key::letter(b'1', b'!'), 0x03 => Key::letter(b'2', b'@'),
                    0x04 => Key::letter(b'3', b'#'), 0x05 => Key::letter(b'4', b'$'),
                    0x06 => Key::letter(b'5', b'%'), 0x07 => Key::letter(b'6', b'^'),
                    0x08 => Key::letter(b'7', b'&'), 0x09 => Key::letter(b'8', b'*'),
                    0x0a => Key::letter(b'9', b'('), 0x0b => Key::letter(b'0', b')'),
                    0x0c => Key::letter(b'-', b'_'), 0x0d => Key::letter(b'=', b'+'),

                    0x0e => Key::letter(b'\x08', b'\x08'), 0x0f => Key::letter(b'\t', b'\t'),

                    0x10 => Key::letter(b'q', b'Q'), 0x11 => Key::letter(b'w', b'W'),
                    0x12 => Key::letter(b'e', b'E'), 0x13 => Key::letter(b'r', b'R'),
                    0x14 => Key::letter(b't', b'T'), 0x15 => Key::letter(b'y', b'Y'),
                    0x16 => Key::letter(b'u', b'U'), 0x17 => Key::letter(b'i', b'I'),
                    0x18 => Key::letter(b'o', b'O'), 0x19 => Key::letter(b'p', b'P'),
                    0x1a => Key::letter(b'[', b'{'), 0x1b => Key::letter(b']', b'}'),

                    0x1c => Key::letter(b'\n', b'\n'), 0x1d => Key::scancode(HidKeyboardScancode::LeftCtrl),

                    0x1e => Key::letter(b'a', b'A'), 0x1f => Key::letter(b's', b'S'),
                    0x20 => Key::letter(b'd', b'D'), 0x21 => Key::letter(b'f', b'F'),
                    0x22 => Key::letter(b'g', b'G'), 0x23 => Key::letter(b'h', b'H'),
                    0x24 => Key::letter(b'j', b'J'), 0x25 => Key::letter(b'k', b'K'),
                    0x26 => Key::letter(b'l', b'L'), 0x27 => Key::letter(b';', b':'),
                    0x28 => Key::letter(b'\'', b'"'), 0x29 => Key::letter(b'`', b'~'),

                    0x2a => Key::scancode(HidKeyboardScancode::LeftShift), 0x2b => Key::letter(b'\\', b'|'),

                    0x2c => Key::letter(b'z', b'Z'), 0x2d => Key::letter(b'x', b'X'),
                    0x2e => Key::letter(b'c', b'C'), 0x2f => Key::letter(b'v', b'V'),
                    0x30 => Key::letter(b'b', b'B'), 0x31 => Key::letter(b'n', b'N'),
                    0x32 => Key::letter(b'm', b'M'), 0x33 => Key::letter(b',', b'<'),
                    0x34 => Key::letter(b'.', b'>'), 0x35 => Key::letter(b'/', b'?'),

                    0x36 => Key::scancode(HidKeyboardScancode::RightShift), 0x37 => Key::letter(b'*', b'*'),
                    0x38 => Key::scancode(HidKeyboardScancode::LeftAlt), 0x39 => Key::letter(b' ', b' '),
                    0x3a => Key::scancode(HidKeyboardScancode::CapsLock),

                    0x3b => Key::scancode(HidKeyboardScancode::F1), 0x3c => Key::scancode(HidKeyboardScancode::F2),
                    0x3d => Key::scancode(HidKeyboardScancode::F3), 0x3e => Key::scancode(HidKeyboardScancode::F4),
                    0x3f => Key::scancode(HidKeyboardScancode::F5), 0x40 => Key::scancode(HidKeyboardScancode::F6),
                    0x41 => Key::scancode(HidKeyboardScancode::F7), 0x42 => Key::scancode(HidKeyboardScancode::F8),
                    0x43 => Key::scancode(HidKeyboardScancode::F8), 0x44 => Key::scancode(HidKeyboardScancode::F10),

                    0x45 => Key::scancode(HidKeyboardScancode::NumLock), 0x46 => Key::scancode(HidKeyboardScancode::ScrollLock),

                    0x47 => Key::letter(b'7', b'7'), 0x48 => Key::letter(b'8', b'8'),
                    0x49 => Key::letter(b'9', b'9'), 0x4a => Key::letter(b'-', b'-'),
                    0x4b => Key::letter(b'4', b'4'), 0x4c => Key::letter(b'5', b'5'),
                    0x4d => Key::letter(b'6', b'6'), 0x4e => Key::letter(b'+', b'+'),
                    0x4f => Key::letter(b'1', b'1'), 0x50 => Key::letter(b'2', b'2'),
                    0x51 => Key::letter(b'3', b'3'), 0x52 => Key::letter(b'0', b'0'),
                    0x53 => Key::letter(b'.', b'.'),

                    0x57 => Key::scancode(HidKeyboardScancode::F11), 0x58 => Key::scancode(HidKeyboardScancode::F12),

                    0x5c => Key::ctrl("Command Right"),

                    unknown => { debug!("Unknown scancode {:#04x}", unknown); Key::Empty }
                }
            } // end single-byte scancodes
        };

        KeyEvent { key, state }
    }
}

impl PS2 {
    /// Handle a control key scancode
    fn handle_control_key(&self, key: HidKeyboardScancode, state: State) {
        match key {
            HidKeyboardScancode::CapsLock => {
                match state {
                    State::Pressed => {
                        // flip capslock state
                        loop {
                            let current = self.is_capslocked.load(SeqCst);
                            let was = self.is_capslocked.compare_and_swap(current, !current, SeqCst);
                            if was == current {
                                break;
                            }
                        }
                        // flip the LED
                        // todo flip the LED
                    }
                    State::Released => { /* nothing to do on release */ }
                }
            }
            HidKeyboardScancode::LeftShift => {
                match state {
                    Pressed  => { self.is_left_shift.store(true,  SeqCst); }
                    Released => { self.is_left_shift.store(false, SeqCst); }
                }
            }
            HidKeyboardScancode::RightShift => {
                match state {
                    Pressed  => { self.is_right_shift.store(true,  SeqCst); }
                    Released => { self.is_right_shift.store(false, SeqCst); }
                }
            }
            _ => { debug!("Keyboard: {} {:?}", match state { Pressed => "pressed ", Released => "released" }, key); }
        }
    }

    /// Gets the letter from the key, accounting for shift and capslock
    fn key_to_letter(&self, key: LetterKey) -> char {
        match self.is_left_shift.load(SeqCst) || self.is_right_shift.load(SeqCst) || self.is_capslocked.load(SeqCst) {
            false => char::from(key.lower_case),
            true  => char::from(key.upper_case)
        }
    }
    
    /// Get a bitfield representing the modifiers of this keyboard
    fn encode_modifiers(&self, state: State) -> u8 {
        let caps_locked = self.is_capslocked.load(SeqCst) as u8;
        let is_left_shift = self.is_left_shift.load(SeqCst) as u8;
        let is_right_shift = self.is_right_shift.load(SeqCst) as u8;
        let is_left_ctrl = self.is_left_ctrl.load(SeqCst) as u8;
        let is_right_ctrl = self.is_right_ctrl.load(SeqCst) as u8;
        let is_left_alt = self.is_left_alt.load(SeqCst) as u8;
        let is_right_alt = self.is_right_alt.load(SeqCst) as u8;
        let is_pressed = (state == State::Pressed) as u8;

        caps_locked | (is_left_shift << 1)
                    | (is_right_shift << 2)
                    | (is_left_ctrl << 3)
                    | (is_right_ctrl << 4)
                    | (is_left_alt << 5)
                    | (is_right_alt << 6)
                    | (is_pressed << 7)
    }

    /// Return true if the PS2 keyboard has an key event to read.
    fn has_read_key_event(&self) -> bool {
            let status = self.status_port.read();
            status & 0x01 != 0
    }

    /// Return a representation of a single key press if any updates is availaible.
    ///
    /// Key presses are bufferized: if nobody is calling read_key when the user
    /// presses a key, it will be kept in a buffer until read_key is called.
    fn try_read_keyboard_state(&self) -> Option<HidKeyboardState> {
        if self.has_read_key_event() {
            let key = KeyEvent::read_key_event(self.data_port);
            match key {
                KeyEvent {key: Key::Scancode(k), state: s} => {
                    self.handle_control_key(k, s);

                    Some(HidKeyboardState {
                        data: k.0,
                        additional_data: 0,
                        state_type: HidKeyboardStateType::Scancode,
                        modifiers: self.encode_modifiers(s)
                    })
                },
                KeyEvent {key: Key::Letter(l), state: s} => {
                    Some(HidKeyboardState {
                        data: l.lower_case,
                        additional_data: l.upper_case,
                        state_type: HidKeyboardStateType::Ascii,
                        modifiers: self.encode_modifiers(s)
                    })
                },
                KeyEvent {key: Key::Control(_), state: s} => {
                    Some(HidKeyboardState {
                        data: 0,
                        additional_data: 0,
                        state_type: HidKeyboardStateType::Control,
                        modifiers: self.encode_modifiers(s)
                    })
                },
                KeyEvent {key: Key::Empty, state: s} => {
                    Some(HidKeyboardState {
                        data: 0,
                        additional_data: 0,
                        state_type: HidKeyboardStateType::Unknown,
                        modifiers: self.encode_modifiers(s)
                    })
                },
            }
        } else {
            None
        }
    }

    /// Waits for a single key press, and return its unicode representation.
    ///
    /// Key presses are bufferized: if nobody is calling read_key when the user
    /// presses a key, it will be kept in a buffer until read_key is called.
    fn read_key(&self) -> char {
        loop {
            let status = self.status_port.read();
            if status & 0x01 != 0 {
                let key = KeyEvent::read_key_event(self.data_port);
                match key {
                    KeyEvent {key: Key::Letter(l),  state: State::Pressed  } => { return self.key_to_letter(l) },
                    KeyEvent {key: Key::Letter(_),  state: State::Released } => { /* ignore released letters */ },
                    KeyEvent {key: Key::Control(_), ..                     } => { /* ignore legacy keys */ },
                    KeyEvent {key: Key::Empty,      ..                     } => { /* ignore unknown keys */ },
                    KeyEvent {key: Key::Scancode(k), state: s              } => { self.handle_control_key(k, s); },
                }
            } else {
                let _ = syscalls::wait_synchronization(&[self.event.0.as_ref()], None);
            }
        }
    }

    /// If a key press is pending, return its unicode representation. This can be
    /// used to implement poll-based or asynchronous reading from keyboard.
    fn try_read_key(&self) -> Option<char> {
        loop {
            let status = self.status_port.read();
            if status & 0x01 != 0 {
                let key = KeyEvent::read_key_event(self.data_port);
                match key {
                    KeyEvent {key: Key::Scancode(k), state: s              } => self.handle_control_key(k, s),
                    KeyEvent {key: Key::Letter(l),  state: State::Pressed  } => return Some(self.key_to_letter(l)),
                    _ => ()
                }
            } else {
                return None;
            }
        }
    }

    /// Get a ReadableEvent for the PS2 IRQ. Waiting on this event will wait until
    /// a keypress is detected. Note that once this event is triggered, it won't
    /// trigger again until [read_key] or [try_read_key] is called.
    fn event_irq(&self) -> &ReadableEvent {
        &self.event
    }
}

lazy_static! {
    /// Primary PS2 controller instance on a classical IBM/PC architecture.
    static ref PRIMARY_PS2 : PS2 = PS2 {
        status_port: Pio::<u8>::new(0x64),
        data_port: Pio::<u8>::new(0x60),
        event: syscalls::create_interrupt_event(1, 0).unwrap(),
        is_capslocked: AtomicBool::new(false),
        is_left_shift: AtomicBool::new(false),
        is_right_shift: AtomicBool::new(false),
        is_left_ctrl: AtomicBool::new(false),
        is_right_ctrl: AtomicBool::new(false),
        is_left_alt: AtomicBool::new(false),
        is_right_alt: AtomicBool::new(false),
    };
}

/// Waits for a single key press, and return its unicode representation.
///
/// Key presses are bufferized: if nobody is calling read_key when the user
/// presses a key, it will be kept in a buffer until read_key is called.
pub fn read_key() -> char {
    PRIMARY_PS2.read_key()
}

/// If a key press is pending, return its unicode representation. This can be
/// used to implement poll-based or asynchronous reading from keyboard.
pub fn try_read_key() -> Option<char> {
    PRIMARY_PS2.try_read_key()
}

/// Get a ReadableEvent for the PS2 IRQ. Waiting on this event will wait until
/// a keypress is detected. Note that once this event is triggered, it won't
/// trigger again until [read_key] or [try_read_key] is called.
pub fn get_event() -> &'static ReadableEvent {
    PRIMARY_PS2.event_irq()
}

/// Return true if the PS2 keyboard has an key event to read.
pub fn has_read_key_event() -> bool {
    PRIMARY_PS2.has_read_key_event()
}

/// Return a representation of a single key press if any updates is availaible.
pub fn try_read_keyboard_state() -> Option<HidKeyboardState> {
    PRIMARY_PS2.try_read_keyboard_state()
}