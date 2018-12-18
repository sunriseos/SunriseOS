use io::{Io, Pio};
use core::sync::atomic::{AtomicBool, Ordering::SeqCst};
use alloc::string::String;
use libuser::syscalls;
use libuser::types::ReadableEvent;
use libuser::terminal::Terminal;
use core::fmt::Write;

struct PS2 {
    status_port: Pio<u8>,
    data_port: Pio<u8>,
    event: ReadableEvent,
    is_capslocked:  AtomicBool,
    is_shift:       AtomicBool
}

/// A non-control key
/// (lowercase_ascii, uppercase_ascii)
#[derive(Copy, Clone, Debug)]
struct LetterKey {
    lower_case: char,
    upper_case: char
}

/// A control key (ctrl, shift, alt, arrows, end, ...)
#[derive(Copy, Clone, Debug)]
struct ControlKey(&'static str);

/// A key is either a letter key, a control key, or not attributed
#[derive(Copy, Clone, Debug)]
enum Key {
    Letter(LetterKey),
    Control(ControlKey),
    Empty // not a scancode
}

impl Key {
    const fn ctrl(s: &'static str) -> Key {
        Control(ControlKey(s))
    }

    const fn letter(l: char, u: char) -> Key {
        Letter(LetterKey {lower_case: l, upper_case: u})
    }
}

use self::Key::*;

enum State {
    Pressed,
    Released
}

use self::State::*;

/// A KeyEvent is the combination of a key and its state
struct KeyEvent {
    key: Key,
    state: State,
}

impl KeyEvent {

    /// Reads one or more bytes from the port until it matches a known scancode sequence
    fn read_key_event(port: &Pio<u8>) -> KeyEvent {
        let scancode = port.read();
        let mut state = Pressed;

        let key = match scancode {

            // multibyte scancodes
            0xe0 => {
                match port.read() {
                    // The print screen pressed sequence, 0xe0 0x2a 0xe0 0x37
                    0x2A => { match port.read() {
                           0xe0 => { match port.read() {
                                   0x37 => { state = Pressed; Key::ctrl("Print Screen") },
                                   unknown => { debug!("Unknown sequence 0xe0, 0x2a, 0xe0, {:#04x}", unknown); Key::Empty }
                           }},
                           unknown => { debug!("Unknown sequence 0xe0, 0x2a, {:#04x}", unknown); Key::Empty }
                    }},

                    // The print screen released sequence, 0xe0 0xb7 0xe0 0xaa
                    // 0xb7 & 0x7F = 0x37
                    0x37 => { match port.read() {
                            0xe0 => { match port.read() {
                                   0xaa => { state = Released; Key::ctrl("Print Screen") },
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
                            0x10 => Key::ctrl("Track Previous"),
                            0x19 => Key::ctrl("Track Next"),
                            0x1C => Key::letter('\n', '\n'), // keypad enter
                            0x1D => Key::ctrl("Control Right"),
                            0x20 => Key::ctrl("Mute"),
                            0x21 => Key::ctrl("Calculator"),
                            0x22 => Key::ctrl("Play"),
                            0x24 => Key::ctrl("Stop"),
                            0x2E => Key::ctrl("Volume Down"),
                            0x30 => Key::ctrl("Volume Up"),
                            0x32 => Key::ctrl("WWW Home"),
                            0x35 => Key::letter('/', '/'), // keypad /
                            0x38 => Key::ctrl("Alt Right"),
                            0x47 => Key::ctrl("Home"),
                            0x48 => Key::ctrl("Arrow Up"),
                            0x49 => Key::ctrl("Page Up"),
                            0x4B => Key::ctrl("Arrow Left"),
                            0x4D => Key::ctrl("Arrow Right"),
                            0x4F => Key::ctrl("End"),
                            0x50 => Key::ctrl("Arrow Down"),
                            0x51 => Key::ctrl("Page Down"),
                            0x52 => Key::ctrl("Insert"),
                            0x53 => Key::ctrl("Delete"),
                            0x5B => Key::ctrl("Meta Left"),
                            0x5C => Key::ctrl("Meta Right"),
                            0x5D => Key::ctrl("Apps"), // WTF is this !?
                            0x5E => Key::ctrl("Power"),
                            0x5F => Key::ctrl("Sleep"),
                            0x63 => Key::ctrl("Wake"),
                            0x65 => Key::ctrl("WWW Search"),
                            0x66 => Key::ctrl("WWW Favorites"),
                            0x67 => Key::ctrl("WWW Refresh"),
                            0x68 => Key::ctrl("WWW Stop"),
                            0x69 => Key::ctrl("WWW Forward"),
                            0x6A => Key::ctrl("WWW Back"),
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

                    0x01 => Key::ctrl("Escape"),

                    0x02 => Key::letter('1', '!'), 0x03 => Key::letter('2', '@'),
                    0x04 => Key::letter('3', '#'), 0x05 => Key::letter('4', '$'),
                    0x06 => Key::letter('5', '%'), 0x07 => Key::letter('6', '^'),
                    0x08 => Key::letter('7', '&'), 0x09 => Key::letter('8', '*'),
                    0x0a => Key::letter('9', '('), 0x0b => Key::letter('0', ')'),
                    0x0c => Key::letter('-', '_'), 0x0d => Key::letter('=', '+'),

                    0x0e => Key::letter('\x08', '\x08'), 0x0f => Key::letter('\t', '\t'),

                    0x10 => Key::letter('q', 'Q'), 0x11 => Key::letter('w', 'W'),
                    0x12 => Key::letter('e', 'E'), 0x13 => Key::letter('r', 'R'),
                    0x14 => Key::letter('t', 'T'), 0x15 => Key::letter('y', 'Y'),
                    0x16 => Key::letter('u', 'U'), 0x17 => Key::letter('i', 'I'),
                    0x18 => Key::letter('o', 'O'), 0x19 => Key::letter('p', 'P'),
                    0x1a => Key::letter('[', '{'), 0x1b => Key::letter(']', '}'),

                    0x1c => Key::letter('\n', '\n'), 0x1d => Key::ctrl("Control Left"),

                    0x1e => Key::letter('a', 'A'), 0x1f => Key::letter('s', 'S'),
                    0x20 => Key::letter('d', 'D'), 0x21 => Key::letter('f', 'F'),
                    0x22 => Key::letter('g', 'G'), 0x23 => Key::letter('h', 'H'),
                    0x24 => Key::letter('j', 'J'), 0x25 => Key::letter('k', 'K'),
                    0x26 => Key::letter('l', 'L'), 0x27 => Key::letter(';', ':'),
                    0x28 => Key::letter('\'', '"'), 0x29 => Key::letter('`', '~'),

                    0x2a => Key::ctrl("Shift Left"), 0x2b => Key::letter('\\', '|'),

                    0x2c => Key::letter('z', 'Z'), 0x2d => Key::letter('x', 'X'),
                    0x2e => Key::letter('c', 'C'), 0x2f => Key::letter('v', 'V'),
                    0x30 => Key::letter('b', 'B'), 0x31 => Key::letter('n', 'N'),
                    0x32 => Key::letter('m', 'M'), 0x33 => Key::letter(',', '<'),
                    0x34 => Key::letter('.', '>'), 0x35 => Key::letter('/', '?'),

                    0x36 => Key::ctrl("Shift Right"), 0x37 => Key::letter('*', '*'),
                    0x38 => Key::ctrl("Alt Left"), 0x39 => Key::letter(' ', ' '),
                    0x3a => Key::ctrl("CapsLock"),

                    0x3b => Key::ctrl("F1"), 0x3c => Key::ctrl("F2"),
                    0x3d => Key::ctrl("F3"), 0x3e => Key::ctrl("F4"),
                    0x3f => Key::ctrl("F5"), 0x40 => Key::ctrl("F6"),
                    0x41 => Key::ctrl("F7"), 0x42 => Key::ctrl("F8"),
                    0x43 => Key::ctrl("F9"), 0x44 => Key::ctrl("F10"),

                    0x45 => Key::ctrl("NumberLock"), 0x46 => Key::ctrl("ScrollLock"),

                    0x47 => Key::letter('7', '7'), 0x48 => Key::letter('8', '8'),
                    0x49 => Key::letter('9', '9'), 0x4a => Key::letter('-', '-'),
                    0x4b => Key::letter('4', '4'), 0x4c => Key::letter('5', '5'),
                    0x4d => Key::letter('6', '6'), 0x4e => Key::letter('+', '+'),
                    0x4f => Key::letter('1', '1'), 0x50 => Key::letter('2', '2'),
                    0x51 => Key::letter('3', '3'), 0x52 => Key::letter('0', '0'),
                    0x53 => Key::letter('.', '.'),

                    0x57 => Key::ctrl("F11"), 0x58 => Key::ctrl("F12"),

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
    fn handle_control_key(&self, key: ControlKey, state: State) {
        match key.0 {
            "CapsLock" => {
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
            "Shift Right" | "Shift Left" => {
                match state {
                    Pressed  => { self.is_shift.store(true,  SeqCst); }
                    Released => { self.is_shift.store(false, SeqCst); }
                }
            }
            _ => { debug!("Keyboard: {} {}", match state { Pressed => "pressed ", Released => "released" }, key.0); }
        }
    }

    /// Gets the letter from the key, accounting for shift and capslock
    fn key_to_letter(&self, key: LetterKey) -> char {
        match self.is_shift.load(SeqCst) || self.is_capslocked.load(SeqCst) {
            false => key.lower_case,
            true  => key.upper_case
        }
    }

    fn read_key(&self) -> char {
        loop {
            let status = self.status_port.read();
            if status & 0x01 != 0 {
                let key = KeyEvent::read_key_event(&self.data_port);
                match key {
                    KeyEvent {key: Key::Control(k), state: s               } => { self.handle_control_key(k, s); },
                    KeyEvent {key: Key::Letter(l),  state: State::Pressed  } => { return self.key_to_letter(l) },
                    KeyEvent {key: Key::Letter(_),  state: State::Released } => { /* ignore released letters */ },
                    KeyEvent {key: Key::Empty,      state: _               } => { /* ignore unknown keys */ },
                }
            } else {
                let _ = syscalls::wait_synchronization(&[self.event.0.as_ref()], None);
            }
        }
    }

    fn try_read_key(&self) -> Option<char> {
        loop {
            let status = self.status_port.read();
            if status & 0x01 != 0 {
                let key = KeyEvent::read_key_event(&self.data_port);
                match key {
                    KeyEvent {key: Key::Control(k), state: s               } => self.handle_control_key(k, s),
                    KeyEvent {key: Key::Letter(l),  state: State::Pressed  } => return Some(self.key_to_letter(l)),
                    _ => ()
                }
            } else {
                return None;
            }
        }
    }

    fn event_irq(&self) -> &ReadableEvent {
        &self.event
    }
}

lazy_static! {
    static ref PRIMARY_PS2 : PS2 = PS2 {
        status_port: Pio::<u8>::new(0x64),
        data_port: Pio::<u8>::new(0x60),
        event: syscalls::create_interrupt_event(1, 0).unwrap(),
        is_capslocked:  AtomicBool::new(false),
        is_shift:       AtomicBool::new(false)
    };
}

pub fn read_key() -> char {
    PRIMARY_PS2.read_key()
}

pub fn try_read_key() -> Option<char> {
    PRIMARY_PS2.try_read_key()
}

pub fn get_next_line(logger: &mut Terminal) -> String {
    let mut ret = String::from("");
    loop {
        let key = read_key();
        let _ = write!(logger, "{}", key);
        logger.draw().unwrap();
        if key == '\n' {
            return ret;
        } else if key == '\x08' {
            ret.pop();
        } else {
            ret.push(key);
        }
    }
}

#[allow(dead_code)]
pub fn get_waitable() -> &'static ReadableEvent {
    PRIMARY_PS2.event_irq()
}
