use i386::pio::Pio;
use io::Io;

struct PS2 {
    status_port: Pio<u8>,
    data_port: Pio<u8>,
    event_irq: usize
}

impl PS2 {
    fn read_key(&self) -> char {
        loop {
            ::event::wait_event(self.event_irq);

            const KEYBOARD_MAP : [char; 59] = [
                '\x00', '\x1b', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\x08',
                '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
                '\x00', 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', '\x00',
                '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', '\x00', '*',
                '\x00', ' ', '\x00'
            ];
            unsafe {
                let status = self.status_port.read();
                if status & 0x01 != 0 {
                    let keycode = self.data_port.read();
                    if (keycode as usize) < KEYBOARD_MAP.len() && KEYBOARD_MAP[keycode as usize] != '\x00' {
                        return KEYBOARD_MAP[keycode as usize];
                    }
                }
            }
        }
    }
}

static PRIMARY_PS2 : PS2 = PS2 {
    status_port: Pio::<u8>::new(0x64),
    data_port: Pio::<u8>::new(0x60),
    event_irq: 1
};

pub fn read_key() -> char {
    PRIMARY_PS2.read_key()
}
