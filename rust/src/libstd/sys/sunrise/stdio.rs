use crate::io;

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;

impl Stdin {
    pub fn new() -> io::Result<Stdin> {
        Ok(Stdin)
    }
}

impl io::Read for Stdin {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        panic!("not supported on sunrise yet")
    }
}

impl Stdout {
    pub fn new() -> io::Result<Stdout> {
        Ok(Stdout)
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO(Sunrise): Bufferize
        use sunrise_libuser::syscalls::output_debug_string;

        let buf = unsafe { core::str::from_utf8_unchecked(buf) };

        let _ = output_debug_string(buf, 50, "stdout");

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stderr {
    pub fn new() -> io::Result<Stderr> {
        Ok(Stderr)
    }
}

impl io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO(Sunrise): Bufferize
        use sunrise_libuser::syscalls::output_debug_string;

        let buf = unsafe { core::str::from_utf8_unchecked(buf) };

        let _ = output_debug_string(buf, 10, "stderr");

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub const STDIN_BUF_SIZE: usize = 0;

pub fn is_ebadf(_err: &io::Error) -> bool {
    true
}

pub fn panic_output() -> Option<impl io::Write> {
    Stderr::new().ok()
}
