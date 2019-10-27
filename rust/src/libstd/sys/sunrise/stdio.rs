use crate::io;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::{ITwiliServiceProxy, IPipeProxy};
use spin::Once;

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;

pub static PIPES: Once<(IPipeProxy, IPipeProxy, IPipeProxy)> =
    Once::new();

pub fn init() -> Result<(), Error> {
    let pipes = ITwiliServiceProxy::new()?.open_pipes()?;
    PIPES.call_once(|| pipes);
    Ok(())
}

impl Stdin {
    pub fn new() -> io::Result<Stdin> {
        Ok(Stdin)
    }
}

impl io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        PIPES.r#try()
            .ok_or(io::Error::from(io::ErrorKind::NotFound))
            .and_then(|v| Ok(v.0.read(buf)? as usize))
    }
}

impl Stdout {
    pub fn new() -> io::Result<Stdout> {
        Ok(Stdout)
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        PIPES.r#try()
            .ok_or(io::Error::from(io::ErrorKind::NotFound))
            .and_then(|v| { v.1.write(buf)?; Ok(buf.len()) })
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
