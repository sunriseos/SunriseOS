use crate::io;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::{ITwiliServiceProxy, IPipeProxy};
use crate::sync::{LockResult, RwLock};
use lazy_static::lazy_static;

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;

lazy_static! {
    static ref PIPE_STDIN: RwLock<Option<IPipeProxy>> = RwLock::new(None);
    static ref PIPE_STDOUT: RwLock<Option<IPipeProxy>> = RwLock::new(None);
    static ref PIPE_STDERR: RwLock<Option<IPipeProxy>> = RwLock::new(None);
}

pub fn init() -> Result<(), Error> {
    let (stdin, stdout, stderr) = ITwiliServiceProxy::new()?.open_pipes()?;
    *get_poison_inner(PIPE_STDIN.write()) = Some(stdin);
    *get_poison_inner(PIPE_STDOUT.write()) = Some(stdout);
    *get_poison_inner(PIPE_STDERR.write()) = Some(stderr);

    fn get_poison_inner<T>(result: LockResult<T>) -> T {
        match result {
            Ok(val) => val,
            Err(err) => err.into_inner()
        }
    }

    // Close the pipes on exit
    crate::sys_common::at_exit(|| {
        get_poison_inner(PIPE_STDIN.write()).take();
        get_poison_inner(PIPE_STDOUT.write()).take();
        get_poison_inner(PIPE_STDERR.write()).take();
    });

    Ok(())
}

impl Stdin {
    pub fn new() -> io::Result<Stdin> {
        Ok(Stdin)
    }
}

impl io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let lock = PIPE_STDIN.try_read()
            .or(Err(io::Error::from(io::ErrorKind::NotFound)))?;
        lock.as_ref()
            .ok_or(io::Error::from(io::ErrorKind::NotFound))
            .and_then(|v| Ok(v.read(buf)? as usize))
    }
}

impl Stdout {
    pub fn new() -> io::Result<Stdout> {
        Ok(Stdout)
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let lock = PIPE_STDOUT.try_read()
            .or(Err(io::Error::from(io::ErrorKind::NotFound)))?;
        lock.as_ref()
            .ok_or(io::Error::from(io::ErrorKind::NotFound))
            .and_then(|v| { v.write(buf)?; Ok(buf.len()) })
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

pub const STDIN_BUF_SIZE: usize = 1024; // 1024 bytes should be more than enough.

pub fn is_ebadf(_err: &io::Error) -> bool {
    true
}

pub fn panic_output() -> Option<impl io::Write> {
    Stderr::new().ok()
}
