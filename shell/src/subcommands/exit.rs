//! Exits the shell.

use alloc::string::String;
use alloc::vec::Vec;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;
use sunrise_libuser::syscalls;

/// Help string.
pub static HELP: &str = "exit: Exit this process";

/// Print the current working directory.
pub fn main(_stdin: IPipeProxy, _stdout: IPipeProxy, _stderr: IPipeProxy, _args: Vec<String>) -> Result<(), Error> {
    // Kinda dangerous. Doesn't close all pending IPC sockets.
    syscalls::exit_process();
    unreachable!();
    Ok(())
}