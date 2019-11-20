//! Kill the provided pid.
//!
//! Takes a single argument, the pid to kill. PID should be a number, you can
//! find the currently running processes with the ps command.

use core::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;
use sunrise_libuser::ldr::ILoaderInterfaceProxy;

/// Help string.
pub static HELP: &str = "kill <pid>: Kill the given process";

/// Kill the process associated with the provided pid.
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, args: Vec<String>) -> Result<(), Error> {
    let pid = match args.get(1) {
        Some(pid) => pid,
        None => {
            let _ = writeln!(&mut stdout, "usage: kill <pid>");
            return Ok(());
        },
    };

    let pid = match str::parse(pid) {
        Ok(pid) => pid,
        Err(_) => {
            let _ = writeln!(&mut stdout, "usage: kill <pid>");
            return Ok(())
        }
    };

    let loader = ILoaderInterfaceProxy::new().unwrap();

    loader.kill(pid)?;
    let _ = loader.wait(pid);
    Ok(())
}
