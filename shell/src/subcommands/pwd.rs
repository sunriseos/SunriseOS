//! Print the current working directory.

use core::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;

/// Help string.
pub static HELP: &str = "pwd: Print name of the current/working directory";

/// Print the current working directory.
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, _args: Vec<String>) -> Result<(), Error> {
    let _ = writeln!(&mut stdout, "{}", crate::CURRENT_WORK_DIRECTORY.lock().as_str());
    Ok(())
}