//! Test function ensuring SM's get_service works.

use core::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;
use sunrise_libuser::sm;

/// Help string.
pub static HELP: &str = "connect: Test SM get_service function.";

/// Test function ensuring SM's get_service works.
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, _args: Vec<String>) -> Result<(), Error> {
    let handle = sm::IUserInterfaceProxy::raw_new().unwrap().get_service(u64::from_le_bytes(*b"vi:\0\0\0\0\0"));
    let _ = writeln!(&mut stdout, "Got handle {:?}", handle);
    Ok(())
}