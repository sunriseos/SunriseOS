//! List currently running processes.
//!

use core::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;
use sunrise_libuser::syscalls;
use sunrise_libuser::ldr::ILoaderInterfaceProxy;

/// Help string.
pub static HELP: &str = "ps: List running processes";

/// Get the pid and names of processes currently running.
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, _args: Vec<String>) -> Result<(), Error> {
    let loader = ILoaderInterfaceProxy::raw_new().unwrap();

    let mut pids = [0; 256];
    let pid_read = syscalls::get_process_list(&mut pids)?;
    for pid in &pids[..pid_read] {
        let mut name = [0; 32];
        let name = match loader.get_name(*pid, &mut name) {
            Ok(copied_len) => String::from_utf8_lossy(&name[..copied_len as usize]).into_owned(),
            Err(err) => {
                log::debug!("Error: {:?}", err);
                String::from("<Unknown>")
            }
        };
        let _ = writeln!(&mut stdout, "{}: {}", pid, name);
    }
    Ok(())
}
