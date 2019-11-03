//! Print the help message.

use core::fmt::Write;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;

/// Help string.
pub static HELP: &'static str = "help: Print this message.";

/// Print the help message.
pub fn main(_stdin: IPipeProxy, mut stdout: IPipeProxy, _stderr: IPipeProxy, _args: &[&str]) -> Result<(), Error> {
    let _ = writeln!(&mut stdout, "COMMANDS:");
    // Harcode exit, which isn't a "real" subcommand.
    let _ = writeln!(&mut stdout, "exit: Exit this process");
    for (_f, help) in super::SUBCOMMANDS.values() {
        let _ = writeln!(&mut stdout, "{}", help);
    }
    Ok(())
}