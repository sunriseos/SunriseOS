//! Shell builtin subcommands
//!
//! When the user tries to run a command, shell will first check if it's a
//! built-in command by looking if the command name exists within the
//! `SUBCOMMANDS` global.
//!
//! A subcommand is a function of type `fn(IPipeProxy, IPipeProxy, IPipeProxy, Vec<String>) -> Result<(), Error>`.
//! It is expected to be started in a separate thread from the main shell. This
//! is necessary because reading on a pipe can potentially block. If they were
//! spawned on the main thread, it could lead to a blocked main thread.
//!
//! Also stored is the help text associated with that function.

mod useradd;
mod showgif;
mod pwd;
mod cd;
mod test_threads;
mod test_divide_by_zero;
mod test_page_fault;
mod connect;
mod ps;
mod kill;
mod help;
mod exit;

use sunrise_libuser::error::Error;
use sunrise_libuser::twili::IPipeProxy;
use lazy_static::lazy_static;

use alloc::collections::BTreeMap;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::Arc;
use spin::Once;

/// Subcommand function. See [module documentation](crate::subcommands).
type SubcommandFn = fn(IPipeProxy, IPipeProxy, IPipeProxy, Vec<String>) -> Result<(), Error>;

lazy_static! {
    /// List of subcommands. See [module documentation](crate::subcommands).
    pub static ref SUBCOMMANDS: BTreeMap<&'static str, (SubcommandFn, &'static str)> = {
        let mut subcommands = BTreeMap::new();
        subcommands.insert("exit", (exit::main as _, exit::HELP));
        subcommands.insert("useradd", (useradd::main as _, useradd::HELP));
        subcommands.insert("showgif", (showgif::main as _, showgif::HELP));
        subcommands.insert("pwd", (pwd::main as _, pwd::HELP));
        subcommands.insert("cd", (cd::main as _, cd::HELP));
        subcommands.insert("test_threads", (test_threads::main as _, test_threads::HELP));
        subcommands.insert("test_divide_by_zero", (test_divide_by_zero::main as _, test_divide_by_zero::HELP));
        subcommands.insert("test_page_fault", (test_page_fault::main as _, test_page_fault::HELP));
        subcommands.insert("connect", (connect::main as _, connect::HELP));
        subcommands.insert("ps", (ps::main as _, ps::HELP));
        subcommands.insert("kill", (kill::main as _, kill::HELP));
        subcommands.insert("help", (help::main as _, help::HELP));
        subcommands
    };
}

/// The structure sent to the builtin subcommand's trampoline function.
pub struct RunArgs {
    /// Stdin pipe to use for this subcommand.
    pub stdin: IPipeProxy,
    /// Stdout pipe to use for this subcommand.
    pub stdout: IPipeProxy,
    /// Stderr pipe to use for this subcommand.
    pub stderr: IPipeProxy,
    /// Args to pass to the subcommand's main.
    pub args: Vec<String>,
    /// Return value of this subcommand.
    pub ret: Arc<Once<Result<(), Error>>>,
    /// Subcommand's main function.
    pub f: fn(IPipeProxy, IPipeProxy, IPipeProxy, Vec<String>) -> Result<(), Error>
}

/// Trampoline function for a subcommand thread. Takes a pointer to a RunArgs
/// box as an argument.
pub fn run(arg: usize) {
    let args: Box<RunArgs> = unsafe { Box::from_raw(arg as *mut RunArgs) };
    let RunArgs {
        stdin, stdout, stderr, args, ret, f
    } = *args;
    ret.call_once(move || f(stdin, stdout, stderr, args));
}