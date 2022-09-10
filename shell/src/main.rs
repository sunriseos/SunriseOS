//! Shell
//!
//! Creates an interactive terminal window, providing a few functions useful to
//! test Sunrise. Type help followed by enter to get a list of allowed commands.

#![feature(naked_functions)]
#![no_std]

// rustc warnings
#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]

// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(rustdoc::broken_intra_doc_links)]

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate sunrise_libuser as libuser;

mod subcommands;

use crate::libuser::fs::{IFileSystemServiceProxy, IFileSystemProxy, IFileProxy};
use crate::libuser::terminal::{Terminal, WindowSize};
use crate::libuser::ldr::{ILoaderInterfaceProxy};
use crate::libuser::error::{Error, FileSystemError};
use crate::libuser::syscalls;
use crate::libuser::ps2::Keyboard;
use crate::libuser::twili::ITwiliManagerServiceProxy;
use crate::libuser::threads::Thread;

use sunrise_libkern::process::ProcessState;

use core::fmt::Write;
use alloc::string::{ToString, String};
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::sync::Arc;
use bstr::ByteSlice;
use lazy_static::lazy_static;
use spin::{Once, Mutex};

use log::warn;
use log::error;


lazy_static! {
    /// Represent the current work directory.
    static ref CURRENT_WORK_DIRECTORY: Mutex<String> = Mutex::new(String::from("/"));
}

/// Asks the user to login repeatedly. Returns with an error if the /etc/passwd
/// file is invalid or doesn't exist.
fn login(mut terminal: &mut Terminal, keyboard: &mut Keyboard, filesystem: &IFileSystemProxy) -> Result<(), Error> {
    let mut ipc_path = [0x0; 0x300];
    ipc_path[..b"/etc/passwd".len()].copy_from_slice(b"/etc/passwd");

    let file: IFileProxy = filesystem.open_file(1, &ipc_path)?;
    let size = file.get_size().expect("get_size to work");
    let mut data = vec![0; size as usize];
    let read_count = file.read(0, 0, size, &mut data).expect("Read to work");
    data.resize(read_count as usize, 0);
    let data = match String::from_utf8(data) {
        Ok(data) => data,
        Err(_err) => {
            warn!("Invalid FSTAB: non-utf8 data found");
            return Ok(())
        }
    };

    // Login
    loop {
        let _ = write!(&mut terminal, "Login: ");
        let _ = terminal.draw();
        let username = get_next_line(&mut terminal);
        let username = username.trim_end_matches('\n');

        let _ = writeln!(&mut terminal, "Password: ");
        let password = get_next_line_no_echo(keyboard);
        let password = password.trim_end_matches('\n');

        let hash = sha1::Sha1::from(&password).digest().bytes();

        for item in data.split('\n') {
            let mut it = item.split(' ');
            if let (Some(item_username), Some(item_hash)) = (it.next(), it.next()) {
                if let Ok(item_hash) = hex::decode(item_hash) {
                    if username == item_username && hash[..] == item_hash[..] {
                        let _ = writeln!(&mut terminal, "Login Success!");
                        return Ok(());
                    }
                }
            }
        }

        let _ = writeln!(&mut terminal, "Invalid login or password");
        let _ = syscalls::sleep_thread(1 * 1000 * 1000 * 1000);
    }
}

/// Read key presses until a \n is detected, and return the string
/// (excluding \n). Don't print the key presses on stdout.
pub fn get_next_line_no_echo(keyboard: &mut Keyboard) -> String {
    let mut ret = String::from("");
    loop {
        let key = keyboard.read_key();
        if key == '\n' {
            return ret;
        } else if key == '\x08' {
            ret.pop();
        } else {
            ret.push(key);
        }
    }
}

/// Read key presses until a \n is detected, and return the string
/// (excluding \n). The key presses should be written to stdout.
pub fn get_next_line(logger: &mut Terminal) -> String {
    let mut bytes = vec![0; 256];
    let mut read = 0;
    loop {
        if bytes.len() - read < 4 {
            bytes.resize(bytes.len() * 2, 0);
        }
        read += logger.read(&mut bytes[read..]).unwrap() as usize;
        let s = core::str::from_utf8(&bytes[..read]).unwrap();
        if s.contains('\n') {
            bytes.resize(read, 0);
            return String::from_utf8(bytes).unwrap();
        }
    }
}

/// A command to run as part of a pipeline.
#[derive(Debug)]
struct Command<'a> {
    /// Array of arguments to pass to the subcommand. First argument is the
    /// command name.
    args: Vec<&'a str>,
    /// The filename to take stdin from.
    redirect_stdin: Option<&'a str>,
    /// The filename to redirect stdout to.
    redirect_stdout: Option<&'a str>,
    /// True if stdout should be piped to the next command in the cmdline.
    pipe_stdout: bool,
}

/// Parses a single command from the given string. Returns the command and the
/// amount of bytes read from the string.
fn parse_line(args: &str) -> (Command, usize) {
    let mut data = Vec::new();
    let mut redirects = [None, None, None];

    let mut arg_start = None;
    let mut arg_len = 0;
    let mut quote_flag = false;
    let mut redirect_flag = None;
    let mut stop_at = None;
    for (argi, item) in args.bytes().enumerate() {
        if arg_start.is_none() && item.is_ascii_whitespace() {
            // Skip over ascii whitespace
            continue;
        }

        if item == b'|' || item == b'&' {
            // Found a character delimiting
            stop_at = Some(argi);
            break;
        }

        if let Some(arg_start_idx) = arg_start {
            // We're currently handling an arg.
            // Check if we have reached the end of an argument.
            let end_flag = (quote_flag && item == b'"') || item.is_ascii_whitespace();

            // If we didn't, include the character being processed in the
            // current arg.
            if !end_flag {
                arg_len += 1;
            }

            if end_flag && arg_len != 0 {
                // If we've reached the end of an argument we copy it to the
                // args vec.
                if let Some(idx) = redirect_flag {
                    redirects[idx] = Some(&args[arg_start_idx..arg_start_idx + arg_len]);
                } else if arg_len != 0 {
                    data.push(&args[arg_start_idx..arg_start_idx + arg_len])
                }

                // Reset all state to and look for the next arg.
                arg_start = None;
                quote_flag = false;
                redirect_flag = None;
                arg_len = 0;
            }
        } else if item == b'"' {
            // Found a new quoted argument.
            arg_start = Some(argi + 1);
            quote_flag = true;
        } else if (item == b'<' || item == b'>') && redirect_flag.is_some() {
            // Error!
            panic!("");
        } else if item == b'<' {
            // Found an stdin redirect.
            redirect_flag = Some(0);
        } else if item == b'>' {
            // Found an stdout redirect.
            redirect_flag = Some(1);
        } else {
            // Found a new argument.
            arg_start = Some(argi);
            arg_len += 1;
        }
    }

    if let Some(arg_start_idx) = arg_start {
        // Handle last argument.
        if let Some(idx) = redirect_flag {
            redirects[idx] = Some(&args[arg_start_idx..arg_start_idx + arg_len]);
        } else if arg_len != 0 {
            data.push(&args[arg_start_idx..arg_start_idx + arg_len])
        }
    }

    let cmd = Command {
        args: data, redirect_stdin: redirects[0], redirect_stdout: redirects[1],
        pipe_stdout: false
    };

    (cmd, stop_at.unwrap_or_else(|| args.len()))
}

/// Generate a list of command from a given command line.
fn generate_cmd(args: &str) -> Vec<Command> {
    let mut cmds = Vec::new();

    let mut cur = 0;
    while cur < args.len() {
        let (mut cmd, stop_at) = parse_line(&args[cur..]);
        assert_ne!(stop_at, 0, "parse_line failed");
        cur += stop_at;

        if args.bytes().nth(cur) == Some(b'|') {
            cmd.pipe_stdout = true;
            cur += 1;
        }
        cmds.push(cmd);
    }

    cmds
}

/// Represents a command currently running.
///
/// Commands can either be built-in, in which case they are represented by a
/// thread handle, or a different process which is represented by a pid.
#[derive(Debug)]
pub enum Job {
    /// This job is a builtin running in a separate thread.
    BuiltIn {
        /// This job's underlying thread handle.
        thread: Thread
    },
    /// This job is an external binary running in a different process.
    Process {
        /// This job's underlying pid.
        pid: u64
    },
}

impl Job {
    /// Let this job start running.
    pub fn start(&self, loader: &ILoaderInterfaceProxy) -> Result<(), Error> {
        match self {
            Job::BuiltIn { thread } => thread.start(),
            Job::Process { pid } => loader.launch_title(*pid)
        }
    }
}

/// Generate a vector of [Job] from a command line.
///
/// The returned jobs will not be started, it's up to the caller to start them.
/// The jobs' stdin/stdout/stderr will be properly configured according to the
/// line - pipes and stdin/stdout redirection are supported. Stderr always
/// points to the terminal.
pub fn generate_jobs(mut terminal: &mut Terminal, filesystem: &IFileSystemProxy, twili: &ITwiliManagerServiceProxy, loader: &ILoaderInterfaceProxy, line: &str) -> Result<Vec<Job>, Error> {
    let mut processes = Vec::new();
    let mut last_pipe = None;

    for cmd in generate_cmd(&line) {
        let cmdname = if let Some(val) = cmd.args.get(0) {
            val
        } else {
            let _ = writeln!(&mut terminal, "Invalid command: no cmdname provided");
            break;
        };

        let stdin = match (cmd.redirect_stdin, last_pipe) {
            (Some(_), Some(_)) => {
                let _ = writeln!(&mut terminal, "Invalid command: {} had both a pipe and an input redirect provided.", cmdname);
                break;
            },
            (Some(path), None) => {
                let mut ipc_path = [0; 0x300];
                ipc_path[..path.len()].copy_from_slice(path.as_bytes());
                filesystem.open_file_as_ipipe(1, &ipc_path).unwrap()
            },
            (None, Some(pipe)) => pipe,
            (None, None) => terminal.clone_pipe().unwrap()
        };

        last_pipe = None;

        let stdout = match (cmd.redirect_stdout, cmd.pipe_stdout) {
            (Some(_), true) => {
                let _ = writeln!(&mut terminal, "Invalid command: {} had both a pipe and an input redirect provided.", cmdname);
                break;
            },
            (Some(path), false) => {
                let mut ipc_path = [0; 0x300];
                ipc_path[..path.len()].copy_from_slice(path.as_bytes());
                let _ = filesystem.create_file(0, 0, &ipc_path);
                let file = filesystem.open_file(6, &ipc_path)?;
                file.set_size(0)?;
                filesystem.open_file(6, &ipc_path).unwrap();
                filesystem.open_file_as_ipipe(6, &ipc_path).unwrap()
            },
            (None, true) => {
                let (read_pipe, write_pipe) = twili.create_pipe().unwrap();
                last_pipe = Some(read_pipe);
                write_pipe
            },
            (None, false) => {
                terminal.clone_pipe().unwrap()
            },
        };

        let stderr = terminal.clone_pipe().unwrap();

        let job = if let Some((f, _)) = subcommands::SUBCOMMANDS.get(cmdname) {
            let thread = Thread::create(subcommands::run, Box::into_raw(Box::new(subcommands::RunArgs {
                stdin, stdout, stderr, f: *f,
                args: line.split_whitespace().map(|v| v.to_string()).collect::<Vec<String>>(),
                ret: Arc::new(Once::new()),
            })) as usize, 4096 * 4)?;
            Job::BuiltIn { thread }
        } else {
            // Try to run it as an external binary.
            let args = cmd.args.iter().map(|v| format!("\"{}\" ", v)).collect::<String>();
            let env = format!("PWD=system:{}\0", &*CURRENT_WORK_DIRECTORY.lock());
            let pid = loader.create_title(cmdname.as_bytes(), args.as_bytes(), env.as_bytes())?;
            twili.register_pipes(pid, stdin, stdout, stderr)?;
            Job::Process { pid }
        };

        processes.push(job)
    }

    Ok(processes)
}

fn main() {
    let mut terminal = Terminal::new(WindowSize::FontLines(-1, false)).unwrap();
    let mut keyboard = Keyboard::new().unwrap();
    let twili = ITwiliManagerServiceProxy::new().unwrap();
    let loader = ILoaderInterfaceProxy::raw_new().unwrap();

    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();

    let process_state_changed_event = loader.get_process_state_changed_event().unwrap();

    cat(&mut terminal, &filesystem, "/etc/motd").unwrap();

    if let Err(err) = login(&mut terminal, &mut keyboard, &filesystem) {
        error!("Error while setting up login: {:?}", err);
    }

    loop {
        let line = get_next_line(&mut terminal);
        let jobs = match generate_jobs(&mut terminal, &filesystem, &twili, &loader, &line) {
            Ok(jobs) => jobs,
            Err(err) => {
                let _ = writeln!(&mut terminal, "Failed to run line: {:?}", err);
                continue
            }
        };

        let mut waiters = vec![process_state_changed_event.0.as_ref()];
        let mut pids = vec![];

        let mut finished_count = 0;
        for job in &jobs {
            if let Err(err) = job.start(&loader) {
                let _ = writeln!(&mut terminal, "Failed to start process: {:?}", err);
            }
            match job {
                Job::BuiltIn { thread } => waiters.push(thread.as_thread_ref().0.as_ref_static()),
                Job::Process { pid } => pids.push(pid),
            }
        }

        while finished_count != jobs.len() {
            match syscalls::wait_synchronization(&waiters, None) {
                Err(err) => {
                    error!("{:?}", err);
                    let _ = writeln!(&mut terminal, "Internal error: {:?}", err);
                    break;
                },
                Ok(0) => {
                    let _ = process_state_changed_event.clear();
                    // Check all the pids, hopefully one died.
                    pids.retain(|pid| {
                        let state = match loader.get_state(**pid) {
                            Ok(state) => state,
                            Err(err) => {
                                finished_count += 1;
                                error!("{:?}", err);
                                return false;
                            }
                        };
                        let is_exited = ProcessState(state) == ProcessState::Exited;
                        if is_exited {
                            finished_count += 1;
                        }
                        !is_exited
                    })
                },
                Ok(idx) => {
                    // Subprocess died?
                    finished_count += 1;
                    waiters.remove(idx);
                }
            }
        }
    }
}

/// Splits a path at the first `/` it encounters.
///
/// Returns a tuple of the parts before and after the cut.
///
/// # Notes:
/// - The rest part can contain duplicates '/' in the middle of the path. This should be fine as you should call split_path to parse the rest part.
pub fn split_path(path: &str) -> (&str, Option<&str>) {
    let mut path_split = path.trim_matches('/').splitn(2, '/');

    // unwrap will never fail here
    let comp = path_split.next().unwrap();
    let rest_opt = path_split.next().map(|x| x.trim_matches('/'));

    (comp, rest_opt)
}

/// Get an absolute path from an user path
fn get_absolute_path(path: &str) -> String {
    let mut path = path;
    let mut path_parts = Vec::new();

    loop {
        let (comp, rest_opt) = split_path(path);

        match comp {
            "." => {},
            ".." => {
                path_parts.pop();
            }
            _ => {
                let mut component = String::new();
                component.push('/');
                component.push_str(comp);

                path_parts.push(component);
            }
        }

        if rest_opt.is_none() {
            break;
        }

        path = rest_opt.unwrap();
    }

    let mut res = String::new();

    if path_parts.is_empty() {
        res.push('/');
    }

    for part in path_parts {
        res.push_str(part.as_str())
    }

    res
}

/// Get a path relative to the current directory
fn get_path_relative_to_current_directory(resource: &str) -> String {
    let current_directory = CURRENT_WORK_DIRECTORY.lock();

    let mut absolute_current_directory = get_absolute_path(current_directory.as_str());

    // We check that the initial input start with a '/'
    if !resource.starts_with('/') {
        absolute_current_directory.push('/');
        absolute_current_directory.push_str(resource);
        absolute_current_directory = get_absolute_path(absolute_current_directory.as_str());
    } else {
        absolute_current_directory = get_absolute_path(resource);
    }

    absolute_current_directory
}

/// Print a file on the standard output.
fn cat<W: Write>(f: &mut W, filesystem: &IFileSystemProxy, file: &str) -> Result<(), Error> {
    let absolute_file_directory = get_path_relative_to_current_directory(file);

    if absolute_file_directory.len() > 0x300 {
        return Err(FileSystemError::InvalidInput.into())
    }

    let mut ipc_path = [0x0; 0x300];
    ipc_path[..absolute_file_directory.as_bytes().len()].copy_from_slice(absolute_file_directory.as_bytes());

    let mut buffer = [0; 0x200];
    let buffer_len = buffer.len() as u64;
    let mut offset = 0;

    let file: IFileProxy = filesystem.open_file(1, &ipc_path)?;
    loop {
        let read_size = file.read(0, offset, buffer_len, &mut buffer)?;
        let string_part = (&buffer[..read_size as usize]).as_bstr().trim_with(|c| c == '\0').as_bstr();
        let _ = write!(f, "{}", string_part);

        offset += read_size;

        if read_size != buffer_len {
            break;
        }
    }
    Ok(())
}

kip_header!(HEADER = sunrise_libuser::caps::KipHeader {
    magic: *b"KIP1",
    name: *b"shell\0\0\0\0\0\0\0",
    title_id: 0x0200000000001000,
    process_category: sunrise_libuser::caps::ProcessCategory::KernelBuiltin,
    main_thread_priority: 0,
    default_cpu_core: 0,
    flags: 0,
    reserved: 0,
    stack_page_count: 16,
});

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        libuser::syscalls::nr::SleepThread,
        libuser::syscalls::nr::ExitProcess,
        libuser::syscalls::nr::CloseHandle,
        libuser::syscalls::nr::WaitSynchronization,
        libuser::syscalls::nr::OutputDebugString,
        libuser::syscalls::nr::SetThreadArea,
        libuser::syscalls::nr::ClearEvent,

        libuser::syscalls::nr::SetHeapSize,
        libuser::syscalls::nr::QueryMemory,
        libuser::syscalls::nr::CreateThread,
        libuser::syscalls::nr::StartThread,
        libuser::syscalls::nr::ExitThread,
        libuser::syscalls::nr::MapSharedMemory,
        libuser::syscalls::nr::UnmapSharedMemory,
        libuser::syscalls::nr::ConnectToNamedPort,
        libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        libuser::syscalls::nr::CreateSharedMemory,
        libuser::syscalls::nr::CreateInterruptEvent,
        libuser::syscalls::nr::GetProcessList,
    ]
});
