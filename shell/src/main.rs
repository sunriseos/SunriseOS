//! Shell
//!
//! Creates an interactive terminal window, providing a few functions useful to
//! test Sunrise. Type help followed by enter to get a list of allowed commands.

#![feature(asm, naked_functions)]
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
#![deny(intra_doc_link_resolution_failure)]

#[macro_use]
extern crate alloc;

#[macro_use]
extern crate sunrise_libuser as libuser;

mod subcommands;

use crate::libuser::fs::{IFileSystemServiceProxy, IFileSystemProxy, IFileProxy};
use crate::libuser::terminal::{Terminal, WindowSize};
use crate::libuser::ldr::{ILoaderInterfaceProxy};
use crate::libuser::error::{Error, LoaderError, FileSystemError};
use crate::libuser::syscalls;
use crate::libuser::ps2::Keyboard;
use crate::libuser::twili::ITwiliManagerServiceProxy;

use core::fmt::Write;
use alloc::string::String;
use alloc::vec::Vec;
use bstr::ByteSlice;
use lazy_static::lazy_static;
use spin::Mutex;

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

fn main() {
    let mut terminal = Terminal::new(WindowSize::FontLines(-1, false)).unwrap();
    let mut keyboard = Keyboard::new().unwrap();
    let twili = ITwiliManagerServiceProxy::new().unwrap();
    let loader = ILoaderInterfaceProxy::raw_new().unwrap();

    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();

    cat(&mut terminal, &filesystem, "/etc/motd").unwrap();

    if let Err(err) = login(&mut terminal, &mut keyboard, &filesystem) {
        error!("Error while setting up login: {:?}", err);
    }

    loop {
        let line = get_next_line(&mut terminal);

        let stdin = terminal.clone_pipe().unwrap();
        let stdout = terminal.clone_pipe().unwrap();
        let stderr = terminal.clone_pipe().unwrap();

        let command = match line.split_whitespace().next() {
            Some(cmd) => cmd,
            None => continue
        };

        if let Some((f, _)) = subcommands::SUBCOMMANDS.get(command) {
            if let Err(err) = f(stdin, stdout, stderr, line.split_whitespace().map(|v| v.to_string()).collect::<Vec<String>>()) {
                let _ = writeln!(&mut terminal, "{}: {:?}", command, err);
            }
        } else if command == "exit" {
            // Handling it as a built-in is too much work.
            return;
        } else {
            // Try to run it as an external binary.
            let res = (|| {
                let pid = loader.create_title(command.as_bytes(), line.as_bytes())?;
                twili.register_pipes(pid, stdin, stdout, stderr)?;
                loader.launch_title(pid)?;
                loader.wait(pid)
            })();

            match res {
                Err(Error::Loader(LoaderError::ProgramNotFound, _)) => {
                    let _ = writeln!(&mut terminal, "Unknown command");
                },
                Err(err) => {
                    let _ = writeln!(&mut terminal, "Error: {:?}", err);
                },
                Ok(_exitstatus) => ()
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
    let rest_opt = path_split.next().and_then(|x| Some(x.trim_matches('/')));

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
