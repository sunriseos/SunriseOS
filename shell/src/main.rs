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

use gif;
#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate sunrise_libuser as libuser;



mod ps2;
use crate::libuser::io;
use crate::libuser::sm;
use crate::libuser::fs::{IFileSystemServiceProxy, IFileSystemProxy, IFileProxy};
use crate::libuser::window::{Window, Color};
use crate::libuser::terminal::{Terminal, WindowSize};
use crate::libuser::threads::{self, Thread};
use crate::libuser::error::{Error, FileSystemError};
use crate::libuser::syscalls;

use core::fmt::Write;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::Arc;
use spin::Mutex;
use bstr::ByteSlice;

lazy_static! {
    /// Represent the current work directory.
    static ref CURRENT_WORK_DIRECTORY: Mutex<String> = Mutex::new(String::from("/"));
}

/// Asks the user to login repeatedly. Returns with an error if the /etc/passwd
/// file is invalid or doesn't exist.
fn login(mut terminal: &mut Terminal, filesystem: &IFileSystemProxy) -> Result<(), Error> {
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
        let username = ps2::get_next_line(&mut terminal, true);
        let username = username.trim_end_matches('\n');

        let _ = writeln!(&mut terminal, "Password: ");
        let password = ps2::get_next_line(&mut terminal, false);
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

/// Adds a new user to /etc/passwd with the specified username.
///
/// The function takes care of prompting for the password in no-echo mode. If
/// an error is returned, then it should be assumed that the user was not added
/// to /etc/passwd.
fn user_add(mut terminal: &mut Terminal, filesystem: &IFileSystemProxy, username: &str) -> Result<(), Error> {
    let _ = writeln!(&mut terminal, "Password: ");
    let password = ps2::get_next_line(&mut terminal, false);
    let password = password.trim_end_matches('\n');

    let hash = sha1::Sha1::from(&password).digest().bytes();

    let mut ipc_path = [0x0; 0x300];
    ipc_path[..b"/etc/passwd".len()].copy_from_slice(b"/etc/passwd");

    let _ = filesystem.create_file(0, 0, &ipc_path);
    let file = filesystem.open_file(0b111, &ipc_path)?;
    let size = file.get_size()?;

    let mut newline = String::from(username);
    newline.push(' ');
    newline += &hex::encode(&hash);
    newline.push('\n');

    file.write(0, size, newline.len() as _, newline.as_bytes())?;

    Ok(())
}

fn main() {
    let mut terminal = Terminal::new(WindowSize::FontLines(-1, false)).unwrap();

    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();

    cat(&mut terminal, &filesystem, "/etc/motd").unwrap();

    if let Err(err) = login(&mut terminal, &filesystem) {
        error!("Error while setting up login: {:?}", err);
    }

    loop {
        let line = ps2::get_next_line(&mut terminal, true);
        let mut arguments = line.split_whitespace();
        let command_opt = arguments.next();

        if command_opt.is_none() {
            continue;
        }

        match command_opt.unwrap() {
            "useradd" => {
                match arguments.next() {
                    None => {
                        let _ = writeln!(&mut terminal, "usage: useradd <username>");
                    }
                    Some(username) => match user_add(&mut terminal, &filesystem, username) {
                        Ok(_) => (),
                        Err(err) => {
                            let _ = writeln!(&mut terminal, "Failed to add user: {:?}", err);
                        }
                    },
                }
            }
            "meme1" => show_gif(&LOUIS1[..]),
            "meme2" => show_gif(&LOUIS2[..]),
            "meme3" => show_gif(&LOUIS3[..]),
            "meme4" => show_gif(&LOUIS4[..]),
            "meme5" => show_gif(&LOUIS5[..]),
            "meme6" => show_gif(&LOUIS6[..]),
            "memset" => show_gif(&LOUIS7[..]),
            "cat" => {
                match arguments.nth(0) {
                    None => {
                        let _ = writeln!(&mut terminal, "usage: cat <file>");
                    }
                    Some(path) => {
                        if let Err(error) = cat(&mut terminal, &filesystem, path) {
                            let _ = writeln!(&mut terminal, "cat: {}", error);
                        }
                    }
                }

            }
            "pwd" => {
                let _ = writeln!(&mut terminal, "{}", CURRENT_WORK_DIRECTORY.lock().as_str());
            },
            "cd" => {
                match arguments.nth(0) {
                    None => {
                        let _ = writeln!(&mut terminal, "usage: cd <directory>");
                    }
                    Some(path) => {
                        if let Err(error) = cd(&filesystem, path) {
                            let _ = writeln!(&mut terminal, "cd: {}", error);
                        }
                    }
                }
            }
            "ls" => if let Err(error) = ls(&mut terminal, &filesystem, arguments.nth(0)) {
                let _ = writeln!(&mut terminal, "ls: {}", error);
            },
            "test_threads" => terminal = test_threads(terminal),
            "test_divide_by_zero" => test_divide_by_zero(),
            "test_page_fault" => test_page_fault(),
            "connect" => {
                let handle = sm::IUserInterfaceProxy::raw_new().unwrap().get_service(u64::from_le_bytes(*b"vi:\0\0\0\0\0"));
                let _ = writeln!(&mut terminal, "Got handle {:?}", handle);
            },
            "exit" => return,
            //"stackdump" => unsafe { stack::KernelStack::dump_current_stack() },
            "help" => {
                let _ = writeln!(&mut terminal, "COMMANDS:");
                let _ = writeln!(&mut terminal, "exit: Exit this process");
                let _ = writeln!(&mut terminal, "useradd <username>: Adds a new user");
                let _ = writeln!(&mut terminal, "cat <file>: Print a file on the terminal");
                let _ = writeln!(&mut terminal, "cd <directory>: change the working directory");
                let _ = writeln!(&mut terminal, "ls [directory]: List directory contents. Defaults to the current directory.");
                let _ = writeln!(&mut terminal, "pwd: Print name of the current/working directory");
                let _ = writeln!(&mut terminal, "meme1: Display the KFS-1 meme");
                let _ = writeln!(&mut terminal, "meme2: Display the KFS-2 meme");
                let _ = writeln!(&mut terminal, "meme3: Display the KFS-3 meme");
                let _ = writeln!(&mut terminal, "meme4: Display the KFS-4 meme");
                let _ = writeln!(&mut terminal, "meme5: Display the KFS-5 meme");
                let _ = writeln!(&mut terminal, "meme6: Display the KFS-6 meme");
                let _ = writeln!(&mut terminal, "memset: Display the KFS-7 meme");
                let _ = writeln!(&mut terminal, "test_threads: Run threads that concurrently print As and Bs");
                let _ = writeln!(&mut terminal, "test_divide_by_zero: Check exception handling by throwing a divide by zero");
                let _ = writeln!(&mut terminal, "test_page_fault: Check exception handling by throwing a page_fault");
            }
            _ => { let _ = writeln!(&mut terminal, "Unknown command"); }
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

/// Change the current working directory
fn cd(filesystem: &IFileSystemProxy, directory: &str) -> Result<(), Error> {
    let absolute_current_directory = get_path_relative_to_current_directory(directory);
    if absolute_current_directory.len() > 0x300 {
        return Err(FileSystemError::InvalidInput.into())
    }

    let mut ipc_path = [0x0; 0x300];
    ipc_path[..absolute_current_directory.as_bytes().len()].copy_from_slice(absolute_current_directory.as_bytes());


    filesystem.open_directory(3, &ipc_path)?;

    let mut current_directory = CURRENT_WORK_DIRECTORY.lock();
    *current_directory = absolute_current_directory;
    Ok(())
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

/// List files and folders at the given path, or in the current path is none is
/// given.
fn ls(mut terminal: &mut Terminal, filesystem: &IFileSystemProxy, orig_path: Option<&str>) -> Result<(), Error> {
    use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType};

    #[allow(clippy::missing_docs_in_private_items)]
    const BG: Color = Color::rgb(0, 0, 0);
    #[allow(clippy::missing_docs_in_private_items)]
    const FILE_FG: Color = Color::rgb(0x56, 0xF7, 0x68);
    #[allow(clippy::missing_docs_in_private_items)]
    const DIR_FG: Color = Color::rgb(0x68, 0x70, 0xF1);

    let path = orig_path.unwrap_or(".");
    let path = get_path_relative_to_current_directory(path);
    if path.len() > 0x300 {
        return Err(FileSystemError::InvalidInput.into())
    }

    let mut ipc_path = [0x0; 0x300];
    ipc_path[..path.as_bytes().len()].copy_from_slice(path.as_bytes());

    let directory = match filesystem.open_directory(3, &ipc_path) {
        Ok(d) => d,
        Err(Error::FileSystem(FileSystemError::NotADirectory, _)) => {
            terminal.print_attr(
                orig_path.unwrap_or(&CURRENT_WORK_DIRECTORY.lock()),
                FILE_FG, BG);
            let _ = writeln!(&mut terminal);
            return Ok(())
        },
        Err(err) => return Err(err)
    };

    let mut entries = [DirectoryEntry {
        path: [0; 0x300], attribute: 0,
        directory_entry_type: DirectoryEntryType::Directory, file_size: 0
    }; 6];
    loop {
        let count = directory.read(&mut entries)?;
        if count == 0 {
            break;
        }
        let entries = &entries[..count as usize];
        for entry in entries {
            let split_at = entry.path.iter().position(|v| *v == 0).unwrap_or(0x300);
            let prefix_len = if path == "/" {
                // The prefix to remove is literally just the leading `/`
                1
            } else {
                // The prefix to remove is the path + the trailing `/`.
                path.len() + 1
            };

            let mut s = String::from_utf8_lossy(&entry.path[prefix_len..split_at]).into_owned();
            s.push('\n');
            if entry.directory_entry_type == DirectoryEntryType::File {
                terminal.print_attr(&s, FILE_FG, BG);
            } else {
                terminal.print_attr(&s, DIR_FG, BG);
            };
        }
    }

    Ok(())
}

/// Shows a GIF in a new window, blocking the caller. When a key is pressed, the
/// window is closed and control is given back to the caller.
fn show_gif(louis: &[u8]) {
    let mut reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
    let mut window = Window::new(0, 0, u32::from(reader.width()), u32::from(reader.height())).unwrap();
    let mut buf = Vec::new();

    loop {
        {
            let end = reader.next_frame_info().unwrap().is_none();
            if end {
                reader = gif::Decoder::new(&louis[..]).read_info().unwrap();
                let _ = reader.next_frame_info().unwrap().unwrap();
            }
        }
        buf.resize(reader.buffer_size(), 0);
        // simulate read into buffer
        reader.read_into_buffer(&mut buf[..]).unwrap();
        for y in 0..(reader.height() as usize) {
            for x in 0..(reader.width() as usize) {
                let frame_coord = (y * reader.width() as usize + x) * 4;
                window.write_px_at(x, y, Color::rgb(buf[frame_coord], buf[frame_coord + 1], buf[frame_coord + 2]));
            }
        }
        window.draw().unwrap();
        if ps2::try_read_key().is_some() {
            return
        }
    }
}

/// Test function ensuring threads are working properly.
fn test_threads(terminal: Terminal) -> Terminal {
    #[doc(hidden)]
    fn thread_a(terminal: usize) {
        let terminal = unsafe {
            Arc::from_raw(terminal as *const Mutex<Terminal>)
        };
        let mut i = 0;
        while i < 10 {
            if let Some(mut lock) = terminal.try_lock() {
                let _ = writeln!(lock, "A");
                i += 1;
            }
            let _ = libuser::syscalls::sleep_thread(0);
        }
    }

    #[doc(hidden)]
    fn thread_b(terminal: usize) {
        // Wrap in a block to forcibly call Arc destructor before exiting the thread.
        {
            let terminal = unsafe {
                Arc::from_raw(terminal as *const Mutex<Terminal>)
            };
            let mut i = 0;
            while i < 10 {
                if let Some(mut lock) = terminal.try_lock() {
                    let _ = writeln!(lock, "B");
                    i += 1;
                }
                let _ = libuser::syscalls::sleep_thread(0);
            }
        }
    }

    let mut terminal = Arc::new(Mutex::new(terminal));

    let t = Thread::create(thread_b, Arc::into_raw(terminal.clone()) as usize, threads::DEFAULT_STACK_SIZE)
        .expect("Failed to create thread B");
    t.start()
        .expect("Failed to start thread B");

    // thread is running b, run a meanwhile
    thread_a(Arc::into_raw(terminal.clone()) as usize);

    // Wait for thread_b to terminate.
    loop {
        match Arc::try_unwrap(terminal) {
            Ok(terminal) => break terminal.into_inner(),
            Err(x) => terminal = x
        }
        let _ = libuser::syscalls::sleep_thread(0);
    }
}

/// Test function ensuring divide by zero interruption kills only the current
/// process.
fn test_divide_by_zero() {
    // don't panic, we want to actually divide by zero
    unsafe {
        asm!("
        mov eax, 42
        mov ecx, 0
        div ecx" :::: "volatile", "intel")
    }
}

/// Test function ensuring pagefaults kills only the current process.
fn test_page_fault() {
    // dereference the null pointer.
    // doing this in rust is so UB, it's optimized out, so we do it in asm.
    unsafe {
        asm!("
        mov al, [0]
        " ::: "eax" : "volatile", "intel")
    }
}

/// Meme for KFS1
static LOUIS1: &[u8] = include_bytes!("../img/meme1.gif");
/// Meme for KFS2
static LOUIS2: &[u8] = include_bytes!("../img/meme2.gif");
/// Meme for KFS3
static LOUIS3: &[u8] = include_bytes!("../img/meme3.gif");
/// Meme for KFS4
static LOUIS4: &[u8] = include_bytes!("../img/meme4.gif");
/// Meme for KFS5
static LOUIS5: &[u8] = include_bytes!("../img/meme5.gif");
/// Meme for KFS6
static LOUIS6: &[u8] = include_bytes!("../img/meme6.gif");
/// Meme for KFS7
static LOUIS7: &[u8] = include_bytes!("../img/meme7.gif");

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
    ],
    raw_caps: [libuser::caps::ioport(0x60), libuser::caps::ioport(0x64), libuser::caps::irq_pair(1, 0x3FF)]
});
