//! Filesystem sysmodule
//!
//! High level access to filesystem and disks.
//!
//! NOTE: This need at least 16 pages of stack to run in debug builds because of bad codegen on the compiler side for libfat's iterators.

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

extern crate alloc;

#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate sunrise_libuser;
#[macro_use]
extern crate log;
#[macro_use]
extern crate static_assertions;

use sunrise_libuser::error::Error;
use sunrise_libuser::futures::WaitableManager;
use sunrise_libuser::fs::IFileSystemService;
use sunrise_libuser::ipc::server::port_handler;
use futures::future::FutureObj;

use alloc::boxed::Box;

mod detail;
mod interface;
mod ipc;

use detail::FileSystemProxy;
use detail::driver::DRIVER_MANAGER;
use interface::driver::FileSystemDriver;
use detail::driver::fat::FATDriver;

/// A libuser result.
pub type LibUserResult<T> = Result<T, Error>;

use crate::interface::filesystem::*;
use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType};

/// Do a directory listing at a given path.
fn print_dir(filesystem: &dyn FileSystemOperations, path: &str, level: u32, recursive: bool) -> LibUserResult<()>
{
    let mut root_dir = filesystem.open_directory(path, DirFilterFlags::ALL)?;

    let mut entries: [DirectoryEntry; 1] = [DirectoryEntry {
        path: [0x0; PATH_LEN],
        attribute: 0,
        directory_entry_type: DirectoryEntryType::Directory,
        file_size: 0,
    }; 1];

    while root_dir.read(&mut entries).unwrap() != 0 {
        for entry in &entries {
            let path = core::str::from_utf8(&entry.path).unwrap();
            let entry_name = path.trim_matches(char::from(0));

            /*for _ in 0..level {
                print!("    ");
            }*/

            info!(
                "- \"{}\" (type: {:?}, file_size: {}, timestamp: {:?})",
                entry_name,
                entry.directory_entry_type,
                entry.file_size,
                filesystem.get_file_timestamp_raw(entry_name)
            );

            if entry.directory_entry_type == DirectoryEntryType::Directory && recursive {
                print_dir(filesystem, entry_name, level + 1, recursive)?;
            }
        }
    }

    Ok(())
}

fn main() {
    info!("Hello World");

    {
        let mut driver_manager = DRIVER_MANAGER.lock();
        driver_manager.register_driver(Box::new(FATDriver) as Box<dyn FileSystemDriver>);
        driver_manager.init_drives().unwrap();
    }

    info!("Hello World");

    let mut fs_proxy: FileSystemProxy = FileSystemProxy::default();
    //fs_proxy.initialize_disk(0).unwrap();
    //fs_proxy.format_disk_partition(0, 0, FileSystemType::FAT32).unwrap();
    let filesystem = fs_proxy.open_disk_partition(0, 0).unwrap();
    print_dir(filesystem.lock().as_operations(), "/", 0, true).unwrap();

    let mut man = WaitableManager::new();
    let handler = port_handler(man.work_queue(), "fsp-srv\0", ipc::FileSystemService::dispatch).unwrap();;
    man.work_queue().spawn(FutureObj::new(Box::new(handler)));
    man.run();
}

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::SetThreadArea,

        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,
        sunrise_libuser::syscalls::nr::CreateSession,
        sunrise_libuser::syscalls::nr::QueryMemory,
    ]
});
