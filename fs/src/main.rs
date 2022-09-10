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
#![deny(rustdoc::broken_intra_doc_links)]

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
use sunrise_libuser::futures_rs::future::FutureObj;

use alloc::boxed::Box;

mod detail;
mod interface;
mod ipc;

use detail::driver::DRIVER_MANAGER;
use interface::driver::FileSystemDriver;
use detail::driver::fat::FATDriver;

/// A libuser result.
pub type LibUserResult<T> = Result<T, Error>;

fn main() {
    {
        let mut driver_manager = DRIVER_MANAGER.lock();
        driver_manager.register_driver(Box::new(FATDriver) as Box<dyn FileSystemDriver>);
        driver_manager.init_drives().unwrap();
    }

    //let mut fs_proxy: FileSystemProxy = FileSystemProxy::default();
    //fs_proxy.initialize_disk(0).unwrap();
    //fs_proxy.format_disk_partition(0, 0, FileSystemType::FAT32).unwrap();

    let mut man = WaitableManager::new();
    let handler = port_handler(man.work_queue(), "fsp-srv\0", ipc::FileSystemService::dispatch).unwrap();
    man.work_queue().spawn(FutureObj::new(Box::new(handler)));
    man.run();
}

kip_header!(HEADER = sunrise_libuser::caps::KipHeader {
    magic: *b"KIP1",
    name: *b"fs\0\0\0\0\0\0\0\0\0\0",
    title_id: 0x0200000000000000,
    process_category: sunrise_libuser::caps::ProcessCategory::KernelBuiltin,
    main_thread_priority: 0,
    default_cpu_core: 0,
    flags: 0,
    reserved: 0,
    stack_page_count: 32,
});

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
