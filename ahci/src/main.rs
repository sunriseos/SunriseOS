//! TODO: Write some AHCI documentation
#![feature(alloc, const_let)]
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
extern crate kfs_libuser;
#[macro_use]
extern crate log;

mod pci;

fn main() {
    info!("Hello, world!");
    let ahci_devices_list = pci::get_ahci_controllers();
    info!("AHCI devices : {:#x?}", ahci_devices_list);
}

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        kfs_libuser::syscalls::nr::SleepThread,
        kfs_libuser::syscalls::nr::ExitProcess,
        kfs_libuser::syscalls::nr::CloseHandle,
        kfs_libuser::syscalls::nr::WaitSynchronization,
        kfs_libuser::syscalls::nr::OutputDebugString,

        kfs_libuser::syscalls::nr::SetHeapSize,
        kfs_libuser::syscalls::nr::QueryMemory,
        kfs_libuser::syscalls::nr::MapSharedMemory,
        kfs_libuser::syscalls::nr::UnmapSharedMemory,
        kfs_libuser::syscalls::nr::ConnectToNamedPort,
        kfs_libuser::syscalls::nr::CreateInterruptEvent,
    ],
    raw_caps: [
        kfs_libuser::caps::ioport(pci::CONFIG_ADDRESS + 0), kfs_libuser::caps::ioport(pci::CONFIG_ADDRESS + 1), kfs_libuser::caps::ioport(pci::CONFIG_ADDRESS + 2), kfs_libuser::caps::ioport(pci::CONFIG_ADDRESS + 3),
        kfs_libuser::caps::ioport(pci::CONFIG_DATA    + 0), kfs_libuser::caps::ioport(pci::CONFIG_DATA    + 1), kfs_libuser::caps::ioport(pci::CONFIG_DATA    + 2), kfs_libuser::caps::ioport(pci::CONFIG_DATA    + 3),
    ]
});
