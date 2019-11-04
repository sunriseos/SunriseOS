//! Disk Reporting utilitary
//!
//! Report file system disk space usage.

#![warn(unused)]
#![warn(missing_debug_implementations)]
#![allow(unused_unsafe)]
#![allow(unreachable_code)]
#![allow(dead_code)]
#![cfg_attr(test, allow(unused_imports))]
// rustdoc warnings
#![warn(missing_docs)] // hopefully this will soon become deny(missing_docs)
#![deny(intra_doc_link_resolution_failure)]

use std::os::sunrise::prelude::*;
use sunrise_libuser::fs::{IFileSystemProxy, IFileSystemServiceProxy, FileSystemType};

/// Translate a FileSystemType into a str.
fn get_filesystem_type(filesystem_type: FileSystemType) -> &'static str {
    match filesystem_type {
        FileSystemType::FAT12 => "fat12fs",
        FileSystemType::FAT16 => "fat16fs",
        FileSystemType::FAT32 => "fat32fs",
        FileSystemType::PackageFileSubmission => "packagefs",
        _ => "???"
    }
}

/// Print the information of a filesystem.
fn print_filesystem(filesystem : &IFileSystemProxy, disk_id: u32, partition_id: u32) {
    let unknown_info = String::from("???");
    let fs_type = filesystem.get_filesystem_type();

    let ipc_path = [0x0; 0x300];
    let free_space_size = filesystem.get_free_space_size(&ipc_path);
    let total_space_size = filesystem.get_total_space_size(&ipc_path);

    let free_space_size_str = match free_space_size {
        Ok(value) => value.to_string(),
        _ => unknown_info.clone()
    };
    let block_size_str = match total_space_size {
        Ok(value) => (value / 512).to_string(),
        _ => unknown_info.clone()
    };
    let total_space_size_str = match total_space_size {
        Ok(value) => value.to_string(),
        _ => unknown_info.clone()
    };
    let fs_type_str = match fs_type {
        Ok(value) => get_filesystem_type(value).to_string(),
        _ => unknown_info.clone()
    };

    println!("{}\t{}\t{}\t{}\t{}\t{}", fs_type_str, block_size_str, total_space_size_str, free_space_size_str, disk_id, partition_id);
}

/// The entry point of the program.
fn main() {
    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();

    let disk_count = fs_proxy.get_disks_count().unwrap();

    println!("Filesystem\t512B-block\tUsed\tAvailable\tDisk Id\tPartition Id");
    for disk_id in 0..disk_count {
        let mut partition_id = 0;
        while let Ok(filesystem) = fs_proxy.open_disk_partition(disk_id, partition_id) {
            print_filesystem(&filesystem, disk_id, partition_id);
            partition_id += 1
        }

        // The disk doesn't seems valid if we return here wihtout partition being incremneted
        if partition_id == 0 {
            break
        }
    }

}

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        nr::SleepThread,
        nr::ExitProcess,
        nr::CreateThread,
        nr::StartThread,
        nr::ExitThread,
        nr::CloseHandle,
        nr::WaitSynchronization,
        nr::OutputDebugString,
        nr::SetThreadArea,

        nr::ConnectToNamedPort,
        nr::SetHeapSize,
        nr::SendSyncRequestWithUserBuffer,
        nr::QueryMemory,
        nr::CreateSharedMemory,
        nr::MapSharedMemory,
        nr::UnmapSharedMemory,
    ]
});