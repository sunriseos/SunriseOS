//! # Userspace Loader
//!
//! This binary is responsible for all the steps involved in starting an
//! application, creating the kernel process, loading the binary, passing the
//! arguments, and finally starting it.
//!
//! Under HOS/NX, processes are started through `pm:shell`'s LaunchTitle, which
//! will ask `ldr:pm`'s CreateProcess to do the actual process creation. The
//! loader will then use `fsp-ldr`'s OpenCodeFileSystem to find the binary and
//! signature, validate all the signatures and whatnot, and create + load the
//! binary in a new process. The boot sysmodule is responsible for starting the
//! initial process, by asking PM:shell to start them.
//!
//! We will handle things slightly differently: PM and Loader will both live
//! together under the same loader binary. Instead of using `fsp-ldr`, we will
//! look for binaries in the filesystem's `/bin`, using the following hierarchy:
//!
//! - /bin/<titleid>
//!   - main
//!   - main.npdm
//!   - flags/
//!     - boot.flag

#![no_std]

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;

use core::str;
use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType, FileSystemPath, IFileSystemProxy, IFileSystemServiceProxy};
use sunrise_libuser::capabilities;
use sunrise_libkern::process::*;
use sunrise_libuser::mem::PAGE_SIZE;
use sunrise_libutils::div_ceil;

mod elf_loader;

/// Max size of an ELF before we issue a warning. Loader needs to keep its
/// memory usage fairly low to avoid trouble, so we bail upon trying to load a
/// file bigger than 128MiB.
const MAX_ELF_SIZE: u64 = 128 * 1024 * 1024;

/// Start the given titleid by loading its content from the provided filesystem.
fn boot(fs: &IFileSystemProxy, titleid: u64) {
    info!("Booting titleid {:016x}", titleid);

    let val = format!("/bin/{:016x}/main", titleid);
    let mut raw_path: FileSystemPath = [0; 0x300];
    (&mut raw_path[0..val.len()]).copy_from_slice(val.as_bytes());
    let file = fs.open_file(1, &raw_path).unwrap_or_else(|error| panic!("Expected open_file('/bin') to work: {:?}", error));

    let size = file.get_size().expect("get_size to work");

    if size > MAX_ELF_SIZE {
        error!("Why is titleid {:016x} so ridiculously huge? It's {} bytes.
        Like, seriously, stop with the gifs!", titleid, size);
        return;
    }

    let mut cur_offset = 0;
    let mut elf_data = vec![0; size as usize + 1];
    let mut elf_data = if elf_data.as_ptr() as usize % 2 == 0 {
        &mut elf_data[0..size as usize]
    } else {
        &mut elf_data[1..=size as usize]
    };
    while cur_offset < size {
        let read_count = file.read(0, cur_offset, size - cur_offset, &mut elf_data).expect("Read to work");
        if read_count == 0 {
            panic!("Unexpected end of file while reading /bin/{:016x}/main", titleid);
        }
        cur_offset += read_count;
    }

    let elf = elf_loader::from_data(&elf_data);

    let mut flags = ProcInfoFlags(0);
    flags.set_64bit(false);
    flags.set_address_space_type(ProcInfoAddrSpace::AS32Bit);
    flags.set_debug(true);
    flags.set_aslr(false);
    flags.set_application(true);

    let aslr_base = 0x400000;

    let kacs = match elf_loader::get_kacs(&elf) {
        Some(kacs) => kacs,
        None => {
            error!("TitleID {:016x} did not have a KAC section. Bailing.", titleid);
            return;
        }
    };

    let process = sunrise_libuser::syscalls::create_process(&ProcInfo {
        name: *b"Application\0",
        process_category: ProcessCategory::RegularTitle,
        title_id: titleid,
        code_addr: aslr_base as _,
        code_num_pages: div_ceil(elf_loader::get_size(&elf), PAGE_SIZE) as u32,
        flags,
        resource_limit_handle: None,
        system_resource_num_pages: 0,
    }, &kacs).expect("CreateProcess to work flawlessly");

    debug!("Loading ELF");
    elf_loader::load_builtin(&process, &elf, aslr_base);

    debug!("Starting process.");
    if let Err(err) = process.start(0, 0, PAGE_SIZE as u32 * 16) {
        error!("Failed to start titleid {:016x}: {}", titleid, err)
    }
}

fn main() {
    let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
    let fs = fs_proxy.open_disk_partition(0, 0).unwrap();

    let mut raw_path: FileSystemPath = [0; 0x300];
    (&mut raw_path[0..4]).copy_from_slice(b"/bin");

    if let Ok(directory) = fs.open_directory(1, &raw_path) {
        let mut entries: [DirectoryEntry; 12] = [DirectoryEntry {
            path: [0; 0x300],
            attribute: 0,
            directory_entry_type: DirectoryEntryType::Directory,
            file_size: 0
        }; 12];
        loop {
            let count = directory.read(&mut entries).unwrap();
            if count == 0 {
                break;
            }
            let entries = &mut entries[..count as usize];
            for entry in entries {
                raw_path = entry.path;
                let endpos = raw_path.iter().position(|v| *v == 0).unwrap_or(301);
                raw_path[endpos..endpos + 16].copy_from_slice(b"/flags/boot.flag");
                if fs.get_entry_type(&raw_path).is_ok() {
                    let endpos = entry.path.iter()
                        .enumerate()
                        .skip(5)
                        .find(|(_, v)| **v == b'/' || **v == b'\0')
                        .map(|(idx, _)| idx).unwrap_or_else(|| entry.path.len());
                    let titleid = &entry.path[5..endpos];
                    let titleid = str::from_utf8(titleid).unwrap();
                    let titleid = u64::from_str_radix(titleid, 16).unwrap();
                    boot(&fs, titleid);
                }
            }
        }
    } else {
        warn!("No /bin folder on filesystem!");
    }
}

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::SetThreadArea,

        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,

        sunrise_libuser::syscalls::nr::CreateProcess,
        sunrise_libuser::syscalls::nr::MapProcessMemory,
        sunrise_libuser::syscalls::nr::UnmapProcessMemory,
        sunrise_libuser::syscalls::nr::SetProcessMemoryPermission,
        sunrise_libuser::syscalls::nr::StartProcess,
    ],
    raw_caps: [sunrise_libuser::caps::ioport(0x60), sunrise_libuser::caps::ioport(0x64), sunrise_libuser::caps::irq_pair(1, 0x3FF)]
});