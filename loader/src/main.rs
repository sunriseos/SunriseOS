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
//! - /bin/<titlename>
//!   - main
//!   - main.npdm
//!   - flags/
//!     - boot.flag

#![feature(async_await)]
#![no_std]

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;

use core::str;
use core::slice;
use core::mem::size_of;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType, FileSystemPath, IFileSystemProxy, IFileSystemServiceProxy};
use sunrise_libuser::{kip_header, capabilities};
use sunrise_libuser::ipc::server::{port_handler};
use sunrise_libuser::futures::{WaitableManager, WorkQueue};
use sunrise_libuser::error::{Error, LoaderError, PmError, KernelError};
use sunrise_libuser::ldr::ILoaderInterfaceAsync;
use sunrise_libuser::syscalls::{self, map_process_memory};
use sunrise_libuser::types::{Pid, Process};
use sunrise_libkern::process::*;
use sunrise_libkern::MemoryPermissions;
use sunrise_libuser::mem::{find_free_address, PAGE_SIZE};
use sunrise_libutils::{align_up, div_ceil};

use sunrise_libuser::futures_rs::future::FutureObj;
use lazy_static::lazy_static;

use spin::Mutex;

mod elf_loader;

/// Max size of an ELF before we issue a warning. Loader needs to keep its
/// memory usage fairly low to avoid trouble, so we bail upon trying to load a
/// file bigger than 128MiB.
const MAX_ELF_SIZE: u64 = 128 * 1024 * 1024;

lazy_static! {
    static ref PROCESSES: Mutex<BTreeMap<u64, Process>> = Mutex::new(BTreeMap::new());
}

/// Start the given titleid by loading its content from the provided filesystem.
fn boot(fs: &IFileSystemProxy, titlename: &str, args: &[u8]) -> Result<Pid, Error> {
    info!("Booting titleid {}", titlename);

    let val = format!("/bin/{}/main", titlename);
    let mut raw_path: FileSystemPath = [0; 0x300];
    (&mut raw_path[0..val.len()]).copy_from_slice(val.as_bytes());
    let file = fs.open_file(1, &raw_path)?;

    let size = file.get_size()?;

    if size > MAX_ELF_SIZE {
        error!("Why is titleid {} so ridiculously huge? It's {} bytes.
        Like, seriously, stop with the gifs!", titlename, size);
        return Err(LoaderError::InvalidElf.into());
    }

    let mut cur_offset = 0;

    // Ensure we have a properly aligned buffer to avoid pathological worse-case
    // scenario in ahci.
    let mut elf_data = vec![0; size as usize + 1];
    let elf_data = if elf_data.as_ptr() as usize % 2 == 0 {
        &mut elf_data[0..size as usize]
    } else {
        &mut elf_data[1..=size as usize]
    };
    while cur_offset < size {
        let read_count = file.read(0, cur_offset, size - cur_offset, &mut elf_data[cur_offset as usize..])?;
        if read_count == 0 {
            error!("Unexpected end of file while reading /bin/{}/main", titlename);
            return Err(LoaderError::InvalidElf.into());
        }
        cur_offset += read_count;
    }

    let elf = elf_loader::from_data(&elf_data)?;

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
            error!("TitleID {} did not have a KAC section. Bailing.", titlename);
            return Err(LoaderError::InvalidKacs.into());
        }
    };

    let mut titlename_bytes = [0; 12];
    let titlename_len = core::cmp::min(titlename.len(), titlename_bytes.len());
    titlename_bytes[..titlename_len].copy_from_slice(
        titlename[..titlename_len].as_bytes());

    let elf_size = elf_loader::get_size(&elf)?;

    // Note: this calculation seems very, very, **very** wrong in Atmosphere.
    // https://github.com/Atmosphere-NX/Atmosphere/blob/93d83c5/stratosphere/loader/source/ldr_process_creation.cpp#L495
    //
    // Like, wtf is this. So we do our own, based on our usage. See
    // libuser::argv for more info.
    let args_size = args.len() * 2 + 0x20;
    let args_size = align_up(args_size, size_of::<usize>());
    // Add a whole page for the vector of ptrs.
    let args_size = args_size + 0x1000 / size_of::<usize>();
    let args_size = align_up(args_size, PAGE_SIZE);

    let total_size = elf_size + align_up(args_size, PAGE_SIZE);

    let process = sunrise_libuser::syscalls::create_process(&ProcInfo {
        name: titlename_bytes,
        process_category: ProcessCategory::RegularTitle,
        title_id: 0,
        code_addr: aslr_base as _,
        code_num_pages: div_ceil(total_size, PAGE_SIZE) as u32,
        flags,
        resource_limit_handle: None,
        system_resource_num_pages: 0,
    }, &kacs)?;

    debug!("Loading ELF");
    elf_loader::load_file(&process, &elf, aslr_base)?;

    debug!("Handling args");
    let addr = find_free_address(args_size, 0x1000)?;
    map_process_memory(addr, &process, aslr_base + elf_size, args_size)?;

    {
        // Copy the ELF data in the remote process.
        let dest_ptr = addr as *mut u8;
        let dest = unsafe {
            // Safety: Guaranteed to be OK if the syscall returns successfully.
            slice::from_raw_parts_mut(dest_ptr, args_size)
        };
        // Copy header
        dest[0..4].copy_from_slice(&args_size.to_le_bytes());
        dest[4..8].copy_from_slice(&args.len().to_le_bytes());
        // Copy raw cmdline.
        dest[0x20..0x20 + args.len()].copy_from_slice(args);
    }

    // Maybe I should panic if this fails, cuz that'd be really bad.
    unsafe {
        // Safety: this memory was previously mapped and all pointers to it
        // should have been dropped already.
        syscalls::unmap_process_memory(addr, &process, aslr_base + elf_size, args_size)?;
    }

    syscalls::set_process_memory_permission(&process, aslr_base + elf_size, args_size, MemoryPermissions::RW)?;

    debug!("Starting process.");
    if let Err(err) = process.start(0, 0, PAGE_SIZE as u32 * 32) {
        error!("Failed to start titleid {}: {}", titlename, err);
        return Err(err)
    }

    let pid = process.pid()?;
    PROCESSES.lock().insert(pid.0, process);

    Ok(pid)
}

lazy_static! {
    /// The filesystem to boot titles from.
    static ref BOOT_FROM_FS: IFileSystemProxy = {
        let fs_proxy = IFileSystemServiceProxy::raw_new().unwrap();
        fs_proxy.open_disk_partition(0, 0).unwrap()
    };
}

/// Struct implementing the ldr:shel service.
#[derive(Debug, Default, Clone)]
struct LoaderIface;

impl ILoaderInterfaceAsync for LoaderIface {
    fn launch_title(&mut self, _workqueue: WorkQueue<'static>, title_name: &[u8], args: &[u8]) -> FutureObj<'_, Result<u64, Error>> {
        let res = (|| -> Result<u64, Error> {
            let title_name = str::from_utf8(title_name).or(Err(LoaderError::ProgramNotFound))?;
            let Pid(pid) = boot(&*BOOT_FROM_FS, title_name, args)?;
            Ok(pid)
        })();
        FutureObj::new(Box::new(async move {
            res
        }))
    }

    fn wait(&mut self, workqueue: WorkQueue<'static>, pid: u64) -> FutureObj<'_, Result<u32, Error>> {
        FutureObj::new(Box::new(async move {
            // Weird logic: we create an as_ref_static process, and then we'll
            // relock PROCESSES each time we want a process to reset signal and
            // stuff. This kinda sucks.
            //
            // TODO: Unify Handle/HandleRef behind a single trait.
            // BODY: The fact I have to do this makes me think there's really a
            // BODY: problem in the handle/handleref design. Maybe there should be a
            // BODY: trait unifying Handle/HandleRef, and `Process` and co should be
            // BODY: generic on those? That would allow me to call the functions on
            // BODY: "borrowed lifetime-erased" handles.
            // BODY:
            // BODY: This trait could probably be AsRef or Borrow. Ideally the
            // BODY: generic types would be an internal implementation details
            // BODY: and we'd just expose "Process" and "ProcessBorrowed" types
            // BODY: through typedef/newtypes. Needs a lot of thought.
            let process_wait = (PROCESSES.lock().get(&pid)
                .ok_or(PmError::PidNotFound)?.0).as_ref_static();
            loop {
                process_wait.wait_async(workqueue.clone()).await?;
                let mut lock = PROCESSES.lock();
                let process = lock.get(&pid)
                    .ok_or(PmError::PidNotFound)?;
                match process.reset_signal() {
                    Ok(()) | Err(Error::Kernel(KernelError::InvalidState, _)) => (),
                    Err(err) => return Err(err)
                };

                if process.state()? == ProcessState::Exited {
                    lock.remove(&pid);
                    // TODO: Return exit state.
                    return Ok(0);
                }
            }
        }))
    }
}

fn main() {
    let fs = &*BOOT_FROM_FS;

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
            let count = directory.read(&mut entries).unwrap_or_else(|err| {
                error!("Failed to read directory: {:?}", err);
                0
            });
            if count == 0 {
                break;
            }
            let entries = &mut entries[..count as usize];
            for entry in entries {
                raw_path = entry.path;
                let endpos = raw_path.iter().position(|v| *v == 0).unwrap_or_else(|| raw_path.len());
                if endpos > 0x300 - 16 {
                    error!("Path too big in /bin.");
                    continue;
                }
                raw_path[endpos..endpos + 16].copy_from_slice(b"/flags/boot.flag");
                if fs.get_entry_type(&raw_path).is_ok() {
                    let endpos = entry.path.iter()
                        .enumerate()
                        .skip(5)
                        .find(|(_, v)| **v == b'/' || **v == b'\0')
                        .map(|(idx, _)| idx).unwrap_or_else(|| entry.path.len());
                    if let Ok(titleid) = str::from_utf8(&entry.path[5..endpos]) {
                        let _ = boot(&fs, titleid, &[]);
                    } else {
                        error!("Non-ASCII titleid found in /boot.");
                        continue;
                    }
                }
            }
        }
    } else {
        warn!("No /bin folder on filesystem!");
    }

    let mut man = WaitableManager::new();

    let handler = port_handler(man.work_queue(), "ldr:shel", LoaderIface::dispatch).unwrap();
    man.work_queue().spawn(FutureObj::new(Box::new(handler)));

    man.run();
}

kip_header!(HEADER = sunrise_libuser::caps::KipHeader {
    magic: *b"KIP1",
    name: *b"loader\0\0\0\0\0\0",
    title_id: 0x0200000000000001,
    process_category: sunrise_libuser::caps::ProcessCategory::KernelBuiltin,
    main_thread_priority: 0,
    default_cpu_core: 0,
    flags: 0,
    reserved: 0,
    stack_page_count: 16,
});

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

        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,

        sunrise_libuser::syscalls::nr::CreateProcess,
        sunrise_libuser::syscalls::nr::MapProcessMemory,
        sunrise_libuser::syscalls::nr::UnmapProcessMemory,
        sunrise_libuser::syscalls::nr::SetProcessMemoryPermission,
        sunrise_libuser::syscalls::nr::StartProcess,

        sunrise_libuser::syscalls::nr::GetProcessInfo,
        sunrise_libuser::syscalls::nr::GetProcessId,
        sunrise_libuser::syscalls::nr::ResetSignal,
    ],
    raw_caps: [sunrise_libuser::caps::ioport(0x60), sunrise_libuser::caps::ioport(0x64), sunrise_libuser::caps::irq_pair(1, 0x3FF)]
});