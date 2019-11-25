//! Simple program used to test Sunrise's libstd

#[macro_use]
extern crate sunrise_libuser as libuser;

use std::time::SystemTime;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use std::fs::{self, DirEntry};
use std::path::Path;
use std::thread;
use std::env;

use std::process::Command;

/// One possible implementation of walking a directory only visiting files.
fn visit_dirs(dir: &Path, cb: &dyn Fn(&DirEntry)) -> io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit_dirs(&path, cb)?;
            } else {
                cb(&entry);
            }
        }
    }
    Ok(())
}

/// Callback used in visit_dirs to print directory entries.
fn print_entry(entry: &DirEntry) {
    println!("{:?}", entry);
}

/// The entry point of the program.
fn main() {
    println!("Hello from main");

    let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .append(true)
            .create(true)
            .open("system:/test.txt").unwrap();
    file.write_all(b"Hello world!\n").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut buffer = String::new();

    file.read_to_string(&mut buffer).unwrap();

    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => println!("1970-01-01 00:00:00 UTC was {} seconds ago!", n.as_secs()),
        _ => panic!("SystemTime before UNIX EPOCH!"),
    }

    println!("{:?}", fs::metadata(Path::new("system:/etc")).map(|m| m.is_dir()));
    visit_dirs(Path::new("/"), &print_entry).unwrap();

    let thread_spawned = thread::spawn(|| {
        println!("Hello from spawned thread");
    });

    thread_spawned.join().unwrap();
    println!("Hello from main thread");

    println!("Arguments:");
    // Prints each argument on a separate line
    for argument in env::args() {
        println!("{}", argument);
    }

    println!("Environment Variables:");
    // Prints each environment variable on a separate line
    for (k, v) in env::vars() {
        println!("{}={}", k, v);
    }

    if env::args().nth(0).is_none() {
        println!("Spawning ourself with some arguments!");
        Command::new("std_hello_world")
                .arg("Hey")
                .arg("You")
                .spawn()
                .expect("std_hello_world command failed to start")
                .wait()
                .expect("std_hello_world command wait failed");
        println!("Child process is dead!");
    }

    println!("Job done");

}

// TODO: Move this out of here
kip_header!(HEADER = sunrise_libuser::caps::KipHeader {
    magic: *b"KIP1",
    name: *b"std_hellowor",
    title_id: 0x0200000000001060,
    process_category: sunrise_libuser::caps::ProcessCategory::KernelBuiltin,
    main_thread_priority: 0,
    default_cpu_core: 0,
    flags: 0,
    reserved: 0,
    stack_page_count: 16,
});

// TODO: Move this out of here
capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CreateThread,
        sunrise_libuser::syscalls::nr::StartThread,
        sunrise_libuser::syscalls::nr::ExitThread,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::SetThreadArea,

        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::CreateSharedMemory,
        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,
    ]
});
