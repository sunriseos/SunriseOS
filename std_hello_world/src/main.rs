#[macro_use]
extern crate sunrise_libuser as libuser;

use std::time::SystemTime;
use std::fs::OpenOptions;
use std::io::Write;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

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
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

// TODO: Move this out of here
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
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::CreateSharedMemory,
        sunrise_libuser::syscalls::nr::MapSharedMemory,
        sunrise_libuser::syscalls::nr::UnmapSharedMemory,
    ]
});