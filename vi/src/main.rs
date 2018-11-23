#![feature(alloc)]
#![no_std]

#[macro_use]
extern crate kfs_libuser as libuser;
#[macro_use]
extern crate alloc;
extern crate spin;
extern crate hashmap_core;
#[macro_use]
extern crate lazy_static;

use alloc::prelude::*;
use libuser::syscalls;
use libuser::ipc::server::{WaitableManager, PortHandler, IWaitable};
use libuser::types::*;
use hashmap_core::map::{HashMap, Entry};
use spin::Mutex;

enum Error {
    None = 0
}

impl Into<usize> for Error {
    fn into(self) -> usize {
        ((self as usize) << 9) | 0x21
    }
}

#[derive(Default)]
struct ViInterface;

object! {
    impl ViInterface {
        // TODO: Take some transfer memory
        #[cmdid(0)]
        fn create_buffer(&mut self, handle: Handle<copy>,) -> Result<(Handle,), usize> {
            /*let sharedmem = SharedMemory::from_raw(handle);
            addr = find_vaddr();
            sharedmem.map(addr);
            let buf = IBuffer {
                mem: addr,
            };
            let (server, client) = syscalls::create_session(false, 0);
            //session = SessionWrapper::new();*/
            Err(0xFC01)
        }
    }
}
/*
struct IBuffer {
    mem: usize // TODO: MappedSharedMemory type.
}

object! {
    impl IBuffer {
        #[cmdid(0)]
        fn draw(&mut self, ) -> Result<(), usize> {
            
        }
    }
}
*/
fn main() {
    let man = WaitableManager::new();
    let handler = Box::new(PortHandler::<ViInterface>::new("vi:\0").unwrap());
    man.add_waitable(handler as Box<dyn IWaitable>);

    man.run();
}
