#![feature(alloc)]
#![no_std]

#[macro_use]
extern crate libuser;
#[macro_use]
extern crate alloc;
extern crate spin;
extern crate hashmap_core;
#[macro_use]
extern crate lazy_static;

use alloc::prelude::*;
use libuser::syscalls;
use libuser::ipc::Pid;
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

struct ViInterface {
    mapping: HashMap<usize, usize>,
    curhandle: usize,
}

impl ViInterface {
    fn new() -> Self {
        ViInterface {
            mapping: HashMap::new(),
            curhandle: 0
        }
    }
}

object! {
    impl ViInterface {
        // TODO: Take some transfer memory
        #[cmdid(0)]
        fn create_buffer(&mut self,) -> Result<(), usize> {
            Ok(())
        }
    }
}

fn main() {
    let man = WaitableManager::new();
    let handler = Box::new(PortHandler::<ViInterface>::new("vi:\0").unwrap());
    man.add_waitable(handler as Box<dyn IWaitable>);

    man.run();
}
