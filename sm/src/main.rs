#![feature(alloc)]
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
use libuser::error::Error;
use libuser::error::SmError;
use hashmap_core::map::{HashMap, Entry};
use spin::Mutex;

#[derive(Debug, Default)]
struct UserInterface;

lazy_static! {
    static ref SERVICES: Mutex<HashMap<u64, ClientPort>> = Mutex::new(HashMap::new());
}
// TODO: global event when services are accessed.

impl UserInterface {
    fn new() -> Self {
        UserInterface
    }
}

fn get_service_length(servicename: u64) -> usize{
    for i in 0..8 {
        if (servicename >> (8*i)) & 0xFF == 0 {
            return i;
        }
    }
    return 8;
}

fn get_service_str(servicename: &u64) -> &str {
    // TODO: Don't fail, return an error (invalid servicename or something).
    // TODO: Maybe I should use &[u8] instead?
    let len = get_service_length(*servicename);
    unsafe {
        core::str::from_utf8(core::slice::from_raw_parts(servicename as *const u64 as *const u8, len)).unwrap()
    }
}

object! {
    impl UserInterface {
        #[cmdid(0)]
        fn initialize(&mut self, pid: Pid,) -> Result<(), Error> {
            Ok(())
        }

        #[cmdid(1)]
        fn get_service(&mut self, servicename: u64,) -> Result<(Handle,), Error> {
            match SERVICES.lock().get(&servicename) {
                Some(port) => port.connect().map(|v| (v.into_handle(),)),
                None => Err(SmError::ServiceNotRegistered.into())
            }
        }

        #[cmdid(2)]
        fn register_service(&mut self, servicename: u64, is_light: u8, max_handles: u32,) -> Result<(Handle,), Error> {
            let (clientport, serverport) = syscalls::create_port(max_handles, is_light != 0, get_service_str(&servicename))?;
            match SERVICES.lock().entry(servicename) {
                Entry::Occupied(occupied) => Err(SmError::ServiceAlreadyRegistered.into()),
                Entry::Vacant(vacant) => {
                    vacant.insert(clientport);
                    Ok((serverport.0,))
                }
            }
        }

        #[cmdid(3)]
        fn unregister_service(&mut self, servicename: u64,) -> Result<(), Error> {
            match SERVICES.lock().remove(&servicename) {
                Some(_) => Ok(()),
                None => Err(SmError::ServiceNotRegistered.into())
            }
        }
    }
}

fn main() {
    let man = WaitableManager::new();
    let handler = Box::new(PortHandler::<UserInterface>::new_managed("sm:\0").unwrap());
    man.add_waitable(handler as Box<dyn IWaitable>);

    man.run();
}
