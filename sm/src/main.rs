#![feature(alloc)]
#![no_std]

extern crate libuser;
#[macro_use]
extern crate alloc;

use alloc::prelude::*;
use libuser::syscalls;
use libuser::types::*;

fn main() {
    let port = syscalls::manage_named_port("sm:\0", 0).unwrap();

    let mut sessions : Vec<ServerSession> = Vec::new();

    loop {
        match {
            let mut handles : Vec<HandleRef> = Vec::new();
            handles.push(port.0.as_ref());
            handles.extend(sessions.iter().map(|v| v.0.as_ref()));
            syscalls::wait_synchronization(&*handles, None).unwrap()
        } {
            0 => {
                sessions.push(port.accept().unwrap());
            },
            n => {
                syscalls::output_debug_string(&format!("Got wakeup on {}", n));
            }
        }
    }
}
