//! IPC primitives
//!
//! Mostly lifted from the Nintendo Switch.
//! http://switchbrew.org/index.php?title=IPC_Marshalling contains documentation
//! for how it works on the official hardware. I'll try my best to explain the
//! ideas here.
//!
//! The switch IPC mechanism is separated with two main types, Ports and
//! Sessions, both having a client and a server side.
//!
//! # Ports
//!
//! A Port represents an endpoint which can be connected to. It is split in two
//! different part: ServerPort and ClientPort. The ClientPort has a `connect`
//! operation, while a ServerPort has an `accept` operation.
//!
//! The `connect` operations waits until a ServerPort calls `accept`. Similarly,
//! the `accept` operation waits until a ClientPort `connect`s. Once the two
//! operation meet, a `Session` is created. The `accept` operation will return a
//! `ServerSession`, while the `connect` operation returns a `ClientSession`.
//! Those two parts are connected.
//!
//! Additionally, a ServerPort implements the Waitable trait, allowing it to be
//! used with the `event::wait` function. TODO: The ClientPort should also
//! implement Waitable, I believe. In Horizon/NX, it implements KSynchronization.
//!
//! # Session
//!
//! A Session represents an established connection.
//!
//! # Usage
//!
//! First, you'll want to create a Port. This can be done through the svcCreatePort
//! syscall, or in the kernel from the Port::new() function.

use sync::{Once, SpinLock, RwLock};
use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicUsize, Ordering};
use scheduler;
use error::UserspaceError;
use event::{self, Waitable};
use hashmap_core::HashMap;
use process::ProcessStruct;

pub mod session;
pub mod port;

pub use self::session::*;
pub use self::port::*;

lazy_static! {
    // TODO: StringWrapper<[u8; 12]>
    static ref NAMED_PORTS: RwLock<HashMap<String, ClientPort>> = RwLock::new(HashMap::new());
}

pub fn create_named_port(name: [u8; 12], max_sessions: u32) -> Result<ServerPort, UserspaceError> {
    let name = match name.iter().position(|v| *v == 0) {
        Some(pos) => String::from_utf8_lossy(&name[..pos]),
        None => return Err(UserspaceError::ExceedingMaximum)
    };

    let (server, client) = port::new(max_sessions);
    NAMED_PORTS.write().insert(name.into_owned(), client);
    Ok(server)
}

pub fn connect_to_named_port(name: [u8; 12]) -> Result<ClientSession, UserspaceError> {
    let name = match name.iter().position(|v| *v == 0) {
        Some(pos) => String::from_utf8_lossy(&name[..pos]),
        None => return Err(UserspaceError::ExceedingMaximum)
    };

    match NAMED_PORTS.read().get(name.as_ref()) {
        Some(client) => Ok(client.connect()?),
        None => Err(UserspaceError::NoSuchEntry)
    }
}
