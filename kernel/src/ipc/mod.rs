//! IPC primitives
//!
//! Mostly lifted from the Nintendo Switch.
//! http://switchbrew.org/index.php?title=IPC_Marshalling contains documentation
//! for how it works on the official hardware. I'll try my best to explain the
//! ideas here.
//!
//! The switch IPC mechanism is separated with two main types, Ports and
//! Sessions, both having a client and a server side. A port is used to establish
//! a Session.
//!
//! # Ports
//!
//! A Port represents an endpoint which can be connected to, in order to
//! establish a Session. It is split in two different part: ServerPort and
//! ClientPort. The ClientPort has a `connect` operation, while a ServerPort has
//! an `accept` operation.
//!
//! Those work as a rendez-vous, meaning both operations wait for each-other:
//! The `connect` operation blocks until a ServerPort calls `accept`. Similarly,
//! the `accept` operation waits until a ClientPort `connect`s. Once the two
//! operation meet, a `Session` is created. The `accept` operation will return a
//! `ServerSession`, while the `connect` operation returns a `ClientSession`.
//!
//! Additionally, a ServerPort implements the Waitable trait, allowing it to be
//! used with the `event::wait` function. This will wait until the associated
//! ClientPort had its connect operation called. TODO: The ClientPort should also
//! implement Waitable, I believe. In Horizon/NX, it implements KSynchronization.
//!
//! ```rust
//! let (server, client) = Port::new();
//! let client_sess = client.connect();
//! // In a separate thread
//! let server_sess = server.accept();
//! ```
//!
//! # Session
//!
//! A Session represents an established connection. It is split in two different
//! part: ServerSession and ClientSession. The ClientSession has a `send_request`
//! operation (with various variants), while a ClientSession has a `reply` and a
//! `receive` operation (again, with various variants).
//!
//! ServerSession implements the Waitable trait, allowing it to be used with the
//! `event::wait` function. TODO: The ClientSession should also implement Waitable.
//!
//! ```rust
//! use kernel::ipc::session;
//! let (server, client) = session::new();
//! 
//! ```
//!
//! # Managed Ports
//!
//! Sessions and Ports are cool, but we're lacking some kind of entrypoint: In
//! order to do IPC, we need a handle to another service's ClientPort. But we
//! have no such handle when starting a process!
//!
//! To fix this, the kernel has a global registry of ports. Such ports are called
//! "Managed Ports". In a normal userland, only one service (the Service Manager)
//! would register themselves as a Managed Port, but the kernel allows any number
//! of those to be registered at any given time, so long as each has a unique
//! name.
//!
//! Managed Ports aren't very special, the only difference is the syscalls used
//! to interact with them: You can register a managed port, which returns a
//! ServerPort handle, and you can connect to a managed port, which returns a
//! ClientSession handle.
//!
//! ```
//! use kernel::ipc;
//! let serverport = ipc::create_named_port(b"test\0\0\0\0\0\0\0\0")?;
//! loop {
//!     let serversess = serverport.accept()?;
//! }
//! // In another thread
//! let clientsess = ipc::connect_to_named_port(b"test\0\0\0\0\0\0\0\0\0\0\0\0")?;
//! ```

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

pub use self::session::{ClientSession, ServerSession};
pub use self::port::{ClientPort, ServerPort};

lazy_static! {
    // TODO: StringWrapper<[u8; 12]>
    static ref NAMED_PORTS: RwLock<HashMap<String, ClientPort>> = RwLock::new(HashMap::new());
}

/// Creates a named port.
///
/// Registers a new named port. Name should contain a \0 delimiting the end of
/// the string.
///
/// # Errors
///
/// Returns ExceedingMaximum if the name doesn't contain a \0.
pub fn create_named_port(name: [u8; 12], max_sessions: u32) -> Result<ServerPort, UserspaceError> {
    let name = match name.iter().position(|v| *v == 0) {
        Some(pos) => String::from_utf8_lossy(&name[..pos]),
        None => return Err(UserspaceError::ExceedingMaximum)
    };

    let (server, client) = port::new(max_sessions);
    NAMED_PORTS.write().insert(name.into_owned(), client);
    Ok(server)
}

/// Connects to a named port.
///
/// Returns a new ClientSession. Note that this is a blocking call that
/// rendez-vous with the associated ServerPort. In other words, it waits until
/// the associated ServerPort calls accept.
///
/// # Errors
///
/// Returns ExceedingMaximum if the name doesn't contain a \0.
///
/// Returns NoSuchEntry if the associated Named Port is not registered.
///
/// Returns PortRemoteDead if all handles to the associated ServerPort are
/// closed.
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
