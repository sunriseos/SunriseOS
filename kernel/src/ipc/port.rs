use scheduler;
use alloc::vec::Vec;
use alloc::sync::{Arc, Weak};
use sync::{Once, SpinLock, RwLock};
use error::{KernelError, UserspaceError};
use event::{self, Waitable};
use process::ProcessStruct;
use core::sync::atomic::{AtomicUsize, Ordering};
use hashmap_core::HashMap;
use alloc::prelude::*;
use ipc::session::*;

/// An endpoint which can be connected to.
#[derive(Debug)]
pub struct Port {
    incoming_connections: SpinLock<Vec<Arc<IncomingConnection>>>,
    accepters: SpinLock<Vec<Weak<ProcessStruct>>>,
    servercount: AtomicUsize,
}

/// The client side of a Port.
///
/// This side can call connect().
#[derive(Debug, Clone)]
pub struct ClientPort(Arc<Port>);

/// The server side of a Port.
///
/// This is necessary for accepting connections on a port. Its only operation
/// is accept(), which returns a ServerSession.
#[derive(Debug, Clone)]
pub struct ServerPort(Arc<Port>);

impl Port {
    /// Creates a new port. This port may only have _max_sessions sessions active at
    /// a given time.
    pub fn new(_max_sessions: u32) -> (ServerPort, ClientPort) {
        let port = Arc::new(Port {
            servercount: AtomicUsize::new(0),
            incoming_connections: SpinLock::new(Vec::new()),
            accepters: SpinLock::new(Vec::new())
        });
        (Port::server(port.clone()), Port::client(port.clone()))
    }

    /// Returns a ClientPort from this Port.
    pub fn client(this: Arc<Self>) -> ClientPort {
        ClientPort(this)
    }

    /// Returns a ServerPort from this Port.
    pub fn server(this: Arc<Self>) -> ServerPort {
        this.servercount.fetch_add(1, Ordering::SeqCst);
        ServerPort(this)
    }
}

// Wait for a connection to become available.
impl Waitable for ServerPort {
    fn is_signaled(&self) -> bool {
        !self.0.incoming_connections.lock().is_empty()
    }

    fn register(&self) {
        self.0.accepters.lock().push(Arc::downgrade(&scheduler::get_current_process()));
    }
}

impl Drop for ServerPort {
    fn drop(&mut self) {
        assert!(self.0.servercount.fetch_sub(1, Ordering::SeqCst) != 0, "Overflow when decrementing servercount");
    }
}

#[derive(Debug)]
pub struct IncomingConnection {
    session: SpinLock<Option<Arc<Session>>>,
    creator: Arc<ProcessStruct>
}

impl ServerPort {
    /// Accept a new connection on the Port.
    pub fn accept(&self) -> Result<ServerSession, UserspaceError> {
        loop {
            // Wait for incoming_connections to contain a connection.
            let _ = event::wait(Some(self as &dyn Waitable))?;

            // Acquire the connection.
            while let Some(incoming) = self.0.incoming_connections.lock().pop() {
                let mut lock = incoming.session.lock();

                // Check if it was already handled by another accepter!
                // This shouldn't happen since we pop it from the queue above.
                assert!(lock.is_none(), "Handled connection request still in incoming conn queue.");

                // We can associate a session to this now.
                let sess = Session::new();
                *lock = Some(sess.clone());

                // Wake up the creator.
                // **VERY IMPORTANT**: This should be done with the LOCK HELD!!!
                info!("Resuming {}", incoming.creator.name);
                scheduler::add_to_schedule_queue(incoming.creator.clone());

                // We're done!
                return Ok(Session::server(sess));
            }
        }
    }
}

impl ClientPort {
    /// Connects to this port.
    pub fn connect(&self) -> Result<ClientSession, UserspaceError> {
        let incoming = Arc::new(IncomingConnection {
            session: SpinLock::new(None),
            creator: scheduler::get_current_process()
        });

        let mut guard = incoming.session.lock();
        let lock = self.0.incoming_connections.lock().push(incoming.clone());

        let session = loop {
            // If no handle to the server exist anymore, give up.
            if self.0.servercount.load(Ordering::SeqCst) == 0 {
                return Err(UserspaceError::PortRemoteDead);
            }

            // First, wake up an accepter
            while let Some(item) = self.0.accepters.lock().pop() {
                if let Some(process) = item.upgrade() {
                    scheduler::add_to_schedule_queue(process);
                    break;
                }
            }

            // Wait for it to do its job, and wake us up
            guard = scheduler::unschedule(&incoming.session, guard)?;

            // Make sure it did its job. If it didn't, try again.
            if let Some(s) = guard.take() {
                break s;
            }
        };

        Ok(Session::client(session))
    }
}

lazy_static! {
    // TODO: StringWrapper<[u8; 12]>
    static ref NAMED_PORTS: RwLock<HashMap<String, ClientPort>> = RwLock::new(HashMap::new());
}

pub fn create_named_port(name: [u8; 12], max_sessions: u32) -> Result<ServerPort, UserspaceError> {
    let name = match name.iter().position(|v| *v == 0) {
        Some(pos) => String::from_utf8_lossy(&name[..pos]),
        None => return Err(UserspaceError::ExceedingMaximum)
    };

    let (server, client) = Port::new(max_sessions);
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
