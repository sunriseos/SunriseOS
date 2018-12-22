//! IPC Server primitives
//!
//! The creation of an IPC server requires a WaitableManager and a PortHandler.
//! The WaitableManager will manage the event loop: it will wait for a request
//! to arrive on one of the waiters (or for any other event to happen), and call
//! that waiter's `handle_signal` function.
//!
//! A PortHandler is a type of Waiter which listens for incoming connections on
//! a port, creates a new Object from it, wrap it in a SessionWrapper (a kind of
//! waiter), and adds it to the WaitableManager's wait list.
//!
//! When a request comes to the Session, the SessionWrapper's handle_signaled
//! will call the dispatch function of its underlying object.
//!
//! Here's a very simple example server:
//!
//! ```
//! struct IExample;
//! object! {
//!     impl IExample {
//!         #[cmdid(0)]
//!         fn hello(&mut self, ) -> Result<([u8; 5]), Error> {
//!              Ok(b"hello")
//!         }
//!     }
//! }
//!
//! fn main() {
//!      let man = WaitableManager::new();
//!      let handler = Box::new(PortHandler::<IExample>::new("hello\0").unwrap());
//!      man.add_waitable(handler as Box<dyn IWaitable>);
//!      man.run()
//! }
//! ```

use syscalls;
use types::{HandleRef, ServerPort, ServerSession};
use core::marker::PhantomData;
use alloc::prelude::*;
use spin::Mutex;
use core::ops::{Deref, DerefMut, Index};
use error::Error;

/// A handle to a waitable object.
pub trait IWaitable {
    /// Gets the handleref for use in the `wait_synchronization` call.
    fn get_handle<'a>(&'a self) -> HandleRef<'a>;
    /// Function the manager calls when this object gets signaled.
    ///
    /// Takes the manager as a parameter, allowing the handler to add new handles
    /// to the wait queue.
    ///
    /// If the function returns false, remove it from the WaitableManager. If it
    /// returns an error, log the error somewhere, and remove the handle from the
    /// waitable manager.
    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<bool, Error>;
}

/// The event loop manager. Waits on the waitable objects added to it.
pub struct WaitableManager {
    to_add_waitables: Mutex<Vec<Box<IWaitable>>>
}

impl WaitableManager {
    /// Creates an empty waitable manager.
    pub fn new() -> WaitableManager {
        WaitableManager {
            to_add_waitables: Mutex::new(Vec::new())
        }
    }

    /// Add a new handle for the waitable manager to wait on.
    pub fn add_waitable(&self, waitable: Box<IWaitable>) {
        self.to_add_waitables.lock().push(waitable);
    }

    /// Run the event loop. This will call wait_synchronization on all the
    /// pending handles, and call handle_signaled on the handle that gets
    /// signaled.
    pub fn run(&self) -> ! {
        let mut waitables = Vec::new();
        loop {
            {
                let mut guard = self.to_add_waitables.lock();
                for waitable in guard.drain(..) {
                    waitables.push(waitable);
                }
            }

            let idx = {
                let handles = waitables.iter().map(|v| v.get_handle()).collect::<Vec<HandleRef>>();
                // TODO: new_waitable_event
                syscalls::wait_synchronization(&*handles, None).unwrap()
            };

            match waitables[idx].handle_signaled(self) {
                Ok(false) => (),
                Ok(true) => { waitables.remove(idx); },
                Err(err) => {
                    let _ = syscalls::output_debug_string(&format!("Error: {}", err));
                    waitables.remove(idx);
                }
            }
        }
    }
}

/// An IPC object.
///
/// Deriving this function manually is not recommended. Instead, users should use
/// the [object] macro to derive the Object implementation
/// from its external interface.
pub trait Object {
    /// Handle a request with the given cmdid.
    fn dispatch(&mut self, manager: &WaitableManager, cmdid: u32, buf: &mut [u8]) -> Result<(), Error>;
}

#[repr(C, align(16))]
struct Align16<T>(T);
impl<T> Deref for Align16<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> DerefMut for Align16<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T, Idx> Index<Idx> for Align16<T> where T: Index<Idx> {
    type Output = T::Output;

    fn index(&self, index: Idx) -> &T::Output {
        &self.0[index]
    }
}

/// A wrapper around an Object backed by an IPC Session that implements the
/// IWaitable trait.
pub struct SessionWrapper<T: Object> {
    handle: ServerSession,
    object: T,

    // Ensure 16 bytes of alignment so the raw data is properly aligned.
    buf: Align16<[u8; 0x100]>
}

impl<T: Object> SessionWrapper<T> {
    /// Create a new SessionWrapper from an open ServerSession and a backing
    /// Object.
    pub fn new(handle: ServerSession, object: T) -> SessionWrapper<T> {
        SessionWrapper {
            handle,
            object,
            buf: Align16([0; 0x100]),
        }
    }
}

impl<T: Object> IWaitable for SessionWrapper<T> {
    fn get_handle<'a>(&'a self) -> HandleRef<'a> {
        self.handle.0.as_ref()
    }

    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<bool, Error> {
        self.handle.receive(&mut self.buf[..], Some(0))?;
        let (ty, cmdid) = super::find_ty_cmdid(&self.buf[..]);
        match ty {
            // TODO: Handle other types.
            4 | 6 => {
                self.object.dispatch(manager, cmdid, &mut self.buf[..])?;
                self.handle.reply(&mut self.buf[..])?;
                Ok(false)
            },
            2 => Ok(true),
            _ => Ok(true)
        }
    }
}

/// A wrapper around a Server Port that implements the IWaitable trait. Waits for
/// connection requests, and creates a new SessionWrapper around the incoming
/// connections, which gets registered on the WaitableManager.
pub struct PortHandler<T: Object + Default> {
    handle: ServerPort,
    phantom: PhantomData<T>
}

impl<T: Object + Default + 'static> IWaitable for PortHandler<T> {
    fn get_handle<'a>(&'a self) -> HandleRef<'a> {
        self.handle.0.as_ref()
    }

    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<bool, Error> {
        let session = Box::new(SessionWrapper {
            object: T::default(),
            handle: self.handle.accept()?,
            buf: Align16([0; 0x100])
        });
        manager.add_waitable(session);
        Ok(false)
    }
}

fn encode_bytes(s: &str) -> u64 {
    assert!(s.len() < 8);
    let s = s.as_bytes();
    0
        | (*s.get(0).unwrap_or(&0) as u64) << 00 | (*s.get(1).unwrap_or(&0) as u64) << 08
        | (*s.get(2).unwrap_or(&0) as u64) << 16 | (*s.get(3).unwrap_or(&0) as u64) << 24
        | (*s.get(4).unwrap_or(&0) as u64) << 32 | (*s.get(5).unwrap_or(&0) as u64) << 40
        | (*s.get(6).unwrap_or(&0) as u64) << 48 | (*s.get(7).unwrap_or(&0) as u64) << 56
}

impl<T: Object + Default> PortHandler<T> {
    /// Registers a new PortHandler of the given name to the sm: service.
    pub fn new(server_name: &str) -> Result<PortHandler<T>, Error> {
        use sm::IUserInterface;
        let port = IUserInterface::raw_new()?.register_service(encode_bytes(server_name), false, 0)?;
        Ok(PortHandler {
            handle: port,
            phantom: PhantomData
        })
    }

    /// Registers a new PortHandler of the given name to the kernel. Note that
    /// this interface should not be used by most services. Only the service
    /// manager should register itself through this interface, as kernel managed
    /// services do not implement any access controls.
    pub fn new_managed(server_name: &str) -> Result<PortHandler<T>, Error> {
        let port = syscalls::manage_named_port(server_name, 0)?;
        Ok(PortHandler {
            handle: port,
            phantom: PhantomData
        })
    }
}
