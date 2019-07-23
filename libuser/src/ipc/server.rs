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
//! #[derive(Debug, Default)]
//! struct IExample;
//!
//! impl sunrise_libuser::example::IExample for IExample {
//!     fn hello(&mut self, _manager: &WaitableManager) -> Result<([u8; 5]), Error> {
//!          Ok(b"hello")
//!     }
//! }
//!
//! fn main() {
//!      let man = WaitableManager::new();
//!      let handler = Box::new(PortHandler::new("hello\0", IExample::dispatch).unwrap());
//!      man.add_waitable(handler as Box<dyn IWaitable>);
//!      man.run()
//! }
//! ```

use crate::syscalls;
use crate::types::{HandleRef, ServerPort, ServerSession};
use core::marker::PhantomData;
use alloc::vec::Vec;
use alloc::boxed::Box;
use spin::Mutex;
use core::ops::{Deref, DerefMut, Index};
use core::fmt::{self, Debug};
use crate::error::Error;
use crate::ipc::Message;

/// A handle to a waitable object.
pub trait IWaitable: Debug {
    /// Gets the handleref for use in the `wait_synchronization` call.
    fn get_handle(&self) -> HandleRef<'_>;
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
#[derive(Debug, Default)]
pub struct WaitableManager<'a> {
    /// Vector of items to add to the waitable list on the next loop.
    to_add_waitables: Mutex<Vec<Box<dyn IWaitable>>>,

    /// Vector of static ref to items to add to the waitable list on the next loop.
    to_add_waitables_ref: Mutex<Vec<&'a mut dyn IWaitable>>
}

impl<'a> WaitableManager<'a> {
    /// Creates an empty waitable manager.
    pub fn new() -> WaitableManager<'a> {
        WaitableManager {
            to_add_waitables: Mutex::new(Vec::new()),
            to_add_waitables_ref: Mutex::new(Vec::new())
        }
    }

    /// Add a new handle for the waitable manager to wait on.
    pub fn add_waitable(&self, waitable: Box<dyn IWaitable>) {
        self.to_add_waitables.lock().push(waitable);
    }

    /// Add a new handle for the waitable manager to wait on.
    pub fn add_waitable_ref(&self, waitable: &'a mut dyn IWaitable) {
        self.to_add_waitables_ref.lock().push(waitable);
    }

    /// Run the event loop. This will call wait_synchronization on all the
    /// pending handles, and call handle_signaled on the handle that gets
    /// signaled.
    pub fn run(&self) -> ! {
        let mut waitables_box = Vec::new();
        let mut waitables_ref = Vec::new();
        loop {
            {
                let mut guard = self.to_add_waitables.lock();
                for waitable in guard.drain(..) {
                    waitables_box.push(waitable);
                }
            }

            {
                let mut guard = self.to_add_waitables_ref.lock();
                for waitable in guard.drain(..) {
                    waitables_ref.push(waitable);
                }
            }

            let idx = {
                let mut handles = waitables_box.iter().map(|v| v.get_handle()).collect::<Vec<HandleRef<'_>>>();
                let mut handles_waitable_ref = waitables_ref.iter().map(|v| v.get_handle()).collect::<Vec<HandleRef<'_>>>();
                handles.append(&mut handles_waitable_ref);
                // TODO: new_waitable_event
                syscalls::wait_synchronization(&*handles, None).unwrap()
            };

            let result = if idx < waitables_box.len() {
                waitables_box[idx].handle_signaled(self)
            } else {
                waitables_ref[idx - waitables_box.len()].handle_signaled(self)
            };

            match result {
                Ok(false) => (),
                Ok(true) => {
                    waitables_box.remove(idx);
                    if idx < waitables_box.len() {
                        waitables_box.remove(idx);
                    } else {
                        waitables_ref.remove(idx - waitables_box.len());
                    }
                },
                Err(err) => {
                    error!("Error: {}", err);
                    if idx < waitables_box.len() {
                        waitables_box.remove(idx);
                    } else {
                        waitables_ref.remove(idx - waitables_box.len());
                    }
                }
            }
        }
    }
}

/// Wrapper struct that forces the alignment to 0x10. Somewhat necessary for the
/// IPC command buffer.
#[repr(C, align(16))]
#[derive(Debug)]
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

/// Encode an 8-character service string into an u64
fn encode_bytes(s: &str) -> u64 {
    assert!(s.len() < 8);
    let s = s.as_bytes();
    0
        | (u64::from(*s.get(0).unwrap_or(&0))) << 00 | (u64::from(*s.get(1).unwrap_or(&0))) <<  8
        | (u64::from(*s.get(2).unwrap_or(&0))) << 16 | (u64::from(*s.get(3).unwrap_or(&0))) << 24
        | (u64::from(*s.get(4).unwrap_or(&0))) << 32 | (u64::from(*s.get(5).unwrap_or(&0))) << 40
        | (u64::from(*s.get(6).unwrap_or(&0))) << 48 | (u64::from(*s.get(7).unwrap_or(&0))) << 56
}

/// A wrapper around a Server Port that implements the IWaitable trait. Waits
/// for connection requests, and creates a new SessionWrapper around the
/// incoming connections, which gets registered on the WaitableManager.
///
/// The DISPATCH function is passed to [SessionWrapper]s created from this
/// port. The DISPATCH function is responsible for parsing and answering an
/// IPC request. It will usually be found on the interface trait. See, for
/// instance, [crate::sm::IUserInterface::dispatch()].
pub struct PortHandler<T, DISPATCH> {
    /// The kernel object backing this Port Handler. 
    handle: ServerPort,
    /// Function called when sessions created from this port receive a request.
    dispatch: DISPATCH,
    /// Type of the Object this port creates.
    phantom: PhantomData<T>,
}

impl<T, DISPATCH> Debug for PortHandler<T, DISPATCH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortHandler")
            .field("handle", &self.handle)
            .finish()
    }
}

impl<T, DISPATCH> PortHandler<T, DISPATCH> {
    /// Registers a new PortHandler of the given name to the `sm:` service.
    pub fn new(server_name: &str, dispatch: DISPATCH) -> Result<PortHandler<T, DISPATCH>, Error> {
        use crate::sm::IUserInterfaceProxy;
        let port = IUserInterfaceProxy::raw_new()?.register_service(encode_bytes(server_name), false, 0)?;
        Ok(PortHandler {
            handle: port,
            dispatch,
            phantom: PhantomData,
        })
    }

    /// Registers a new PortHandler of the given name to the kernel. Note that
    /// this interface should not be used by most services. Only the service
    /// manager should register itself through this interface, as kernel managed
    /// services do not implement any access controls.
    pub fn new_managed(server_name: &str, dispatch: DISPATCH) -> Result<PortHandler<T, DISPATCH>, Error> {
        let port = syscalls::manage_named_port(server_name, 0)?;
        Ok(PortHandler {
            handle: port,
            dispatch,
            phantom: PhantomData,
        })
    }
}

impl<T: Default + Debug + 'static, DISPATCH: Clone + 'static> IWaitable for PortHandler<T, DISPATCH>
where
    DISPATCH: FnMut(&mut T, &WaitableManager, u32, &mut [u8]) -> Result<(), Error>
{
    fn get_handle(&self) -> HandleRef<'_> {
        self.handle.0.as_ref()
    }

    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<bool, Error> {
        let session = Box::new(SessionWrapper {
            object: T::default(),
            handle: self.handle.accept()?,
            buf: Align16([0; 0x100]),
            pointer_buf: [0; 0x300],
            dispatch: self.dispatch.clone(),
        });
        manager.add_waitable(session);
        Ok(false)
    }
}

/// A wrapper around an Object backed by an IPC Session that implements the
/// IWaitable trait.
///
/// The DISPATCH function is responsible for parsing and answering an IPC
/// request. It will usually be found on the interface trait. See, for instance,
/// [crate::sm::IUserInterface::dispatch()].
pub struct SessionWrapper<T, DISPATCH> {
    /// Kernel Handle backing this object.
    handle: ServerSession,
    /// Object instance.
    object: T,

    /// Function called to handle an IPC request.
    dispatch: DISPATCH,

    /// Command buffer for this session.
    /// Ensure 16 bytes of alignment so the raw data is properly aligned.
    buf: Align16<[u8; 0x100]>,

    /// Buffer used for receiving type-X buffers and answering to type-C buffers.
    // TODO: Pointer Buf should take its size as a generic parameter.
    // BODY: The Pointer Buffer size should be configurable by the sysmodule.
    // BODY: We'll wait for const generics to do it however, as otherwise we'd
    // BODY: have to bend over backwards with typenum.
    pointer_buf: [u8; 0x300]
}

impl<T, DISPATCH> SessionWrapper<T, DISPATCH> {
    /// Create a new SessionWrapper from an open ServerSession and a backing
    /// Object.
    pub fn new(handle: ServerSession, object: T, dispatch: DISPATCH) -> SessionWrapper<T, DISPATCH> {
        SessionWrapper {
            handle,
            object,
            dispatch,
            buf: Align16([0; 0x100]),
            pointer_buf: [0; 0x300],
        }
    }
}

impl<T: Debug, DISPATCH> Debug for SessionWrapper<T, DISPATCH> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionWrapper")
            .field("handle", &self.handle)
            .field("object", &self.object)
            .field("buf", &&self.buf[..])
            .field("pointer_buf", &&self.pointer_buf[..])
            .finish()
    }
}

impl<T: Debug, DISPATCH> IWaitable for SessionWrapper<T, DISPATCH>
where
    DISPATCH: FnMut(&mut T, &WaitableManager, u32, &mut [u8]) -> Result<(), Error>
{
    fn get_handle(&self) -> HandleRef<'_> {
        self.handle.0.as_ref()
    }

    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<bool, Error> {
        // Push a C Buffer before receiving.
        let mut req = Message::<(), [_; 1], [_; 0], [_; 0]>::new_request(None, 0);
        req.push_in_pointer(&mut self.pointer_buf, false);
        req.pack(&mut self.buf[..]);

        self.handle.receive(&mut self.buf[..], Some(0))?;

        match super::find_ty_cmdid(&self.buf[..]) {
            // TODO: Handle other types.
            Some((4, cmdid)) | Some((6, cmdid)) => {
                (self.dispatch)(&mut self.object, manager, cmdid, &mut self.buf[..])?;
                self.handle.reply(&mut self.buf[..])?;
                Ok(false)
            },
            Some((2, _)) => Ok(true),
            _ => Ok(true)
        }
    }
}