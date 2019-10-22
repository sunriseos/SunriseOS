//! # IPC Server primitives
//!
//! The IPC System on horizon is made of Ports pair and Session pairs. Each pair
//! has a client and a server side:
//!
//! - For Ports, the client is used to connect, returning a client Session,
//!   while the server is used to accept connections, returning a server Session
//! - For Sessions, the client is used to send IPC requests, while the server
//!   is used to receive and reply to those requests.
//!
//! An IPC Server is made of a [future executor](crate::futures) on which we
//! spawn futures to handle Port and Session. Those futures, created through
//! [fn port_handler] and [fn new_session_wrapper], will take care of accepting
//! new sessions from a ServerPort, and answering IPC requests sent on the
//! ServerSession.
//!
//! ## Port Handling
//!
//! Most interfaces start with a Port, which is basically an object to which
//! clients can connect to, creating a Session pair. Ports can come from two
//! places: It can either be kernel-managed, or it can be sm-managed. Almost
//! all ports are sm-managed, the only exceptions being `sm:` itself.
//!
//! Kernel-managed ports are created through the [fn managed_port_handler]
//! function. This will internally call [crate::syscalls::manage_named_port()]
//! to acquire a [crate::types::ServerPort]. Sm-managed ports are created
//! through [fn port_handler], which call
//! [crate::sm::IUserInterfaceProxy::register_service()] to acquire their
//! ServerPort.
//!
//! Once the ServerPort is acquired, the port handling functions will run on a
//! loop, accepting new connections, creating a backing Object for the sessions,
//! and spawning a new future on the event loop with [fn new_session_wrapper].
//!
// no_run because port_handler will fail on linux.
//! ```no_run
//! # extern crate alloc;
//! use alloc::boxed::Box;
//! use sunrise_libuser::futures::WaitableManager;
//! use sunrise_libuser::futures_rs::future::FutureObj;
//! use sunrise_libuser::ipc::server::port_handler;
//! use sunrise_libuser::example::IExample1;
//!
//! /// Every time the port accepts a connection and a session is created, it
//! /// will spawn a HelloInterface.
//! #[derive(Debug, Default, Clone)]
//! struct HelloInterface;
//!
//! impl IExample1 for HelloInterface {}
//!
//! fn main() {
//!     let mut man = WaitableManager::new();
//!
//!     let handler = port_handler(man.work_queue(), "hello", HelloInterface::dispatch).unwrap();
//!     man.work_queue().spawn(FutureObj::new(Box::new(handler)));
//!
//! #   let man = FakeMan;
//!     man.run();
//! }
//! # // We can't run the WaitableManager, since that'll attempt to run syscalls
//! # // that aren't implemented.
//! # struct FakeMan;
//! # impl FakeMan { fn run(&self) {} }
//! ```
//!
//! ## Session Handling
//!
//! A Session server is represented by an Object implementing an Interface,
//! receiving and replying to Remote Process Call (RPC) requests on a
//! [crate::types::ServerSession]. A session server is created either through a
//! port handler accepting a session, or through the [fn new_session_wrapper]
//! function, which will receive requests, call the Object's dispatcher
//! function, and reply with the answer.
//!
//! ### Interfaces
//!
//! IPC Servers expose an API to a given service to other processes using an RPC
//! interface. The interface is defined using a SwIPC id file which can be found
//! in the `ipcdefs` folder at the root of the repository. This SwIPC file will
//! then get compiled by swipc-gen into a rust file containing a Client struct
//! and two Server traits (one being synchronous, the other asynchronous). Those
//! will generally be exposed from the `sunrise_libuser` crate.
//!
//! Those traits contain two elements:
//!
//! 1. A function for every function in the SwIPC interface, having roughly the
//!    same signature (but with SwIPC types translated to rust). The user is
//!    expected to implement all those functions to have a complete interface
//!    implementation.
//!
//! 2. A function called `dispatch`. This function will be called by the Session
//!    Wrapper, and is in charge of parsing the IPC message data to extract all
//!    the arguments and call the correct function from the trait
//!    implementation.
//!
// no_run because port_handler will fail on linux...
//! ```no_run
//! extern crate alloc;
//!
//! use alloc::boxed::Box;
//! use sunrise_libuser::futures::{WorkQueue, WaitableManager};
//! use sunrise_libuser::futures_rs::future::FutureObj;
//! use sunrise_libuser::ipc::server::port_handler;
//! use sunrise_libuser::example::IExample2;
//! use sunrise_libuser::error::Error;
//! use log::*;
//!
//! #[derive(Debug, Default, Clone)]
//! struct HelloInterface;
//!
//! impl IExample2 for HelloInterface {
//!     fn function(&mut self, _manager: WorkQueue<'static>) -> Result<(), Error> {
//!         info!("hello");
//!         Ok(())
//!     }
//!     fn function2(&mut self, _manager: WorkQueue<'static>, val1: u32, val2: u32) -> Result<(bool, bool), Error> {
//!         info!("hello");
//!         Ok((false, true))
//!     }
//! }
//!
//! fn main() {
//!     let mut man = WaitableManager::new();
//!
//!     let handler = port_handler(man.work_queue(), "hello", HelloInterface::dispatch).unwrap();
//!     man.work_queue().spawn(FutureObj::new(Box::new(handler)));
//!
//! #   let man = FakeMan;
//!
//!     man.run();
//! }
//! # // We can't run the WaitableManager, since that'll attempt to run syscalls
//! # // that aren't implemented.
//! # struct FakeMan;
//! # impl FakeMan { fn run(&self) {} }
//! ```
//!
//! ### Objects
//!
//! An Object backs every Session. This object is the structure which implements
//! the Interface trait. It contains the state of that specific session, and may
//! be mutated by any IPC request. A common pattern is to have an IPC request
//! contain an initialization method containing various parameters to configure
//! the rest of the operations available on that session.
//!
//! Note that a single interface may be implemented by multiple different
//! Object. This can be used to implement different access control based on the
//! interface used to access the service, for instance. Nintendo uses this
//! pattern: `bsd:u` and `bsd:s` use the same interface, but have different
//! access rights.
//!
//! ### Subsessions
//!
//! While the "root" session is generally created from a Port Handler, the user
//! is free to create and return new subsessions. This can be done by creating
//! a session pair with [crate::syscalls::create_session()], spawning a new
//! Session Handler with [fn new_session_wrapper], and returning the client-side
//! session handle. Here's an example:
//!
// no_run because port_handler will fail on linux...
//! ```no_run
//! extern crate alloc;
//! use alloc::boxed::Box;
//! use sunrise_libuser::futures::WorkQueue;
//! use sunrise_libuser::futures_rs::future::FutureObj;
//! use sunrise_libuser::example::{IExample3, IExample3Subsession, IExample3SubsessionProxy};
//! use sunrise_libuser::syscalls;
//! use sunrise_libuser::error::Error;
//! use sunrise_libuser::ipc::server::new_session_wrapper;
//!
//! #[derive(Debug, Default, Clone)]
//! struct HelloInterface;
//!
//! impl IExample3 for HelloInterface {
//!     fn function(&mut self, work_queue: WorkQueue<'static>) -> Result<IExample3SubsessionProxy, Error> {
//!         let (server, client) = syscalls::create_session(false, 0)?;
//!         let wrapper = new_session_wrapper(work_queue.clone(), server, Subsession, Subsession::dispatch);
//!         work_queue.spawn(FutureObj::new(Box::new(wrapper)));
//!         Ok(IExample3SubsessionProxy::from(client))
//!     }
//! }
//!
//! #[derive(Debug, Clone)]
//! struct Subsession;
//!
//! impl IExample3Subsession for Subsession {}
//!
//! # fn main() {
//! #     use sunrise_libuser::futures::WaitableManager;
//! #     use sunrise_libuser::ipc::server::port_handler;
//! #     let mut man = WaitableManager::new();
//!
//! #     let handler = port_handler(man.work_queue(), "hello", HelloInterface::dispatch).unwrap();
//! #     man.work_queue().spawn(FutureObj::new(Box::new(handler)));
//! # }
//! ```
//!
//! ### Asynchronous Traits
//!
//! A server might want to wait for asynchronous events to occur before
//! answering: for instance, the `read()` function of a filesystem might want
//! to wait for an [crate::types::IRQEvent] to get signaled before getting the
//! data from the disk and returning it to the client.
//!
//! This is doable by using the Asynchronous traits. Those return a Future
//! instead of directly returning the Result. This has one huge downside: the
//! futures need to be Boxed, incuring a needless heap allocation. This should
//! get fixed when `impl Trait` in traits or `async fn` in traits is
//! implemented.
//!
//! Here's an example usage:
//!
// no_run because port_handler will fail on linux.
//! ```no_run
//! #![feature(async_await)]
//! extern crate alloc;
//!
//! use core::future::Future;
//! use alloc::boxed::Box;
//! use sunrise_libuser::futures::WorkQueue;
//! use sunrise_libuser::futures_rs::future::FutureObj;
//! use sunrise_libuser::example::IExample4Async;
//! use sunrise_libuser::types::SharedMemory;
//! use sunrise_libuser::error::{Error, KernelError};
//!
//! #[derive(Debug, Default, Clone)]
//! struct HelloInterface;
//!
//! fn do_async_stuff() -> impl Future<Output=()> + Send {
//!     futures::future::ready(())
//! }
//!
//! impl IExample4Async for HelloInterface {
//!     fn function<'a>(&'a mut self, manager: WorkQueue<'static>, val: &u8) -> FutureObj<'a, Result<SharedMemory, Error>> {
//!         FutureObj::new(Box::new(async move {
//!             do_async_stuff().await;
//!             Err(KernelError::PortRemoteDead.into())
//!         }))
//!     }
//! }
//!
//! # fn main() {
//! #     use sunrise_libuser::futures::WaitableManager;
//! #     use sunrise_libuser::ipc::server::port_handler;
//! #     let mut man = WaitableManager::new();
//!
//! #     let handler = port_handler(man.work_queue(), "hello", HelloInterface::dispatch).unwrap();
//! #     man.work_queue().spawn(FutureObj::new(Box::new(handler)));
//! # }
//! ```

use crate::syscalls;
use crate::types::{ServerPort, ServerSession};
use alloc::boxed::Box;
use core::ops::{Deref, DerefMut, Index};
use crate::error::{KernelError, Error};
use crate::ipc::Message;
use futures::future::{FutureObj, FutureExt};
use core::future::Future;
use crate::futures::WorkQueue;

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
    assert!(s.len() <= 8);
    let s = s.as_bytes();
    0
        | (u64::from(*s.get(0).unwrap_or(&0))) << 00 | (u64::from(*s.get(1).unwrap_or(&0))) <<  8
        | (u64::from(*s.get(2).unwrap_or(&0))) << 16 | (u64::from(*s.get(3).unwrap_or(&0))) << 24
        | (u64::from(*s.get(4).unwrap_or(&0))) << 32 | (u64::from(*s.get(5).unwrap_or(&0))) << 40
        | (u64::from(*s.get(6).unwrap_or(&0))) << 48 | (u64::from(*s.get(7).unwrap_or(&0))) << 56
}

/// Infinite loop future that waits for `port` to get signaled, then accepts a
/// new session on the port, creates a new object backing the session using
/// `T::default()`, and finally spawns a new session wrapper future using
/// [new_session_wrapper()].
fn common_port_handler<T, DISPATCH>(work_queue: WorkQueue<'static>, port: ServerPort, dispatch: DISPATCH) -> impl Future<Output=()>
where
    DISPATCH: for<'b> hrtb_hack::FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Clone + Unpin + Send + 'static,
    T: Default + Clone + Unpin + Send + 'static,
{
    crate::loop_future::loop_fn((work_queue, dispatch, port), |(work_queue, dispatch, port)| {
        port.wait_async(work_queue.clone())
            .map(move |res| {
                if let Err(err) = res {
                    // This instance of WaitAsync can return one of two errors:
                    // - InvalidAddress: Someone did something silly with
                    //   memory.
                    // - InvalidHandle: Shouldn't happen since we hold the
                    //   ServerPort. Someone might have manually closed it?
                    unreachable!("WaitAsync errors cannot be reached from here. {:?}", err);
                }
                let handle = port.accept().unwrap();
                let future = new_session_wrapper(work_queue.clone(), handle, T::default(), dispatch.clone());
                work_queue.spawn(FutureObj::new(Box::new(future)));
                crate::loop_future::Loop::Continue((work_queue, dispatch, port))
            })
    })
}

/// Creates a port through [crate::sm::IUserInterfaceProxy::register_service()]
/// with the given name, and returns a future which will handle the port - that
/// is, it will continuously accept new sessions on the port, and create backing
/// objects through `T::default()`, and spawn a top-level future handling that
/// sesion with [new_session_wrapper()].
pub fn port_handler<T, DISPATCH>(work_queue: WorkQueue<'static>, server_name: &str, dispatch: DISPATCH) -> Result<impl Future<Output=()>, Error>
where
    DISPATCH: for<'b> hrtb_hack::FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Clone + Unpin + Send + 'static,
    T: Default + Clone + Unpin + Send + 'static,
{
    use crate::sm::IUserInterfaceProxy;
    // We use `new()` and not `raw_new()` in order to avoid deadlocking when closing the
    // IUserInterfaceProxy handle. See implementation note in sm/src/main.rs
    let port = IUserInterfaceProxy::new()?.register_service(encode_bytes(server_name), false, 0)?;
    Ok(common_port_handler(work_queue, port, dispatch))
}

/// Creates a port through [syscalls::manage_named_port()] with the given name,
/// and returns a future which will handle the port - that is, it
/// will continuously accept new sessions on the port, and create backing
/// objects through `T::default()`, and spawn a top-level future handling that
/// sesion with [new_session_wrapper()].
pub fn managed_port_handler<T, DISPATCH>(work_queue: WorkQueue<'static>, server_name: &str, dispatch: DISPATCH) -> Result<impl Future<Output=()>, Error>
where
    DISPATCH: for<'b> hrtb_hack::FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Clone + Unpin + Send + 'static,
    T: Default + Clone + Unpin + Send + 'static,
{
    let port = syscalls::manage_named_port(server_name, 0)?;
    Ok(common_port_handler(work_queue, port, dispatch))
}

pub mod hrtb_hack {
    //! Ideally, that's what we would want to write
    //! async fn new_session_wrapper<F>(mut dispatch: F) -> ()
    //! where
    //!     F: for<'a> FnMut<(&'a mut [u8],)>,
    //!     for<'a> <F as FnOnce<(&'a mut [u8],)>>::Output: Future<Output = Result<(), ()>>,
    //! {
    //!     // Session wrapper code
    //! }
    //
    //! But the compiler seems to have trouble reasoning about associated types
    //! in an HRTB context (maybe that's just not possible ? Not sure).
    //!
    //! To work around this, we'll make a supertrait over `FnMut<T>` and make
    //! use of lifetime ellision rules to get this done.

    //! So instead, we'll make a wrapper for `FnMut` that has the right trait bound
    //! on its associated output type directly, Implement it for all FnMut with
    //! Ret = Output, and use that as a bound instead.

    use core::future::Future;

    /// A similar trait to FnMut() but moving the Ret associated trait to a
    /// generic position, simplifying stuff. See module docs.
    pub trait FutureCallback<T, O>: FnMut<T> {
        /// See [type FnMut::Output]
        type Ret: Future<Output = O> + Send;

        /// See [FnMut::call_mut()].
        fn call(&mut self, x: T) -> Self::Ret;
    }

    impl<T, O, F: FnMut<T>> FutureCallback<T, O> for F
    where
        F::Output: Future<Output = O> + Send,
    {
        type Ret = F::Output;

        fn call(&mut self, x: T) -> Self::Ret {
            self.call_mut(x)
        }
    }
}

/// Creates a new top-level future that handles session.
///
/// The returned future will continuously accept new incoming requests on the
/// handle, call the dispatch function with the given object, and the request'
/// cmdid and buffer, and finally reply to the request.
///
/// It may be used to open subsessions.
pub fn new_session_wrapper<T, DISPATCH>(work_queue: WorkQueue<'static>, handle: ServerSession, mut object: T, mut dispatch: DISPATCH) -> impl Future<Output = ()> + Send
where
    DISPATCH: for<'b> hrtb_hack::FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Unpin + Send + Clone + 'static,
    T: Unpin + Send + Clone + 'static,
{
    let mut buf = Align16([0; 0x100]);
    let mut pointer_buf = [0; 0x400];

    async move {
        loop {
            debug!("Waiting for a new session on handle {:?}", handle);
            let res = handle.wait_async(work_queue.clone()).await;

            if let Err(err) = res {
                // This instance of WaitAsync can return one of two errors:
                // - InvalidAddress: Someone did something silly with
                //   memory.
                // - InvalidHandle: Shouldn't happen since we hold the
                //   ServerPort. Someone might have manually closed it?
                unreachable!("WaitAsync errors cannot be reached from here. {:?}", err);
            }

            // Push a C Buffer before receiving.
            let mut req = Message::<(), [_; 1], [_; 0], [_; 0]>::new_request(None, 0);
            req.push_in_pointer(&mut pointer_buf, false);
            req.pack(&mut buf[..]);

            // Use a timeout of 0 to avoid blocking.
            match handle.receive(&mut buf[..], Some(0)) {
                Err(Error::Kernel(KernelError::Timeout, _)) => continue,
                res => res.unwrap(),
            }

            let tycmdid = super::find_ty_cmdid(&buf[..]);
            debug!("Got request for: {:?}", tycmdid);

            let close = match tycmdid {
                Some((4, cmdid)) | Some((6, cmdid)) => dispatch.call((&mut object, work_queue.clone(), cmdid, &mut buf[..])).await
                    .map(|_| false)
                    .unwrap_or_else(|err| { error!("Dispatch method errored out: {:?}", err); true }),
                Some((2, _)) => true,
                Some((5, cmdid)) | Some((7, cmdid)) => control_dispatch(&mut object, dispatch.clone(), work_queue.clone(), cmdid, &mut buf[..])
                    .map(|_| false)
                    .unwrap_or_else(|err| { error!("Dispatch method errored out: {:?}", err); true }),
                _ => true,
            };

            if close {
                break;
            }

            handle.reply(&mut buf[..]).unwrap();
        }
    }
}

/// Implement the Control ipc cmd types.
///
/// See [switchbrew](https://switchbrew.org/w/index.php?title=IPC_Marshalling#Control)
fn control_dispatch<T, DISPATCH>(object: &mut T, dispatch: DISPATCH, manager: WorkQueue<'static>, cmdid: u32, buf: &mut [u8]) -> Result<(), Error>
where
    DISPATCH: for<'b> hrtb_hack::FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Unpin + Send + Clone + 'static,
    T: Unpin + Send + Clone + 'static
{
    match cmdid {
        2 | 4 => {
            let (server, client) = syscalls::create_session(false, 0)?;
            let new_object = object.clone();
            let future = new_session_wrapper(manager.clone(), server, new_object, dispatch);
            manager.spawn(FutureObj::new(Box::new(future)));

            let mut msg__ = Message::<(), [_; 0], [_; 0], [_; 1]>::new_response(None);
            msg__.push_handle_move(client.into_handle());
            msg__.pack(buf);
            Ok(())
        },
        _ => {
            let mut msg__ = Message::<(), [_; 0], [_; 0], [_; 0]>::new_response(None);
            msg__.set_error(KernelError::PortRemoteDead.make_ret() as u32);
            msg__.pack(buf);
            Ok(())
        }
    }
}