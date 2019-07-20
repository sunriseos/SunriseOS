//! # IPC Server primitives
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
//! ```ignore
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
//!      let mut man = WaitableManager::new();
//!      let handler = managed_port_handler(man.work_queue(), "hello\0", IExample::dispatch).unwrap();
//!      man.work_queue().spawn(FutureObj::new(Box::new(handler)));
//!      man.run()
//! }
//! ```
//!
//! Future support is very liberally taken from the blog post [Building an
//! Embedded Futures Executor](https://josh.robsonchase.com/embedded-executor/)
//! and adapted to the newer version of futures.

// TODO: Rewrite the docs, split future executor from IPC.

use crate::syscalls;
use crate::types::{HandleRef, ServerPort, ServerSession};
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::collections::vec_deque::VecDeque;
use core::pin::Pin;
use spin::Mutex;
use core::ops::{Deref, DerefMut, Index};
use crate::error::Error;
use crate::ipc::Message;
use core::task::{Poll, Context, Waker};
use futures::future::{FutureObj, LocalFutureObj, FutureExt};
use futures::task::ArcWake;
use core::future::Future;

#[derive(Debug)]
struct Task<'a> {
    future: LocalFutureObj<'a, ()>,
    // Invariant: waker should always be Some after the task has been spawned.
    waker: Option<Waker>,
}

impl<'a> Task<'a> {
    fn new(future: LocalFutureObj<'a, ()>) -> Task<'a> {
        Task {
            future,
            waker: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct WorkQueue<'a>(Arc<Mutex<VecDeque<WorkItem<'a>>>>);

impl<'a> WorkQueue<'a> {
    pub(crate) fn wait_for(&self, handles: &[HandleRef], ctx: &mut Context) {
        for handle in handles {
            self.0.lock().push_back(WorkItem::WaitHandle(handle.staticify(), ctx.waker().clone()))
        }
    }

    pub fn spawn(&self, future: FutureObj<'a, ()>) {
        self.0.lock().push_back(WorkItem::Spawn(future));
    }
}

// Super simple Wake implementation.
#[derive(Debug, Clone)]
pub struct QueueWaker<'a> {
    queue: WorkQueue<'a>,
    id: generational_arena::Index,
}

impl<'a> ArcWake for QueueWaker<'a> {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.queue.0.lock().push_back(WorkItem::Poll(arc_self.id))
    }
}

#[derive(Debug)]
enum WorkItem<'a> {
    Poll(generational_arena::Index),
    Spawn(FutureObj<'a, ()>),
    WaitHandle(HandleRef<'static>, Waker),
}

/// The event loop manager. Waits on the waitable objects added to it.
#[derive(Debug)]
pub struct WaitableManager<'a> {
    /// Queue of things to do in the next "tick" of the event loop.
    work_queue: WorkQueue<'a>,
    /// List of futures that are currently running on this executor.
    registry: generational_arena::Arena<Task<'a>>
}

impl<'a> WaitableManager<'a> {
    /// Creates an empty waitable manager.
    pub fn new() -> WaitableManager<'a> {
        WaitableManager {
            work_queue: WorkQueue(Arc::new(Mutex::new(VecDeque::new()))),
            registry: generational_arena::Arena::new(),
        }
    }

    pub fn work_queue(&self) -> WorkQueue<'a> {
        self.work_queue.clone()
    }

    pub fn run(&mut self) {
        let mut waitables = Vec::new();
        let mut waiting_on: Vec<Vec<Waker>> = Vec::new();
        loop {
            loop {
                let item = self.work_queue.0.lock().pop_front();
                let item = if let Some(item) = item { item } else { break };
                match item {
                    WorkItem::Poll(id) => {
                        if let Some(Task { future, waker }) = self.registry.get_mut(id) {
                            let future = Pin::new(future);

                            let waker = waker
                                .as_ref()
                                .expect("waker not set, task spawned incorrectly");

                            if let Poll::Ready(_) = future.poll(&mut Context::from_waker(waker)) {
                                self.registry.remove(id);
                            }
                        }
                    },
                    WorkItem::Spawn(future) => {
                        let id = self.registry.insert(Task::new(future.into()));
                        self.registry.get_mut(id).unwrap().waker = Some(Arc::new(QueueWaker {
                            queue: self.work_queue.clone(),
                            id,
                        }).into_waker());
                        self.work_queue.0.lock().push_back(WorkItem::Poll(id));
                    },
                    WorkItem::WaitHandle(hnd, waker) => {
                        if let Some(idx) = waitables.iter().position(|v| *v == hnd) {
                            waiting_on[idx].push(waker);
                        } else {
                            waitables.push(hnd);
                            waiting_on.push(vec![waker]);
                        }
                    }
                }
            }

            if self.registry.is_empty() {
                break;
            }

            assert!(!waitables.is_empty(), "WaitableManager entered invalid state: No waitables to wait on.");
            info!("Calling WaitSynchronization with {:?}", waitables);
            let idx = syscalls::wait_synchronization(&*waitables, None).unwrap();
            info!("Handle idx {} got signaled", idx);
            for item in waiting_on.remove(idx) {
                item.wake()
            }

            waitables.remove(idx);
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

fn common_port_handler<T, DISPATCH>(work_queue: WorkQueue<'static>, port: ServerPort, dispatch: DISPATCH) -> impl Future<Output=()>
where
    DISPATCH: for<'b> FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Clone + Unpin + Send + 'static,
    T: Default + Unpin + Send + 'static,
{
    crate::loop_future::loop_fn((work_queue, dispatch, port), |(work_queue, dispatch, port)| {
        port.wait_async(work_queue.clone())
            .map(move |_| {
                let handle = port.accept().unwrap();
                let future = new_session_wrapper(work_queue.clone(), handle, T::default(), dispatch.clone());
                work_queue.spawn(FutureObj::new(Box::new(future)));
                crate::loop_future::Loop::Continue((work_queue, dispatch, port))
            })
    })
}

pub fn port_handler<T, DISPATCH>(work_queue: WorkQueue<'static>, server_name: &str, dispatch: DISPATCH) -> Result<impl Future<Output=()>, Error>
where
    DISPATCH: for<'b> FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Clone + Unpin + Send + 'static,
    T: Default + Unpin + Send + 'static,
{
    use crate::sm::IUserInterfaceProxy;
    // We use `new()` and not `raw_new()` in order to avoid deadlocking when closing the
    // IUserInterfaceProxy handle. See implementation note in sm/src/main.rs
    let port = IUserInterfaceProxy::new()?.register_service(encode_bytes(server_name), false, 0)?;
    Ok(common_port_handler(work_queue, port, dispatch))
}

pub fn managed_port_handler<T, DISPATCH>(work_queue: WorkQueue<'static>, server_name: &str, dispatch: DISPATCH) -> Result<impl Future<Output=()>, Error>
where
    DISPATCH: for<'b> FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Clone + Unpin + Send + 'static,
    T: Default + Unpin + Send + 'static,
{
    let port = syscalls::manage_named_port(server_name, 0)?;
    Ok(common_port_handler(work_queue, port, dispatch))
}

// Ideally, that's what we would want to write
// But the compiler seems to have trouble reasoning about associated types in
// an HRTB context (maybe that's just not possible ? Not sure)
// async fn new_session_wrapper<F>(mut dispatch: F) -> ()
// where
//     F: for<'a> FnMut<(&'a mut [u8],)>,
//     for<'a> <F as FnOnce<(&'a mut [u8],)>>::Output: Future<Output = Result<(), ()>>,
// {
//     // Session wrapper code
// }

// So instead, we'll make a wrapper for `FnMut` that has the right trait bound
// on its associated output type directly
pub trait FutureCallback<T, O>: FnMut<T> {
    type Ret: Future<Output = O> + Send;

    fn call(&mut self, x: T) -> Self::Ret;
}

// Implement it for all FnMut with Ret = Output
impl<T, O, F: FnMut<T>> FutureCallback<T, O> for F
where
    F::Output: Future<Output = O> + Send,
{
    type Ret = F::Output;

    fn call(&mut self, x: T) -> Self::Ret {
        self.call_mut(x)
    }
}

// And this now magically works
//fn dispatch<'a>            (&'a mut self,    work_queue: WorkQueue<'static>,    cmdid: u32, buf: &'a mut [u8]) -> FutureObj<'a, Result<(), Error>> {
// for<'a> core::ops::FnOnce<(&'a mut IBuffer, libuser::ipc::server::WorkQueue<'static>, u32, &'a mut [u8])>`
//         core::ops::FnOnce<(&mut IBuffer,    libuser::ipc::server::WorkQueue<'_>,      u32, &mut [u8])>`

// `core::ops::FnOnce<(&'0 mut IBuffer, libuser::ipc::server::WorkQueue<'static>, u32, &'0 mut [u8])>`
// would have to be implemented for the type
// `for<'a>         fn(&'a mut IBuffer, libuser::ipc::server::WorkQueue<'static>, u32, &'a mut [u8]) -> futures_core::future::future_obj::FutureObj<'a, core::result::Result<(), libuser::error::Error>> {<IBuffer as libuser::vi::IBuffer>::dispatch}`,
// for some specific lifetime `'0`, but
// `core::ops::FnOnce<(&mut IBuffer, libuser::ipc::server::WorkQueue<'_>, u32, &mut [u8])>`
// is actually implemented for the type
// `for<'a>         fn(&'a mut IBuffer, libuser::ipc::server::WorkQueue<'static>, u32, &'a mut [u8]) -> futures_core::future::future_obj::FutureObj<'a, core::result::Result<(), libuser::error::Error>> {<IBuffer as libuser::vi::IBuffer>::dispatch}`
pub fn new_session_wrapper<T, DISPATCH>(work_queue: WorkQueue<'static>, handle: ServerSession, mut object: T, mut dispatch: DISPATCH) -> impl Future<Output = ()> + Send
where
    DISPATCH: for<'b> FutureCallback<(&'b mut T, WorkQueue<'static>, u32, &'b mut [u8]), Result<(), Error>>,
    DISPATCH: Unpin + Send + 'static,
    T: Unpin + Send + 'static,
{
    let mut buf = Align16([0; 0x100]);
    let mut pointer_buf = [0; 0x300];

    async move {
        loop {
            info!("Waiting for our handle");
            handle.wait_async(work_queue.clone()).await;

            // Push a C Buffer before receiving.
            let mut req = Message::<(), [_; 1], [_; 0], [_; 0]>::new_request(None, 0);
            req.push_in_pointer(&mut pointer_buf, false);
            req.pack(&mut buf[..]);

            handle.receive(&mut buf[..], Some(0)).unwrap();

            let tycmdid = super::find_ty_cmdid(&buf[..]);
            info!("{:?}", tycmdid);

            let close = match super::find_ty_cmdid(&buf[..]) {
                // TODO: Handle other types.
                Some((4, cmdid)) | Some((6, cmdid)) => dispatch.call((&mut object, work_queue.clone(), cmdid, &mut buf[..])).await
                    .map(|_| false)
                    .unwrap_or_else(|err| { error!("Dispatch method errored out: {:?}", err); true }),
                Some((2, _)) => true,
                _ => true
            };

            if close {
                break;
            }

            info!("Replying!");
            handle.reply(&mut buf[..]).unwrap();
        }
    }
}
