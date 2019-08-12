//! Definition of the `LoopFn` combinator, implementing `Future` loops.
//!
//! Shamelessly stolen from [the old futures](https://docs.rs/futures/0.1.27/futures/future/fn.loop_fn.html).
use core::future::Future;
use core::task::Context;
use core::pin::Pin;
use core::marker::Unpin;

#[doc(hidden)]
pub use core::task::Poll;

macro_rules! ready {
    ($e:expr) => (match $e {
        $crate::loop_future::Poll::Ready(t) => t,
        $crate::loop_future::Poll::Pending =>
            return $crate::loop_future::Poll::Pending,
    })
}

/// The status of a `loop_fn` loop.
#[derive(Debug)]
pub enum Loop<T, S> {
    /// Indicates that the loop has completed with output `T`.
    Break(T),

    /// Indicates that the loop function should be called again with input
    /// state `S`.
    Continue(S),
}

/// A future implementing a tail-recursive loop.
///
/// Created by the `loop_fn` function.
#[derive(Debug)]
pub struct LoopFn<A, F> {
    /// Future representing the current loop iteration.
    future: A,
    /// Function called on every new iteration to generate that iteration's
    /// future
    func: F,
}

/// Creates a new future implementing a tail-recursive loop.
///
/// The loop function is immediately called with `initial_state` and should
/// return a value that can be converted to a future. On successful completion,
/// this future should output a `Loop<T, S>` to indicate the status of the
/// loop.
///
/// `Loop::Break(T)` halts the loop and completes the future with output `T`.
///
/// `Loop::Continue(S)` reinvokes the loop function with state `S`. The returned
/// future will be subsequently polled for a new `Loop<T, S>` value.
///
/// # Examples
///
/// ```
/// use sunrise_libutils::loop_future::{loop_fn, Loop};
/// use core::future::Future;
/// use futures::future::{FutureExt, ready};
///
/// struct Client {
///     ping_count: u8,
/// }
///
/// impl Client {
///     fn new() -> Self {
///         Client { ping_count: 0 }
///     }
///
///     fn send_ping(self) -> impl Future<Output=Self> {
///         ready(Client { ping_count: self.ping_count + 1 })
///     }
///
///     fn receive_pong(self) -> impl Future<Output=(Self, bool)> {
///         let done = self.ping_count >= 5;
///         ready((self, done))
///     }
/// }
///
/// let ping_til_done = loop_fn(Client::new(), |client| {
///     client.send_ping()
///         .then(|client| client.receive_pong())
///         .map(|(client, done)| {
///             if done {
///                 Loop::Break(client)
///             } else {
///                 Loop::Continue(client)
///             }
///         })
/// });
/// ```
pub fn loop_fn<S, T, A, F>(initial_state: S, mut func: F) -> LoopFn<A, F>
    where F: FnMut(S) -> A,
          A: Future<Output = Loop<T, S>> + Unpin,
{
    LoopFn {
        future: func(initial_state),
        func: func,
    }
}

impl<S, T, A, F> Future for LoopFn<A, F>
    where F: FnMut(S) -> A,
          A: Future<Output = Loop<T, S>> + Unpin,
          Self: Unpin
{
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        loop {
            match ready!(Pin::new(&mut self.future).poll(cx)) {
                Loop::Break(x) => return Poll::Ready(x),
                Loop::Continue(s) => self.future = (&mut self.func)(s),
            }
        }
    }
}