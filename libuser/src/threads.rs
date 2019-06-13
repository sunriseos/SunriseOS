//! Low-level api to create threads and start them.
//!
//! This module defines the low-level representation of a thread, kind to pthread on Unix.
//! You will want to abstract it in the libstd.
//!
//! # Threads on SunriseOS
//!
//! The sunrise kernel provides only three syscalls of interest relative to threads:
//!
//! * [`svcCreateThread`] : allocates kernel resources for a thread and returns a handle to it.
//! * [`svcStartThread`] : starts a thread created by `svcCreateThread`.
//! * [`svcExitThread`] : terminates the current thread.
//!
//! Note that it is impossible to terminate another thread that our own.
//!
//! The first thread of a process (referred later in this doc as "main thread") gets the handle to
//! its own thread in one of its registers when it is started by the kernel.
//!
//! ### TLS region
//!
//! Every thread possesses a small memory region called [Thread Local Storage region] which the kernel
//! allocates, and puts its address in a ro register so it can be accessed from the userspace.
//!
//! There lives the [IpcBuffer], and a userspace controlled pointer where the user can store a
//! user-defined context. We use it to to keep a pointer to a [ThreadContext] (see below).
//!
//! # Threads in libuser
//!
//! The main thread will always live for the entire life of the process.
//! When its routine returns, it calls `svcExitProcess` and every other thread will be killed.
//!
//! It can create other threads, which are represented by the [`Thread`] struct.
//! A `Thread` detaches (read "leak") the associated thread when it is dropped,
//! which means that there is no longer any handle to thread and no way to join on it.
//!
//! This is analog to the way the libstd threads work.
//!
//! ### Thread context
//!
//! For every thread we create (and also for the main thread), we allocate a [ThreadContext]
//! structure on the heap, which holds its stack, its thread handle so it will be able to use
//! mutexes, the routine we want it to execute, and the argument to pass to it.
//!
//! ### Thread entry point
//!
//! We tell the kernel the entry of the thread is [`thread_trampoline`].
//! This function will set-up a valid environment for the routine (mainly handle ELF thread local variables),
//! call the routine with its argument, and finally call `svcExitThread` when the routine has returned.
//!
//! [`svcCreateThread`]: crate::syscalls::create_thread
//! [`svcStartThread`]: crate::syscalls::start_thread
//! [`svcExitThread`]: crate::syscalls::exit_thread
//! [Thread Local Storage region]: sunrise_libkern::TLS
//! [IpcBuffer]: sunrise_libkern::IpcBuffer
//! [ThreadContext]: self::threads::ThreadContext
//! [`Thread`]: self::threads::Thread
//! [`thread_trampoline`]: self::threads::thread_trampoline

use crate::types::Thread as ThreadHandle;
use crate::syscalls;
use crate::error::Error;
use sunrise_libkern::{TLS, IpcBuffer};
use alloc::boxed::Box;
use core::mem::ManuallyDrop;
use core::fmt;
use spin::Once;

/// Size of a thread's stack, in bytes.
const STACK_SIZE: usize = 0x8000;

/// Structure holding the thread local context of a thread.
/// Allocated at thread creation by the creator of the thread.
#[repr(C)]
pub struct ThreadContext {
    /// Pointer to the function this thread should execute after
    /// all its set-up in [thread_trampoline] is done.
    entry_point: fn (usize) -> (),
    /// The argument to call it with.
    arg: usize,
    /// The stack used by this thread.
    ///
    /// `None` for the main thread's stack, since it was not allocated by us
    /// and will never be freed as it'll be the last thread alive.
    ///
    /// `Some` for every other thread.
    stack: Option<Box<[u8; STACK_SIZE]>>,
    /// The ThreadHandle of this thread.
    ///
    /// The thread needs to be able to access its own ThreadHandle at anytime
    /// to be able to use mutexes.
    thread_handle: Once<ThreadHandle>,
}

impl fmt::Debug for ThreadContext {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("ThreadContext")
            .field("entry_point", &self.entry_point)
            .field("arg", &self.arg)
            .field("stack_address", &(self.stack.as_ref().map(|v| v as *const _ as usize).unwrap_or(0)))
            .field("thread_handle", &self.thread_handle)
            .finish()
    }
}

/// Get a pointer to this thread's [TLS] region pointed to by `gs`, translated to the flat-memory model.
#[inline]
fn get_my_tls_region() -> *mut TLS {
    let mut tls: *mut TLS;
    unsafe {
        // get the address of the TLS region from gs:0x00 translated to the flat model
        // safe: gs:0x00 is guaranteed by the kernel to hold a valid pointer to itself.
        asm!("mov $0, gs:0x00" : "=r" (tls) ::: "intel");
    }
    tls
}


/// Get a pointer to this thread's [ThreadContext], from the [TLS] region pointed to by `gs`.
#[inline]
pub fn get_my_thread_context() -> *mut ThreadContext {
    unsafe {
        // safe: just pointer arithmetic
        &(*get_my_tls_region()).ptr_thread_context as *const usize as *mut _
    }
}

/// Get a pointer to this thread's [IPCBuffer], from the [TLS] region pointed to by `gs`.
///
/// [IpcBuffer]: sunrise_libkern::IpcBuffer
#[inline]
pub fn get_my_ipc_buffer() -> *mut IpcBuffer {
    unsafe {
        // safe: just pointer arithmetic
        &(*get_my_tls_region()).ipc_command_buffer as *const _ as *mut _
    }
}

/// Libuser's representation of a thread.
///
/// This is the low-level representation of a thread, kind to `pthread_t` on Unix.
///
/// You can create and start a thread from its `Thread` structure.
///
/// A `Thread` detaches (read "leak resources of") the associated thread when it is dropped,
/// which means that there is no longer any handle to thread and no way to join on it.
///
/// Internally owns the [ThreadContext] for this thread, including its stack.
#[derive(Debug)]
pub struct Thread(ManuallyDrop<Box<ThreadContext>>);

impl Thread {
    /// Start this thread.
    pub fn start(&self) -> Result<(), Error> {
        unsafe {
            syscalls::start_thread(&(*self.0).thread_handle.r#try().unwrap())
            .map_err(|v| v.into())
        }
    }

    /// Allocates resources for a thread. To start it, call [`start`].
    ///
    /// Allocates the stack, sets up the context, and calls `svcCreateThread`.
    ///
    /// [`start`]: Thread::start
    pub fn create(entry: fn (usize) -> (), arg: usize) -> Result<Self, Error> {
        let context = ManuallyDrop::new(Box::new(ThreadContext {
            entry_point: entry,
            arg,
            stack: Some(box [0u8; STACK_SIZE]),
            thread_handle: Once::new(), // will be rewritten in a second
        }));
        match syscalls::create_thread(
            thread_trampoline,
            &**context as *const ThreadContext as usize,
            (&**context.stack.as_ref().unwrap() as *const u8).wrapping_add(STACK_SIZE),
            0,
            0) {
            Err(err) => {
                error!("Failed to create thread {:?}: {}", &*context, err);
                // dealloc the stack and context
                drop(ManuallyDrop::into_inner(context));
                Err(err.into())
            }
            Ok(thread_handle) => {
                // finally, push the handle to the context.
                context.thread_handle.call_once(|| { thread_handle });
                debug!("Allocated new thread: {:?}", context);

                Ok(Self(context))
            }
        }
    }
}

/// Small stub executed by every thread but the main thread when they start.
///
/// Saves the pointer to their [ThreadContext] in their [TLS], performs copy of `.tdata` and `.tbss`,
/// calls the routine this thread was meant to perform, and calls `svcExitThread` when it's finished.
///
/// # ABI
///
/// This function is the entry point of a thread, called directly by the kernel, with the
/// argument passed by [Thread::create].
/// It expects this argument to be the address of its `ThreadContext` so it can save it its `TLS`.
///
/// The routine to call and its argument are expected to be found in this `ThreadContext`.
extern "fastcall" fn thread_trampoline(thread_context_addr: usize) -> ! {
    debug!("starting from new thread, context at address {:#010x}", thread_context_addr);
    // first save the address of our context in our TLS region
    unsafe { (*get_my_tls_region()).ptr_thread_context = thread_context_addr };

    let thread_context_addr = thread_context_addr as *mut ThreadContext;

    // call the routine saved in the context, passing it the arg saved in the context
    unsafe {
        ((*thread_context_addr).entry_point)((*thread_context_addr).arg)
    }

    debug!("exiting thread");
    syscalls::exit_thread()
}


impl Drop for Thread {
    fn drop(&mut self) {
        // todo: Properly free resource after thread detach
        // body: When detaching a thread, we should ensure that the associated resources (stack,
        // body: handle, context, etc...) are properly freed before the Process exits. This can be
        // body: done by adding the ThreadContext to a global Vec<> of ThreadContext that gets freed
        // body: when the main thread (or the last thread alive?) exits.
    }
}
