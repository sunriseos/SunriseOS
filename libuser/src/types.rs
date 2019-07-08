//! Core kernel types.
//!
//! This module contains all the core types of the libuser. Most objects in this
//! modules are newtypes around Handle.

use core::marker::PhantomData;
use crate::syscalls;
use core::num::NonZeroU32;
use sunrise_libkern::MemoryPermissions;
use crate::error::{Error, KernelError};
use crate::ipc::{Message, MessageTy};
use core::mem;

/// A Handle is a sort of reference to a Kernel Object. Its underlying
/// representation is that of a u32. Furthermore, an Option<Handle> is also
/// guaranteed to be represented on a u32, with None represented as 0. This
/// allows handle to be used directly in the syscall functions.
///
/// Handles are closed automatically when Dropped via [close_handle].
///
/// [close_handle]: crate::syscalls::close_handle.
#[repr(transparent)]
#[derive(Debug)]
pub struct Handle(pub(crate) NonZeroU32);

impl Handle {
    /// Creates a new handle from the given number. This number should come from
    /// a raw syscall. Constructing a handle from an arbitrary number is not
    /// unsafe, but may lead to extremely confusing code.
    pub fn new(handle: u32) -> Handle {
        Handle(NonZeroU32::new(handle).expect("Syscall returned handle 0!?!"))
    }

    /// Creates a new reference to this handle. See the documentation of
    /// [HandleRef] for more information.
    pub fn as_ref(&self) -> HandleRef<'_> {
        HandleRef {
            inner: self.0,
            lifetime: PhantomData
        }
    }

    /// Creates a new static reference to this handle. See the documentation of
    /// [HandleRef] for more information.
    ///
    /// The kernel guarantees that a Handle is never reused. If the parent [Handle]
    /// dies before this HandleRef is dropped, every function taking this HandleRef
    /// will fail with [sunrise_libkern::error::KernelError::InvalidHandle]
    pub fn as_ref_static(&self) -> HandleRef<'static> {
        HandleRef {
            inner: self.0,
            lifetime: PhantomData
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        match self.0.get() {
            0xFFFF8000 | 0xFFFF8001 => (),
            handle => { let _ = syscalls::close_handle(handle); },
        }
    }
}

/// A fake reference to a Handle. Has the same representation as a real Handle,
/// but is bound to the real handle's lifetime.
///
/// This pattern allows for passing handle arrays without giving up ownership of
/// the handle, and without an expensive conversion from an array of pointers to
/// an array of handles.
#[repr(transparent)]
#[derive(Debug)]
pub struct HandleRef<'a> {
    /// The underlying handle number.
    pub(crate) inner: NonZeroU32,
    /// The real handle this reference is tied to.
    lifetime: PhantomData<&'a Handle>
}

/// A handle on an IRQ event.
#[repr(transparent)]
#[derive(Debug)]
pub struct IRQEvent(pub Handle);

/// The readable part of an event. The user shall use this end to verify if the
/// event is signaled, and wait for the signaling through wait_synchronization.
/// The user can also use this handle to clear the signaled state through
/// [ReadableEvent::clear_signal()].
#[repr(transparent)]
#[derive(Debug)]
pub struct ReadableEvent(pub Handle);

impl ReadableEvent {
    /// Clears the signaled state.
    pub fn clear_signal(&self) -> Result<(), KernelError> {
        syscalls::clear_event(self.0.as_ref())
    }
}


/// The writable part of an event. The user shall use this end to signal (and
/// wake up threads waiting on the event).
pub struct WritableEvent(pub Handle);

impl WritableEvent {
    /// Clears the signaled state.
    pub fn clear_signal(&self) -> Result<(), KernelError> {
        syscalls::clear_event(self.0.as_ref())
    }

    /// Signals the event, setting its state to signaled and waking up any
    /// thread waiting on its value.
    pub fn signal(&self) -> Result<(), KernelError> {
        syscalls::signal_event(self)
    }
}

/// The client side of an IPC session.
///
/// Usually obtained by connecting to a service through the sm: service manager.
/// However, an anonymous session pair might be created through the
/// [create_session] syscall, or by calling [connect_to_named_port].
///
/// [create_session]: crate::syscalls::create_session
/// [connect_to_named_port]: crate::syscalls::connect_to_named_port
#[repr(transparent)]
#[derive(Debug)]
pub struct ClientSession(pub Handle);

impl ClientSession {
    /// Send an IPC request to the handle, and wait for a response. The passed
    /// buffer should contain the request on input, and will contain the reply
    /// on output.
    ///
    /// This is a low-level primitives that is usually wrapped by a higher-level
    /// library. Look at the [ipc module] for more information on the IPC
    /// message format.
    ///
    /// [ipc module]: crate::ipc
    pub fn send_sync_request_with_user_buffer(&self, buf: &mut [u8]) -> Result<(), Error> {
        syscalls::send_sync_request_with_user_buffer(buf, self)
            .map_err(|v| v.into())
    }

    /// Consumes the session, returning the underlying handle. Note that closing
    /// a Handle without sending a close IPC message will leak the object in the
    /// sysmodule. You should always reconstruct the ClientSession from the
    /// Handle before dropping it.
    pub fn into_handle(self) -> Handle {
        let handle = Handle((self.0).0);
        mem::forget(self);
        handle
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        let mut buf = [0; 0x100];
		    let mut msg = Message::<(), [_; 0], [_; 0], [_; 0]>::new_request(None, 1);
        msg.set_ty(MessageTy::Close);
        msg.pack(&mut buf[..]);
		    let _ = self.send_sync_request_with_user_buffer(&mut buf[..]);
    }
}

/// The server side of an IPC session.
///
/// Usually obtained by calling [accept], but may also be obtained by calling 
/// the [create_session] syscall, providing a server/client session pair.
///
/// [accept]: ServerPort::accept
/// [create_session]: crate::syscalls::create_session
#[repr(transparent)]
#[derive(Debug)]
pub struct ServerSession(pub Handle);

impl ServerSession {
    /// Receives an IPC request from the session, waiting if none are available
    /// yet. The buffer should contain an empty message, optionally containing a
    /// C descriptor, and will contain the reply on output.
    ///
    /// If a C descriptor is provided, it will be used as the buffer to copy the
    /// request's X descriptor into.
    ///
    /// This is a low-level primitives that is usually wrapped by a higher-level
    /// library. Look at the [ipc module] for more information on the IPC
    /// message format.
    ///
    /// [ipc module]: crate::ipc
    pub fn receive(&self, buf: &mut [u8], timeout: Option<usize>) -> Result<(), Error> {
        syscalls::reply_and_receive_with_user_buffer(buf, &[self.0.as_ref()], None, timeout).map(|_| ())
            .map_err(|v| v.into())
    }

    /// Replies to an IPC request on the given session. If the given session did
    /// not have a pending request, this function will error out.
    /// 
    /// This is a low-level primitives that is usually wrapped by a higher-level
    /// library. Look at the [ipc module] for more information on the IPC
    /// message format.
    ///
    /// [ipc module]: crate::ipc
    pub fn reply(&self, buf: &mut [u8]) -> Result<(), Error> {
        syscalls::reply_and_receive_with_user_buffer(buf, &[], Some(self.0.as_ref()), Some(0))
            .map(|_| ())
            .or_else(|v| if KernelError::Timeout == v {
                Ok(())
            } else {
                Err(v)
            })
            .map_err(|v| v.into())
    }
}

/// The client side of an IPC Port. Allows connecting to an IPC server, providing
/// a session to call remote procedures on.
///
/// Obtained by creating an anonymous port pair with the [create_port] syscall.
///
/// [create_port]: crate::syscalls::create_port
#[repr(transparent)]
#[derive(Debug)]
pub struct ClientPort(pub Handle);

impl ClientPort {
    /// Connects to a port, returning a session on which to send IPC request.
    pub fn connect(&self) -> Result<ClientSession, Error> {
        syscalls::connect_to_port(self)
            .map_err(|v| v.into())
    }
}

/// The server side of an IPC Port. Allows listening for connections, providing
/// a session on which to answer remote procedures from.
///
/// Usually obtained by registering a service through the sm: service manager, or
/// by calling [manage_named_port] to obtained a kernel-managed port.
///
/// [manage_named_port]: crate::syscalls::manage_named_port
#[repr(transparent)]
#[derive(Debug)]
pub struct ServerPort(pub Handle);

impl ServerPort {
    /// Accepts a connection to the port, returning a server session on which to
    /// listen and reply to IPC request.
    pub fn accept(&self) -> Result<ServerSession, Error> {
        syscalls::accept_session(self)
            .map_err(|v| v.into())
    }
}

/// A Thread. Created with the [create_thread syscall].
///
/// See the [threads] module.
///
/// [create_thread syscall]: crate::syscalls::create_thread.
/// [threads]: crate::threads
#[repr(transparent)]
#[derive(Debug)]
pub struct Thread(pub Handle);

impl Thread {
    /// Gets the current process handle. Uses the 0xFFFF8000 meta-handle, which
    /// may not be valid in all contexts!
    fn current() -> Thread {
        Thread(Handle::new(0xFFFF8000))
    }
}

/// A Process. Created with `create_process` syscall, or by calling
/// [Process::current()].
#[repr(transparent)]
#[derive(Debug)]
pub struct Process(pub Handle);

impl Process {
    /// Gets the current process handle. Uses the 0xFFFF8001 meta-handle, which
    /// may not be valid in all contexts!
    fn current() -> Process {
        Process(Handle::new(0xFFFF8001))
    }
}

/// A handle to memory that may be mapped in multiple processes at the same time.
///
/// Special care should be used to ensure multiple processes do not write to the
/// memory at the same time, or only does so through the use of atomic
/// operations. Otherwise, UB will occur! 
#[repr(transparent)]
#[derive(Debug)]
pub struct SharedMemory(pub Handle);

impl SharedMemory {
    /// Creates a new Shared Memory handle. The physical memory underlying this
    /// shared memory will span `length` bytes.
    ///
    /// Myperm and otherperm are masks of which permissions are allowed when
    /// mapping the shared memory in the current process and other processes
    /// respectively.
    pub fn new(length: usize, myperm: MemoryPermissions, otherperm: MemoryPermissions) -> Result<SharedMemory, Error> {
        syscalls::create_shared_memory(length, myperm, otherperm)
            .map_err(|v| v.into())
    }

    /// Maps the current shared memory at the given address, consuming the handle
    /// and returning a MappedMemoryRegion. Note that the size must be equal to
    /// the length of the SharedMemory.
    pub fn map(self, addr: usize, size: usize, perm: MemoryPermissions) -> Result<MappedSharedMemory, Error> {
        syscalls::map_shared_memory(&self, addr, size, perm)?;
        Ok(MappedSharedMemory {
            handle: self,
            addr,
            size,
        })
    }
}

/// A mapping to a shared memory region.
///
/// When dropped, the memory region will be unmapped, and the SharedMemory handle
/// associated with it will be closed.
#[derive(Debug)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct MappedSharedMemory {
    handle: SharedMemory,
    addr: usize,
    size: usize
}

#[allow(clippy::len_without_is_empty)] // len cannot be zero.
impl MappedSharedMemory {
    /// Get the underlying shared memory as a byte slice.
    ///
    /// # Safety
    ///
    /// No attempt is made at synchronizing access. This (apparently) read-only
    /// slice might be modified by another process. It is recommended to use
    /// [`as_ptr`] and volatile reads to avoid Undefined Behavior,
    /// unless the application has a way to synchronize access.
    ///
    /// [`as_ptr`]: MappedSharedMemory::as_ptr
    pub unsafe fn get(&self) -> &[u8] {
        ::core::slice::from_raw_parts(self.addr as *const u8, self.size)
    }

    /// Get the underlying shared memory as a mutable byte slice.
    ///
    /// # Safety
    ///
    /// No attempt is made at synchronizing access. This (apparently) read-only
    /// slice might be modified by another process. It is recommended to use
    /// [`as_mut_ptr`] and volatile writes to avoid Undefined Behavior,
    /// unless the application has a way to synchronize access.
    ///
    /// [`as_mut_ptr`]: MappedSharedMemory::as_mut_ptr
    pub unsafe fn get_mut(&mut self) -> &mut [u8] {
        ::core::slice::from_raw_parts_mut(self.addr as *mut u8, self.size)
    }

    /// Gets a raw pointer to the underlying shared memory.
    pub fn as_ptr(&self) -> *const u8 {
        self.addr as *const u8
    }

    /// Gets a mutable raw pointer to the underlying shared memory.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.addr as *mut u8
    }

    /// Gets the byte length of the mapped shared memory.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Return a reference to the underlying shared memory. Useful to send a copy
    /// of the handle of an already mapped shared memory via IPC.
    pub fn as_shared_mem(&self) -> &SharedMemory {
        &self.handle
    }
}

impl Drop for MappedSharedMemory {
    fn drop(&mut self) {
        let _ = syscalls::unmap_shared_memory(&self.handle, self.addr, self.size);
    }
}

/// Process ID, as returned by IPC.
///
/// Each process in Horizon is given a unique, non-reusable PID. It may be used
/// to associate capabilities or resources to a particular process. For instance,
/// sm might associate a process' service access permissions to its pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub u64);
