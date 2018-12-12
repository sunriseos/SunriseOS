use core::marker::PhantomData;
use syscalls;
use core::num::NonZeroU32;
use kfs_libkern::MemoryPermissions;
use error::{Error, KernelError};
use ipc::{Message, MessageTy};
use core::mem;

// Guarantees: A Handle is a u32. An Option<Handle> is *also* a u32, with None
// represented as 0 - useful for the ReplyTarget argument of ReplyAndReceive.
#[repr(transparent)]
#[derive(Debug)]
pub struct Handle(pub(crate) NonZeroU32);

impl Handle {
    pub fn new(handle: u32) -> Handle {
        Handle(NonZeroU32::new(handle).expect("Syscall returned handle 0!?!"))
    }

    pub fn as_ref(&self) -> HandleRef {
        HandleRef {
            inner: self.0,
            lifetime: PhantomData
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        syscalls::close_handle(self.0.get());
    }
}

#[repr(transparent)]
pub struct HandleRef<'a> {
    pub(crate) inner: NonZeroU32,
    lifetime: PhantomData<&'a Handle>
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ReadableEvent(pub Handle);

#[repr(transparent)]
#[derive(Debug)]
pub struct ClientSession(pub Handle);

impl ClientSession {
    pub fn send_sync_request_with_user_buffer(&self, buf: &mut [u8]) -> Result<(), Error> {
        syscalls::send_sync_request_with_user_buffer(buf, self)
            .map_err(|v| v.into())
    }

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

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerSession(pub Handle);

impl ServerSession {
    pub fn receive(&self, buf: &mut [u8], timeout: Option<usize>) -> Result<(), Error> {
        syscalls::reply_and_receive_with_user_buffer(buf, &[self.0.as_ref()], None, timeout).map(|_| ())
            .map_err(|v| v.into())
    }

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


#[repr(transparent)]
#[derive(Debug)]
pub struct ClientPort(pub Handle);

impl ClientPort {
    pub fn connect(&self) -> Result<ClientSession, Error> {
        syscalls::connect_to_port(self)
            .map_err(|v| v.into())
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerPort(pub Handle);

impl ServerPort {
    pub fn accept(&self) -> Result<ServerSession, Error> {
        syscalls::accept_session(self)
            .map_err(|v| v.into())
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct Thread(pub Handle);

impl Thread {
    pub fn start(&self) -> Result<(), Error> {
        syscalls::start_thread(self)
            .map_err(|v| v.into())
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct SharedMemory(pub Handle);

impl SharedMemory {
    pub fn new(length: usize, myperm: MemoryPermissions, otherperm: MemoryPermissions) -> Result<SharedMemory, Error> {
        syscalls::create_shared_memory(length, myperm, otherperm)
            .map_err(|v| v.into())
    }

    pub fn map(self, addr: usize, size: usize, perm: MemoryPermissions) -> Result<MappedSharedMemory, Error> {
        syscalls::map_shared_memory(&self, addr, size, perm)?;
        Ok(MappedSharedMemory {
            handle: self,
            addr,
            size,
        })
    }
}

#[derive(Debug)]
pub struct MappedSharedMemory {
    handle: SharedMemory,
    addr: usize,
    size: usize
}

impl MappedSharedMemory {
    pub unsafe fn get(&self) -> &[u8] {
        ::core::slice::from_raw_parts(self.addr as *const u8, self.size)
    }
    pub unsafe fn get_mut(&self) -> &mut [u8] {
        ::core::slice::from_raw_parts_mut(self.addr as *mut u8, self.size)
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.addr as *const u8
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.addr as *mut u8
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn as_shared_mem(&self) -> &SharedMemory {
        &self.handle
    }
}

impl Drop for MappedSharedMemory {
    fn drop(&mut self) {
        let _ = syscalls::unmap_shared_memory(&self.handle, self.addr, self.size);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub u64);
