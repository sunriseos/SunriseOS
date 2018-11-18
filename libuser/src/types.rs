use core::marker::PhantomData;
use syscalls;
use core::num::NonZeroU32;

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
    pub fn send_sync_request_with_user_buffer(&self, buf: &mut [u8]) -> Result<(), usize> {
        syscalls::send_sync_request_with_user_buffer(buf, self)
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerSession(pub Handle);

impl ServerSession {
    pub fn receive(&self, buf: &mut [u8], timeout: Option<usize>) -> Result<(), usize> {
        syscalls::reply_and_receive_with_user_buffer(buf, &[self.0.as_ref()], None, timeout).map(|v| ())
    }

    pub fn reply(&self, buf: &mut [u8]) -> Result<(), usize> {
        syscalls::reply_and_receive_with_user_buffer(buf, &[], Some(self.0.as_ref()), Some(0))
            .map(|v| ()).or_else(|v| if v == 0xEA01 { Ok(())} else { Err(v) })
    }
}


#[repr(transparent)]
#[derive(Debug)]
pub struct ClientPort(pub Handle);

impl ClientPort {
    pub fn connect(&self) -> Result<ClientSession, usize> {
        syscalls::connect_to_port(self)
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerPort(pub Handle);

impl ServerPort {
    pub fn accept(&self) -> Result<ServerSession, usize> {
        syscalls::accept_session(self)
    }
}
