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

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerSession(pub Handle);

#[repr(transparent)]
#[derive(Debug)]
pub struct ClientPort(pub Handle);

#[repr(transparent)]
#[derive(Debug)]
pub struct ServerPort(pub Handle);

impl ServerPort {
    pub fn accept(&self) -> Result<ServerSession, usize> {
        syscalls::accept_session(self)
    }
}
