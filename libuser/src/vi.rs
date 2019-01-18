//! Vi Compositor service

use crate::types::*;
use crate::sm;
use core::mem;
use crate::error::{Error, SmError};

/// Main compositor interface.
pub struct ViInterface(ClientSession);

impl ViInterface {
    /// Connects to the vi service.
    pub fn raw_new() -> Result<ViInterface, Error> {
        use crate::syscalls;

        loop {
            let svcname = unsafe {
                mem::transmute(*b"vi:\0\0\0\0\0")
            };
            let _ = match sm::IUserInterface::raw_new()?.get_service(svcname) {
                Ok(s) => return Ok(ViInterface(s)),
                Err(Error::Sm(SmError::ServiceNotRegistered, ..)) => syscalls::sleep_thread(0),
                Err(err) => return Err(err)
            };
        }
    }

    /// Create a new window of the given size at the given position. The handle
    /// should contain a framebuffer of size width * height * 4 (aligned up to page_size). Its
    /// content will be copied to the screen on each call to draw(), or when
    /// another buffer calls draw whose position intersects with this buffer.
    pub fn create_buffer(&mut self, handle: &SharedMemory, top: i32, left: i32, width: u32, height: u32,) -> Result<IBuffer, Error> {
        use crate::ipc::Message;
        let mut buf = [0; 0x100];

        #[repr(C)] #[derive(Clone, Copy, Default)]
        struct InRaw {
            top: i32,
            left: i32,
            width: u32,
            height: u32,
        }
        let mut msg = Message::<_, [_; 0], [_; 1], [_; 0]>::new_request(None, 0);
        msg.push_raw(InRaw {
            top, left, width, height
        });
        msg.push_handle_copy(handle.0.as_ref());
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;
        let mut res : Message<'_, (), [_; 0], [_; 0], [_; 1]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(IBuffer(ClientSession(res.pop_handle_move().unwrap())))
    }
}

/// A handle to a window. Created through the create_buffer function on
/// ViInterface. If dropped, the window will be closed.
#[derive(Debug)]
pub struct IBuffer(ClientSession);

impl IBuffer {
    /// Ask the compositor to redraw the window. This will cause the compositor
    /// to redraw every window intersecting with this one as well.
    pub fn draw(&mut self) -> Result<(), Error> {
        use crate::ipc::Message;
        let mut buf = [0; 0x100];

        let msg = Message::<(), [_; 0], [_; 0], [_; 0]>::new_request(None, 0);
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;
        let res : Message<'_, (), [_; 0], [_; 0], [_; 1]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(())
    }
}
