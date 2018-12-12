use types::*;
use sm;
use core::mem;
use error::{Error, SmError};

pub struct ViInterface(ClientSession);

impl ViInterface {
    pub fn raw_new() -> Result<ViInterface, Error> {
        use syscalls;

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

    pub fn create_buffer(&mut self, handle: &SharedMemory, top: i32, left: i32, width: u32, height: u32,) -> Result<IBuffer, Error> {
        use ipc::Message;
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
        let mut res : Message<(), [_; 0], [_; 0], [_; 1]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(IBuffer(ClientSession(res.pop_handle_move().unwrap())))
    }
}

pub struct IBuffer(ClientSession);

impl IBuffer {
    pub fn draw(&mut self) -> Result<(), Error> {
        use ipc::Message;
        let mut buf = [0; 0x100];

        let msg = Message::<(), [_; 0], [_; 0], [_; 0]>::new_request(None, 0);
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;
        let res : Message<(), [_; 0], [_; 0], [_; 1]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(())
    }
}
