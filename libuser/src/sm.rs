use types::*;

pub struct IUserInterface(ClientSession);

impl IUserInterface {
	  pub fn raw_new() -> Result<IUserInterface, usize> {
		    use syscalls;

        loop {
            const NOT_REGISTERED: usize = 7 << 9 | 0x21;
		        let _ = match syscalls::connect_to_named_port("sm:\0") {
                Ok(s) => return Ok(IUserInterface(s)),
                Err(NOT_REGISTERED) => syscalls::sleep_thread(0),
                Err(err) => return Err(err)
            };
        }
	  }

    pub fn get_service(&self, name: u64) -> Result<ClientSession, usize> {
		    use ipc::Message;
        let mut buf = [0; 0x100];

		    #[repr(C)] #[derive(Clone, Copy, Default)]
		    struct InRaw {
			      name: u64,
		    }
		    let mut msg = Message::<_, [_; 0], [_; 0], [_; 0]>::new_request(None, 1);
        msg.push_raw(InRaw {
            name,
        });
        msg.pack(&mut buf[..]);

		    self.0.send_sync_request_with_user_buffer(&mut buf[..])?;
		    let mut res : Message<(), [_; 0], [_; 0], [_; 1]> = Message::unpack(&buf[..]);
        res.error()?;
		    Ok(ClientSession(res.pop_handle_move()?))
    }

    pub fn register_service(&self, name: u64, is_light: bool, max_handles: u32) -> Result<ServerPort, usize> {
		    use ipc::Message;
        let mut buf = [0; 0x100];

		    #[repr(C)] #[derive(Clone, Copy, Default)]
		    struct InRaw {
			      name: u64,
			      is_light: bool,
			      max_handles: u32,
		    }
		    let mut msg = Message::<_, [_; 0], [_; 0], [_; 0]>::new_request(None, 2);
        msg.push_raw(InRaw {
            name,
            is_light,
            max_handles,
        });
        msg.pack(&mut buf[..]);

		    self.0.send_sync_request_with_user_buffer(&mut buf[..])?;
		    let mut res : Message<(), [_; 0], [_; 0], [_; 1]> = Message::unpack(&buf[..]);
        res.error()?;
		    Ok(ServerPort(res.pop_handle_move()?))
    }
}
