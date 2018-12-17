//! Service Manager

use types::*;
use error::{KernelError, Error};

/// Main interface of the service manager. Allows registering and retrieving
/// handles to all the services.
pub struct IUserInterface(ClientSession);

impl IUserInterface {
    /// Connects to the Service Manager.
	  pub fn raw_new() -> Result<IUserInterface, Error> {
		    use syscalls;

        loop {
		        let _ = match syscalls::connect_to_named_port("sm:\0") {
                Ok(s) => return Ok(IUserInterface(s)),
                Err(KernelError::NoSuchEntry) => syscalls::sleep_thread(0),
                Err(err) => Err(err)?
            };
        }
	  }

    /// Retrieves a service registered in the service manager.
    pub fn get_service(&self, name: u64) -> Result<ClientSession, Error> {
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

    /// Registers a service registered in the service manager. Look at the
    /// [create_port](::syscalls::create_port) syscall for more information on
    /// the parameters.
    pub fn register_service(&self, name: u64, is_light: bool, max_handles: u32) -> Result<ServerPort, Error> {
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
