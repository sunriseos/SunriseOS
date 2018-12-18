//! Service Manager
//!
//! Services are system processes running in the background which wait for
//! incoming requests. When a process wants to communicate with a service, it
//! first needs to get a handle to the named service, and then it can communicate
//! with the service via inter-process communication (each service has a name up
//! to 8 characters).
//!
//! Handles for services are retrieved from the service manager port, "sm:", and
//! are released via svcCloseHandle or when a process is terminated or crashes.
//! Manager service "sm:m" also exists. Services are an abstraction of ports,
//! they operate the same way except regular ports can have their handles
//! retrieved directly from a SVC. Services are also able to limit the number of
//! handles given to other processes.

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

    /// Registers a service registered in the service manager.
    ///
    /// Look at the [create_port] syscall for more information on the parameters.
    ///
    /// [create_port]: ::syscalls::create_port
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
