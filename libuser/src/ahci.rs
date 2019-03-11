//! Interface to the AHCI driver service

use crate::types::*;
use crate::sm;
use core::mem;
use crate::error::{Error, SmError};
use crate::ipc::Message;

/// Main ahci interface.
///
/// Can communicate the number of discovered devices,
/// and get an interface to a specific device.
#[derive(Debug)]
pub struct AhciInterface(ClientSession);

impl AhciInterface {
    /// Connects to the ahci service.
    pub fn raw_new() -> Result<Self, Error> {
        use crate::syscalls;

        loop {
            let svcname = unsafe {
                mem::transmute(*b"ahci:\0\0\0")
            };
            let _ = match sm::IUserInterface::raw_new()?.get_service(svcname) {
                Ok(s) => return Ok(Self(s)),
                Err(Error::Sm(SmError::ServiceNotRegistered, ..)) => syscalls::sleep_thread(0),
                Err(err) => return Err(err)
            };
        }
    }

    /// Asks to the ahci service how many disks it has discovered.
    ///
    /// [get_disk] accepts disk ids in `0..discovered_disks_count()`.
    ///
    /// [get_disk]: AhciInterface::get_disk
    pub fn discovered_disks_count(&mut self) -> Result<u32, Error> {
        let mut buf = [0; 0x100];

        let msg = Message::<(), [_; 0], [_; 0], [_; 0]>::new_request(None, 0);
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;

        let res: Message<'_, u32, [_; 0], [_; 0], [_; 0]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(res.raw())
    }

    /// Gets the interface to a disk.
    ///
    /// This creates a session connected to an [IDisk].
    ///
    /// `disk_id` should be in `0..discovered_disk_count()`.
    pub fn get_disk(&mut self, disk_id: u32) -> Result<IDisk, Error> {
        use crate::ipc::Message;
        let mut buf = [0; 0x100];

        let mut msg = Message::<_, [_; 0], [_; 1], [_; 0]>::new_request(None, 1);
        msg.push_raw(disk_id);
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;
        let mut res : Message<'_, (), [_; 0], [_; 0], [_; 1]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(IDisk(ClientSession(res.pop_handle_move().unwrap())))
    }
}

/// Interface to an AHCI device.
///
/// It can:
///
/// - get the number of addressable 512-octet sectors on this disk,
/// - read a range of consecutive sectors.
/// - write a range of consecutive sectors.
#[derive(Debug)]
pub struct IDisk(ClientSession);

impl IDisk {
    /// Retrieves the number of addressable 512-octet sectors on this disk.
    pub fn sectors_count(&mut self) -> Result<u64, Error> {
        let mut buf = [0; 0x100];

        let msg = Message::<(), [_; 0], [_; 0], [_; 0]>::new_request(None, 0);
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;

        let res: Message<'_, u64, [_; 0], [_; 0], [_; 0]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(res.raw())
    }

    /// Reads sectors from the disk.
    ///
    /// This IPC call will invoke the AHCI driver and make it copy `sector_count` sectors from the disk
    /// to the memory pointed to by `handle`.
    /// You should map `handle` in your process to access the copied data.
    ///
    /// # Error
    ///
    /// - The handle should contain a buffer at least `sector_count * 512` octets in size.
    /// - `mapping_size` should reflect the size of `handle`.
    /// - `address..address+sector_count` should be in the range `0..IDisk.sector_count()`.
    pub fn read_dma(&mut self, handle: &SharedMemory, mapping_size: u64, address: u64, sector_count: u64) -> Result<(), Error> {
        let mut buf = [0; 0x100];

        #[repr(C)] #[derive(Clone, Copy, Default)]
        #[allow(clippy::missing_docs_in_private_items)]
        struct InRaw {
            mapping_size: u64,
            addr: u64,
            count: u64,
        }
        let mut msg = Message::<_, [_; 0], [_; 1], [_; 0]>::new_request(None, 1);
        msg.push_raw(InRaw {
            mapping_size: mapping_size,
            addr: address,
            count: sector_count
        });
        msg.push_handle_copy(handle.0.as_ref());
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;

        let res: Message<'_, (), [_; 0], [_; 0], [_; 0]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(())
    }

    /// Writes sectors to the disk.
    ///
    /// This IPC call will invoke the AHCI driver and make it copy `sector_count` sectors to the disk
    /// from the memory pointed to by `handle`.
    /// You should map `handle` in your process first to fill the data to be copied.
    ///
    /// # Error
    ///
    /// - The handle should contain a buffer at least `sector_count * 512` octets in size.
    /// - `mapping_size` should reflect the size of `handle`.
    /// - `address..address+sector_count` should be in the range `0..IDisk.sector_count()`.
    pub fn write_dma(&mut self, handle: &SharedMemory, mapping_size: u64, address: u64, sector_count: u64) -> Result<(), Error> {
        let mut buf = [0; 0x100];

        #[repr(C)] #[derive(Clone, Copy, Default)]
        #[allow(clippy::missing_docs_in_private_items)]
        struct InRaw {
            mapping_size: u64,
            addr: u64,
            count: u64,
        }
        let mut msg = Message::<_, [_; 0], [_; 1], [_; 0]>::new_request(None, 2);
        msg.push_raw(InRaw {
            mapping_size: mapping_size,
            addr: address,
            count: sector_count
        });
        msg.push_handle_copy(handle.0.as_ref());
        msg.pack(&mut buf[..]);

        self.0.send_sync_request_with_user_buffer(&mut buf[..])?;

        let res: Message<'_, (), [_; 0], [_; 0], [_; 0]> = Message::unpack(&buf[..]);
        res.error()?;
        Ok(())
    }
}
