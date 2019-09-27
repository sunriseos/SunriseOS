
//! Storage related interfaces
//! Those interface allows to simplify IStorage <=> StorageDevice layer.

use crate::LibUserResult;
use sunrise_libuser::error::{Error, FileSystemError};
use storage_device::{BlockDevice, StorageDevice};
use storage_device::storage_device::StorageBlockDevice;
use storage_device::cached_block_device::CachedBlockDevice;
use sunrise_libutils::align_down;
use crate::interface::filesystem::FileOperations;

use alloc::sync::Arc;
use alloc::boxed::Box;
use spin::Mutex;
use core::fmt::Debug;

use sunrise_libutils::align_up;

/// This is the interface for a raw device, usually a block device.
pub trait IStorage : StorageDevice + Debug + Sync + Send {
    /// Set the total size of the storage in bytes.
    fn set_size(&mut self, new_size: u64) -> LibUserResult<()>;
}

#[derive(Debug)]
/// Wrapper over a IStorage that permit to access only a partition.
pub struct PartitionStorage {
    /// The backing IStorage implementation
    inner: Arc<Mutex<Box<dyn IStorage<Error = Error>>>>,

    /// The start of the partition.
    partition_start: u64,

    /// The size of the partition.
    partition_len: u64
}

impl PartitionStorage {
    /// Create a new PartitionStorage
    pub fn new(inner: Arc<Mutex<Box<dyn IStorage<Error = Error>>>>, partition_start: u64, partition_len: u64) -> Self {
        PartitionStorage { inner, partition_start, partition_len}
    }
}

impl StorageDevice for PartitionStorage {
    type Error = Error;

    fn read(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        if offset + buf.len() as u64 > self.len()? {
            return Err(FileSystemError::OutOfRange.into())
        }

        self.inner.lock().read(self.partition_start + offset, buf)
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> Result<(), Error> {
        if offset + buf.len() as u64 > self.len()? {
            return Err(FileSystemError::OutOfRange.into())
        }

        self.inner.lock().write(self.partition_start + offset, buf)
    }

    fn flush(&mut self) -> LibUserResult<()> {
        self.inner.lock().flush()
    }

    fn len(&mut self) -> Result<u64, Error> {
        Ok(self.partition_len)
    }
}

impl IStorage for PartitionStorage {
    fn set_size(&mut self, _new_size: u64) -> LibUserResult<()> {
        Err(FileSystemError::UnsupportedOperation.into())
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct FileStorage<F: FileOperations>(F);

impl<F: FileOperations> FileStorage<F> {
    pub fn new(f: F) -> FileStorage<F> {
        FileStorage(f)
    }
}

impl<F: FileOperations> StorageDevice for FileStorage<F> {
    type Error = Error;

    /// Read the data at the given ``offset`` in the storage into a given buffer.
    fn read(&mut self, offset: u64, mut buf: &mut [u8]) -> LibUserResult<()> {
        while buf.len() != 0 {
            let data_read = FileOperations::read(&mut self.0, offset, buf)?;
            if data_read == 0 {
                return Err(FileSystemError::OutOfRange.into());
            }
            buf = &mut buf[data_read as usize..];
        }
        Ok(())
    }

    /// Write the data from the given buffer at the given ``offset`` in the storage.
    fn write(&mut self, offset: u64, buf: &[u8]) -> LibUserResult<()> {
        FileOperations::write(&mut self.0, offset, buf)
    }

    /// Writes every dirty data to the storage.
    fn flush(&mut self) -> LibUserResult<()> {
        FileOperations::flush(&mut self.0)
    }

    fn len(&mut self) -> Result<u64, Error> {
        FileOperations::get_len(&mut self.0)
    }
}

impl<F: FileOperations> IStorage for FileStorage<F> {
    /// Set the total size of the storage in bytes.
    fn set_size(&mut self, new_size: u64) -> LibUserResult<()> {
        FileOperations::set_len(&mut self.0, new_size)
    }
}

impl<B> IStorage for StorageBlockDevice<B>
where
    B: BlockDevice<Error = Error> + Send + Sync,
    B::Block: Send + Sync
{
    fn set_size(&mut self, new_size: u64) -> Result<(), B::Error> {
        Err(FileSystemError::ReadOnlyFileSystem.into())
    }
}