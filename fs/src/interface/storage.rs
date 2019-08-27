
//! Storage related interfaces
//! Those interface allows to simplify IStorage <=> StorageDevice layer.

use crate::LibUserResult;
use sunrise_libuser::error::{Error, FileSystemError};
use storage_device::{Block, BlockDevice, CachedBlockDevice, BlockIndex, StorageDevice, StorageDeviceResult, StorageDeviceError};

use alloc::sync::Arc;
use alloc::boxed::Box;
use spin::Mutex;
use core::fmt::Debug;

use sunrise_libutils::align_up;

/// This is the interface for a raw device, usually a block device.
pub trait IStorage : Debug + Sync + Send {
    /// Read the data at the given ``offset`` in the storage into a given buffer.
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> LibUserResult<()>;

    /// Write the data from the given buffer at the given ``offset`` in the storage.
    fn write(&mut self, offset: u64, buf: &[u8]) -> LibUserResult<()>;

    /// Writes every dirty data to the storage.
    fn flush(&mut self) -> LibUserResult<()>;

    /// Set the total size of the storage in bytes.
    fn set_size(&mut self, new_size: u64) -> LibUserResult<()>;

    /// Return the total size of the storage in bytes.
    fn get_size(&mut self) -> LibUserResult<u64>;
}

/// Implementation of storage device and IStorage for block device.
pub struct StorageCachedBlockDevice<B> where B: BlockDevice + Sync + Send {
    /// The inner block device.
    block_device: CachedBlockDevice<B>,
    /// The block used for unaligned read/write
    temp_storage: [Block; 1],
}

impl<B> Debug for StorageCachedBlockDevice<B> where B: BlockDevice + Sync + Send {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("StorageCachedBlockDevice")
           .field("block_device", &self.block_device)
           .finish()
    }
}

impl<B> StorageCachedBlockDevice<B> where B: BlockDevice + Sync + Send {
    /// Create a new storage block device.
    pub fn new(block_device: B, cap: usize) -> Self {
        StorageCachedBlockDevice {
            block_device: CachedBlockDevice::new(block_device, cap),
            temp_storage: [Block::new()],
        }
    }

    /// Read data at offset to the temp_storage block and copy a part of it to buf.
    /// 
    /// Helper used for unaligned read of parts.
    /// 
    /// # Panics
    /// 
    /// - buf.len() < Block::LEN
    /// - offset / Block::LEN == (offset + buf.len() - 1) / Block::LEN
    fn read_from_temp_storage(&mut self, offset: u64, buf: &mut [u8]) -> StorageDeviceResult<()> {
        assert_ne!(buf.len(), 0);
        assert!(offset / Block::LEN_U64 == (offset + buf.len() as u64 - 1) / Block::LEN_U64, "{:016x} {:016x}", offset, buf.len());

        // Extract the block index containing the data.
        let current_block_index = BlockIndex(offset / Block::LEN_U64);

        // Extract the offset inside the block containing the data.
        let current_block_offset = (offset % Block::LEN_U64) as usize;

        // Read the block.
        self.block_device.read(&mut self.temp_storage, current_block_index)?;

        // copy the needed content
        buf.copy_from_slice(&self.temp_storage[0][current_block_offset .. current_block_offset + buf.len()]);

        Ok(())
    }
}

impl<B> StorageDevice for StorageCachedBlockDevice<B> where B: BlockDevice + Sync + Send {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> StorageDeviceResult<()> {
        let mut buf = buf;
        let mut current_offset = offset;

        let block_alignment = core::mem::align_of::<Block>();

        // First of all, if buf address is unaligned, we need to do a read for one byte and align it.
        if buf.as_ptr() as usize % block_alignment != 0 {
            self.read_from_temp_storage(current_offset, &mut buf[..block_alignment - 1])?;

            // Align buf to Block.
            buf = &mut buf[block_alignment - 1..];

            // This will cause offset to not be block aligned but well... this is the worst case scenario so it's fine.
            current_offset += block_alignment as u64 - 1;
        }

        // Extract the block index containing the data.
        let mut current_block_index = BlockIndex(current_offset / Block::LEN_U64);

        let current_block_offset = current_offset % Block::LEN_U64;

        // If the offset isn't aligned, read unaliged data and align offset for the "middle" read.
        if current_block_offset != 0 || buf.len() < Block::LEN
        {
            // Limit copy to the size of a block or lower.
            let buf_limit = if buf.len() + current_block_offset as usize >= Block::LEN {
                Block::LEN - current_block_offset as usize
            } else {
                buf.len()
            };

            // do the read safely.
            self.read_from_temp_storage(current_offset, &mut buf[..buf_limit])?;

            // Now that unaligned data are read, we align everything for the "middle" read.

            // Update offsets
            current_offset = align_up(current_offset, Block::LEN_U64);
            current_block_index = BlockIndex(current_offset / Block::LEN_U64);

            buf = &mut buf[buf_limit..];
        }

        // Now read the "middle" if needed.
        if !buf.is_empty() {
            let main_blocks = unsafe {
                // Safety: Safe because we guarantee that buf_addr follow the layout and alignment of Block.
                core::slice::from_raw_parts_mut(buf.as_ptr() as *mut Block, buf.len() / Block::LEN)
            };

            self.block_device.read(main_blocks, current_block_index)?;

            buf = &mut buf[main_blocks.len() * Block::LEN..];
            current_offset += main_blocks.len() as u64 * Block::LEN_U64;
        }

        // We have unaliged data to read at the end.
        if !buf.is_empty() {
            self.read_from_temp_storage(current_offset, buf)?;
        }

        Ok(())
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> StorageDeviceResult<()> {
        let mut write_size = 0u64;
        let mut blocks = [Block::new()];

        while write_size < buf.len() as u64 {
            // Compute the next offset of the data to write.
            let current_offset = offset + write_size;

            // Extract the block index containing the data.
            let current_block_index = BlockIndex(current_offset / Block::LEN_U64);

            // Extract the offset inside the block containing the data.
            let current_block_offset = current_offset % Block::LEN_U64;

            // Read the block.
            self.block_device.read(&mut blocks, BlockIndex(current_block_index.0))?;

            // Slice on the part of the buffer we need.
            let buf_slice = &buf[write_size as usize..];

            // Limit copy to the size of a block or lower.
            let buf_limit = if buf_slice.len() + current_block_offset as usize >= Block::LEN {
                Block::LEN - current_block_offset as usize
            } else {
                buf_slice.len()
            };

            let block_slice = &mut blocks[0][current_block_offset as usize..];

            // Copy the data from the buffer.
            for (index, buf_entry) in block_slice.iter_mut().take(buf_limit).enumerate() {
                *buf_entry = buf_slice[index];
            }

            self.block_device.write(&blocks, BlockIndex(current_block_index.0))?;

            // Increment with what we wrote.
            write_size += buf_limit as u64;
        }

        Ok(())
    }

    fn len(&mut self) -> StorageDeviceResult<u64> {
        Ok(self.block_device.count()?.into_bytes_count())
    }
}

/// Convert a StorageDeviceError to a libuser error.
fn storage_error_to_libuser_error(error: StorageDeviceError) -> Error {
    match error {
        StorageDeviceError::ReadError => FileSystemError::ReadFailed,
        StorageDeviceError::WriteError => FileSystemError::WriteFailed,
        _ => FileSystemError::Unknown
    }.into()
}

/// Convert a libuser error to a StorageDeviceError.
fn libuser_error_to_storage_error(error: Error) -> StorageDeviceError {
    match error {
        Error::FileSystem(error, _) => {
            match error {
                FileSystemError::ReadFailed => StorageDeviceError::ReadError,
                FileSystemError::WriteFailed => StorageDeviceError::WriteError,
                _ => StorageDeviceError::Unknown,
            }
        },
        _ => StorageDeviceError::Unknown
    }
}

#[derive(Debug)]
/// Wrapper over a IStorage that permit to access only a partition.
pub struct PartitionStorage {
    /// The backing IStorage implementation
    inner: Arc<Mutex<Box<dyn IStorage>>>,

    /// The start of the partition.
    partition_start: u64,

    /// The size of the partition.
    partition_len: u64
}

impl PartitionStorage {
    /// Create a new PartitionStorage
    pub fn new(inner: Arc<Mutex<Box<dyn IStorage>>>, partition_start: u64, partition_len: u64) -> Self {
        PartitionStorage { inner, partition_start, partition_len}
    }
}

impl StorageDevice for PartitionStorage {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> StorageDeviceResult<()> {
        IStorage::read(self, offset, buf).map_err(libuser_error_to_storage_error)
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> StorageDeviceResult<()> {
        // Write and force a flush
        // TODO: add flush directly to StorageDevice and make use of it inside the drivers.
        IStorage::write(self, offset, buf).map_err(libuser_error_to_storage_error)?;
        IStorage::flush(self).map_err(libuser_error_to_storage_error)
    }

    fn len(&mut self) -> StorageDeviceResult<u64> {
        IStorage::get_size(self).map_err(libuser_error_to_storage_error)
    }
}

impl IStorage for PartitionStorage {
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> LibUserResult<()> {
        if offset + buf.len() as u64 > self.get_size()? {
            return Err(FileSystemError::OutOfRange.into())
        }

        self.inner.lock().read(self.partition_start + offset, buf)
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> LibUserResult<()> {
        if offset + buf.len() as u64 > self.get_size()? {
            return Err(FileSystemError::OutOfRange.into())
        }

        self.inner.lock().write(self.partition_start + offset, buf)
    }

    fn flush(&mut self) -> LibUserResult<()> {
        self.inner.lock().flush()
    }

    fn set_size(&mut self, _new_size: u64) -> LibUserResult<()> {
        Err(FileSystemError::UnsupportedOperation.into())
    }

    fn get_size(&mut self) -> LibUserResult<u64> {
        Ok(self.partition_len)
    }
}

impl<B> IStorage for StorageCachedBlockDevice<B> where B: BlockDevice + Sync + Send {
    /// Read the data at the given ``offset`` in the storage into a given buffer.
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> LibUserResult<()> {
        StorageDevice::read(self, offset, buf).map_err(storage_error_to_libuser_error)
    }

    /// Write the data from the given buffer at the given ``offset`` in the storage.
    fn write(&mut self, offset: u64, buf: &[u8]) -> LibUserResult<()> {
        StorageDevice::write(self, offset, buf).map_err(storage_error_to_libuser_error)
    }

    /// Writes every dirty data to the storage.
    fn flush(&mut self) -> LibUserResult<()> {
        self.block_device.flush().map_err(|error| storage_error_to_libuser_error(error.into()))
    }

    /// Set the total size of the storage in bytes.
    fn set_size(&mut self, _new_size: u64) -> LibUserResult<()> {
        Err(FileSystemError::UnsupportedOperation.into())
    }

    /// Return the total size of the storage in bytes.
    fn get_size(&mut self) -> LibUserResult<u64> {
        self.len().map_err(storage_error_to_libuser_error)
    }
}