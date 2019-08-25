//! FAT filesystem implementation of FileOperations
use crate::LibUserResult;
use super::error::from_driver;
use crate::interface::storage::PartitionStorage;
use crate::interface::filesystem::*;

use libfat::directory::File;

use spin::Mutex;
use alloc::sync::Arc;

use sunrise_libuser::error::FileSystemError;

use core::fmt;

/// A libfat file interface implementing ``FileOperations``.
pub struct FileInterface {
    /// libfat filesystem interface.
    inner_fs: Arc<Mutex<libfat::filesystem::FatFileSystem<PartitionStorage>>>,

    /// The libfat's directory entry of this file.
    file_inner: File,

    /// File mode flags.
    mode: FileModeFlags
}

impl fmt::Debug for FileInterface {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("FileInterface")
           .field("file_info", &self.file_inner.file_info)
           .field("mode", &self.mode)
           .finish()
    }
}


impl FileInterface {
    /// Create a new FileInterface.
    pub fn new(inner_fs: Arc<Mutex<libfat::filesystem::FatFileSystem<PartitionStorage>>>, file_inner: File, mode: FileModeFlags) -> Self {
        FileInterface { inner_fs, file_inner, mode }
    }
}

impl FileOperations for FileInterface {
    /// Read the content of a file at a given ``offset`` in ``buf``.
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> LibUserResult<u64> {
        if (self.mode & FileModeFlags::READABLE) != FileModeFlags::READABLE {
            return Err(FileSystemError::AccessDenied.into());
        }

        self.file_inner
            .read(&self.inner_fs.lock(), offset, buf)
            .map_err(from_driver)
    }

    fn write(&mut self, offset: u64, buf: &[u8]) -> LibUserResult<()> {
        if (self.mode & FileModeFlags::WRITABLE) != FileModeFlags::WRITABLE {
            return Err(FileSystemError::AccessDenied.into());
        }

        self.file_inner
            .write(
                &self.inner_fs.lock(),
                offset,
                buf,
                (self.mode & FileModeFlags::APPENDABLE) == FileModeFlags::APPENDABLE,
            )
            .map_err(from_driver)
    }

    fn flush(&mut self) -> LibUserResult<()> {
        // NOP
        Ok(())
    }

    fn set_len(&mut self, size: u64) -> LibUserResult<()> {
        self.file_inner
            .set_len(&self.inner_fs.lock(), size)
            .map_err(from_driver)
    }

    fn get_len(&mut self) -> LibUserResult<u64> {
        Ok(u64::from(self.file_inner.file_info.file_size))
    }
}