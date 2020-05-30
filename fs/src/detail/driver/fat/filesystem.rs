//! IFileSystem implementation using libfat.

use crate::LibUserResult;
use sunrise_libuser::error::{Error, FileSystemError};
use super::error::from_driver;
use crate::interface::filesystem::*;

use alloc::boxed::Box;

use sunrise_libuser::fs::{DirectoryEntryType, FileTimeStampRaw, FileSystemType};

use core::fmt;
use core::fmt::{Debug, Formatter};

use libfat::FatFsType;

use alloc::sync::Arc;

use spin::Mutex;

use storage_device::StorageDevice;

use super::file::FileInterface;
use super::directory::DirectoryInterface;
use super::directory::DirectoryFilterPredicate;

use libfat::FileSystemIterator;

use arrayvec::ArrayString;

/// A wrapper arround libfat ``FatFileSystem`` implementing ``FileSystemOperations``.
pub struct FatFileSystem {
    /// libfat filesystem interface.
    inner: Arc<Mutex<libfat::filesystem::FatFileSystem<Box<dyn StorageDevice<Error = Error> + Send>>>>,
}

impl Debug for FatFileSystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FatFileSystem")
         .finish()
    }
}

impl FatFileSystem {
    /// Create a new FAT filesystem instance.
    pub fn new(inner: libfat::filesystem::FatFileSystem<Box<dyn StorageDevice<Error = Error> + Send>>) -> Self {
        FatFileSystem { inner: Arc::new(Mutex::new(inner)) }
    }

    /// Construct a FAT filesystem instance with an IStorage.
    pub fn from_storage(storage: Box<dyn StorageDevice<Error = Error> + Send>) -> LibUserResult<Self> {
        let filesystem = libfat::get_raw_partition(storage).map_err(from_driver)?;
        Ok(Self::new(filesystem))
    }
}


impl FileSystemOperations for FatFileSystem {
    fn create_file(&self, path: &str, size: u64) -> LibUserResult<()> {
        self.inner
            .lock()
            .create_file(path)
            .map_err(from_driver)?;

        let mut file = FileSystemOperations::open_file(self, path, FileModeFlags::APPENDABLE)?;
        file.set_len(size)
    }

    fn create_directory(&self, path: &str) -> LibUserResult<()> {
        self.inner
            .lock()
            .create_directory(path)
            .map_err(from_driver)
    }

    fn rename_file(&self, old_path: &str, new_path: &str) -> LibUserResult<()> {
        self.inner
            .lock()
            .rename_file(old_path, new_path)
            .map_err(from_driver)
    }

    fn rename_directory(&self, old_path: &str, new_path: &str) -> LibUserResult<()> {
        self.inner
            .lock()
            .rename_directory(old_path, new_path)
            .map_err(from_driver)
    }

    fn delete_file(&self, path: &str) -> LibUserResult<()> {
        self.inner
            .lock()
            .delete_file(path)
            .map_err(from_driver)
    }

    fn delete_directory(&self, path: &str) -> LibUserResult<()> {
        self.inner
            .lock()
            .delete_directory(path)
            .map_err(from_driver)
    }

    fn get_entry_type(&self, path: &str) -> LibUserResult<DirectoryEntryType> {
        self.inner
            .lock()
            .search_entry(path)
            .map_err(from_driver)
            .map(|result| {
                if result.attribute.is_directory() {
                    DirectoryEntryType::Directory
                } else {
                    DirectoryEntryType::File
                }
            })
    }

    fn open_file(
        &self,
        path: &str,
        mode: FileModeFlags,
    ) -> LibUserResult<Box<dyn FileOperations>> {
        let file_entry = self
            .inner
            .lock()
            .open_file(path)
            .map_err(from_driver)?;
        let inner_fs = self.inner.clone();
        let res = Box::new(FileInterface::new(inner_fs, file_entry, mode));

        Ok(res as Box<dyn FileOperations>)
    }

    fn open_directory(
        &self,
        path: &str,
        filter: DirFilterFlags,
    ) -> LibUserResult<Box<dyn DirectoryOperations>> {
        let filter_fn: fn(&_) -> bool =
            if (filter & DirFilterFlags::ALL) == DirFilterFlags::ALL {
                DirectoryFilterPredicate::all as _
            } else if (filter & DirFilterFlags::DIRECTORY) == DirFilterFlags::DIRECTORY {
                DirectoryFilterPredicate::dirs as _
            } else {
                DirectoryFilterPredicate::files as _
            };

        let filesystem = self.inner.lock();

        let target_dir = filesystem.open_directory(path).map_err(from_driver)?;

        let mut entry_count = 0u64;

        for entry in target_dir.iter().to_iterator(&filesystem) {
            let entry = entry.map_err(from_driver)?;

            if !filter_fn(&entry) {
                continue;
            }

            entry_count += 1;
        }

        let mut data: ArrayString<[u8; PATH_LEN]> = ArrayString::new();

        if data.try_push_str(path).is_err() {
            return Err(FileSystemError::InvalidInput.into());
        }

        // Add '/' if missing at the end
        if let Some('/') = path.chars().last() {
            // Already valid
        } else if data.try_push('/').is_err() {
            return Err(FileSystemError::InvalidInput.into());
        }

        let res = Box::new(DirectoryInterface::new(
            data,
            self.inner.clone(),
            target_dir.iter(),
            filter_fn,
            entry_count,
        ));

        Ok(res as Box<dyn DirectoryOperations>)
    }

    fn get_free_space_size(&self, _path: &str) -> LibUserResult<u64> {
        self.inner
            .lock()
            .get_free_space_size()
            .map_err(from_driver)
    }

    fn get_total_space_size(&self, _path: &str) -> LibUserResult<u64> {
        self.inner
            .lock()
            .get_total_space_size()
            .map_err(from_driver)
    }

    fn get_file_timestamp_raw(&self, path: &str) -> LibUserResult<FileTimeStampRaw> {
        let file_entry = self
            .inner
            .lock()
            .search_entry(path)
            .map_err(from_driver)?;

        let result = FileTimeStampRaw {
            creation_timestamp: file_entry.creation_timestamp,
            modified_timestamp: file_entry.last_modification_timestamp,
            accessed_timestamp: file_entry.last_access_timestamp,
            is_valid: true,
        };

        Ok(result)
    }

    fn get_filesystem_type(&self) -> FileSystemType {
        match self.inner.lock().get_type() {
            FatFsType::Fat12 => FileSystemType::FAT12,
            FatFsType::Fat16 => FileSystemType::FAT16,
            FatFsType::Fat32 => FileSystemType::FAT32,
        }
    }
}