//! Interface to manipulate filesystem

use alloc::boxed::Box;

use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType, FileTimeStampRaw, FileSystemType};
use sunrise_libuser::error::FileSystemError;
use crate::LibUserResult;

/// Represent the max path size (in bytes) supported.
pub const PATH_LEN: usize = 0x301;

/// Import a UTF8 raw path to a slice of str
fn convert_path(raw_path: &[u8]) -> LibUserResult<&str> {
    core::str::from_utf8(raw_path).ok()
        .and_then(|str_path: &str| str_path.split('\0').next())
        .ok_or_else(|| FileSystemError::InvalidInput.into())
}

bitflags! {
    /// Flags indicating the way a file should be open.
    pub struct FileModeFlags: u32 {
        // The file should be readable.
        const READABLE = 0b0000_0001;

        // The file should be writable.
        const WRITABLE = 0b0000_0010;

        // The file should be appendable.
        const APPENDABLE = 0b0000_0100;
    }
}

bitflags! {
    /// Flags indicating the filters when walking a directory.
    pub struct DirFilterFlags: u32 {
        /// Accept directories.
        const DIRECTORY = 0b0000_0001;

        /// Accept files.
        const FILE = 0b0000_0010;

        /// Do not filter anything.
        const ALL = Self::DIRECTORY.bits | Self::FILE.bits;
    }
}

/// Represent a filesystem.
pub trait IFileSystem : FileSystemOperations {
    /// Create a file with a given ``size`` at the specified ``path``.
    fn create_file(&self, path: &[u8], size: u64) -> LibUserResult<()> {
        FileSystemOperations::create_file(self, convert_path(path)?, size)
    }

    /// Create a directory at the specified ``path``.
    fn create_directory(&self, path: &[u8]) -> LibUserResult<()> {
        FileSystemOperations::create_directory(self, convert_path(path)?)
    }

    /// Rename a file at ``old_path`` into ``new_path``.
    fn rename_file(&self, old_path: &[u8], new_path: &[u8]) -> LibUserResult<()> {
        FileSystemOperations::rename_file(self, convert_path(old_path)?, convert_path(new_path)?)
    }

    /// Rename a directory at ``old_path`` into ``new_path``
    fn rename_directory(&self, old_path: &[u8], new_path: &[u8]) -> LibUserResult<()> {
        FileSystemOperations::rename_directory(self, convert_path(old_path)?, convert_path(new_path)?)
    }

    /// Delete a file at the specified ``path``.
    fn delete_file(&self, path: &[u8]) -> LibUserResult<()> {
        FileSystemOperations::delete_file(self, convert_path(path)?)
    }

    /// Delete a directory at the specified ``path``.
    fn delete_directory(&self, path: &[u8]) -> LibUserResult<()> {
        FileSystemOperations::delete_directory(self, convert_path(path)?)
    }

    /// Get the informations about an entry on the filesystem.
    fn get_entry_type(&self, path: &[u8]) -> LibUserResult<DirectoryEntryType> {
        FileSystemOperations::get_entry_type(self, convert_path(path)?)
    }

    /// Open a file at the specified ``path`` with the given ``mode`` flags.
    fn open_file(
        &self,
        path: &[u8],
        mode: u32,
    ) -> LibUserResult<Box<dyn FileOperations>> {
        let flags_res: LibUserResult<_> = FileModeFlags::from_bits(mode).ok_or_else(|| FileSystemError::InvalidInput.into());
        FileSystemOperations::open_file(self, convert_path(path)?, flags_res?)
    }

    /// Open a directory at the specified ``path`` with the given ``mode`` flags.
    fn open_directory(
        &self,
        path: &[u8],
        filter: u32,
    ) -> LibUserResult<Box<dyn DirectoryOperations>> {
        let flags_ret: LibUserResult<_> = DirFilterFlags::from_bits(filter).ok_or_else(|| FileSystemError::InvalidInput.into());
        FileSystemOperations::open_directory(self, convert_path(path)?, flags_ret?)
    }

    /// Get the total availaible space on the given filesystem.
    fn get_free_space_size(&self, path: &[u8]) -> LibUserResult<u64> {
        FileSystemOperations::get_free_space_size(self, convert_path(path)?)
    }

    /// Get the total size of the filesystem.
    fn get_total_space_size(&self, path: &[u8]) -> LibUserResult<u64> {
        FileSystemOperations::get_total_space_size(self, convert_path(path)?)
    }

    /// Return the attached timestamps on a resource at the given ``path``.
    fn get_file_timestamp_raw(&self, path: &[u8]) -> LibUserResult<FileTimeStampRaw> {
        FileSystemOperations::get_file_timestamp_raw(self, convert_path(path)?)
    }

    /// Get the inner filesystem operations reference.
    fn as_operations(&self) -> &dyn FileSystemOperations;

    /// Get the inner filesystem operations mutable reference.
    fn as_operations_mut(&mut self) -> &mut dyn FileSystemOperations;
}

/// Represent the operation on a file.
pub trait FileOperations : core::fmt::Debug + Sync + Send {
    /// Read the content of a file at a given ``offset`` in ``buf``.
    fn read(&mut self, offset: u64, buf: &mut [u8]) -> LibUserResult<u64>;

    /// Write the content given ``buf`` at the given ``offset`` in the file.
    /// If the file is too small to hold the data and the appendable flag is set, it will resize the file and append the data.
    /// If the file is too small to hold the data and the appendable flag isn't set, this will return a FileSystemError::NoSpaceLeft.
    fn write(&mut self, offset: u64, buf: &[u8]) -> LibUserResult<()>;

    /// Flush any data not written on the filesystem.
    fn flush(&mut self) -> LibUserResult<()>;

    /// Resize the file with the given ``size``.
    /// If the file isn't open with the appendable flag, it will not be extendable and will return a FileSystemError::NoSpaceLeft.
    fn set_len(&mut self, size: u64) -> LibUserResult<()>;

    /// Return the current file size.
    fn get_len(&mut self) -> LibUserResult<u64>;
}

/// Represent the operation on a directory.
pub trait DirectoryOperations : core::fmt::Debug + Sync + Send {
    /// Read the next directory entries and return the number of entries read.
    fn read(&mut self, buf: &mut [DirectoryEntry]) -> LibUserResult<u64>;

    /// Return the count of entries in the directory.
    fn entry_count(&self) -> LibUserResult<u64>;
}

/// Represent the operation on a filesystem.
pub trait FileSystemOperations : core::fmt::Debug + Sync + Send {
    /// Create a file with a given ``size`` at the specified ``path``.
    fn create_file(&self, path: &str, size: u64) -> LibUserResult<()>;

    /// Create a directory at the specified ``path``.
    fn create_directory(&self, path: &str) -> LibUserResult<()>;

    /// Rename a file at ``old_path`` into ``new_path``.
    fn rename_file(&self, old_path: &str, new_path: &str) -> LibUserResult<()>;

    /// Rename a directory at ``old_path`` into ``new_path``
    fn rename_directory(&self, old_path: &str, new_path: &str) -> LibUserResult<()>;

    /// Delete a file at the specified ``path``.
    fn delete_file(&self, path: &str) -> LibUserResult<()>;

    /// Delete a directory at the specified ``path``.
    fn delete_directory(&self, path: &str) -> LibUserResult<()>;

    /// Get the informations about an entry on the filesystem.
    fn get_entry_type(&self, path: &str) -> LibUserResult<DirectoryEntryType>;

    /// Open a file at the specified ``path`` with the given ``mode`` flags.
    fn open_file(
        &self,
        path: &str,
        mode: FileModeFlags,
    ) -> LibUserResult<Box<dyn FileOperations>>;

    /// Open a directory at the specified ``path`` with the given ``mode`` flags.
    fn open_directory(
        &self,
        path: &str,
        filter: DirFilterFlags,
    ) -> LibUserResult<Box<dyn DirectoryOperations>>;

    /// Get the total availaible space on the given filesystem.
    fn get_free_space_size(&self, path: &str) -> LibUserResult<u64>;

    /// Get the total size of the filesystem.
    fn get_total_space_size(&self, path: &str) -> LibUserResult<u64>;

    /// Return the attached timestamps on a resource at the given ``path``.
    fn get_file_timestamp_raw(&self, path: &str) -> LibUserResult<FileTimeStampRaw>;

    /// Get the type of the filesystem
    fn get_filesystem_type(&self) -> FileSystemType;
}

impl<T: FileSystemOperations + Sized> IFileSystem for T {
    fn as_operations(&self) -> &dyn FileSystemOperations {
        self
    }

    fn as_operations_mut(&mut self) -> &mut dyn FileSystemOperations {
        self
    }
}