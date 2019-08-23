//! FAT filesystem implementation of DirectoryOperations
use crate::LibUserResult;
use crate::interface::storage::PartitionStorage;
use crate::interface::filesystem::*;

use libfat::FatFileSystemResult;
use libfat::directory::dir_entry::DirectoryEntry as FatDirectoryEntry;
use libfat::directory::dir_entry_iterator::DirectoryEntryIterator as FatDirectoryEntryIterator;
use super::error::from_driver;
use core::fmt;
use spin::Mutex;
use alloc::sync::Arc;

use sunrise_libuser::fs::{DirectoryEntry, DirectoryEntryType};
use libfat::FileSystemIterator;

/// Predicate helper used to filter directory entries.
pub struct DirectoryFilterPredicate;

impl DirectoryFilterPredicate {
    /// Accept all entries except "." & "..".
    pub fn all(entry: &FatFileSystemResult<FatDirectoryEntry>) -> bool {
        if entry.is_err() {
            return false;
        }

        if let Ok(entry) = entry {
            let name = entry.file_name.as_str();
            name != "." && name != ".."
        } else {
            false
        }
    }

    /// Only accept directory entries.
    pub fn dirs(entry: &FatFileSystemResult<FatDirectoryEntry>) -> bool {
        if entry.is_err() {
            return false;
        }

        if let Ok(entry_val) = entry {
            entry_val.attribute.is_directory() && Self::all(entry)
        } else {
            false
        }
    }

    /// Only accept file entries.
    pub fn files(entry: &FatFileSystemResult<FatDirectoryEntry>) -> bool {
        if entry.is_err() {
            return false;
        }

        if let Ok(entry_val) = entry {
            !entry_val.attribute.is_directory() && Self::all(entry)
        } else {
            false
        }
    }
}

/// A libfat directory reader implementing ``DirectoryOperations``.
pub struct DirectoryInterface {
    /// The opened directory path. Used to get the complete path of every entries.
    base_path: [u8; PATH_LEN],

    /// libfat filesystem interface.
    inner_fs: Arc<Mutex<libfat::filesystem::FatFileSystem<PartitionStorage>>>,

    /// The iterator used to iter over libfat's directory entries.
    internal_iter: FatDirectoryEntryIterator,

    /// The filter required by the user.
    filter_fn: fn(&FatFileSystemResult<FatDirectoryEntry>) -> bool,

    /// The number of entries in the directory after ``filter_fn``.
    entry_count: u64,
}

impl fmt::Debug for DirectoryInterface {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("DirectoryInterface")
           .field("base_path", &&self.base_path[..])
           .field("entry_count", &self.entry_count)
           .finish()
    }
}

impl<'a> DirectoryInterface {
    /// Create a new DirectoryInterface.
    pub fn new(base_path: [u8; PATH_LEN], inner_fs: Arc<Mutex<libfat::filesystem::FatFileSystem<PartitionStorage>>>, internal_iter: FatDirectoryEntryIterator, filter_fn: fn(&FatFileSystemResult<FatDirectoryEntry>) -> bool, entry_count: u64) -> Self {
        DirectoryInterface { base_path, inner_fs, internal_iter, filter_fn, entry_count }
    }

    /// convert libfat's DirectoryEntry to libfs's DirectoryEntry.
    fn convert_entry(
        fat_dir_entry: FatDirectoryEntry,
        base_path: &[u8; PATH_LEN],
    ) -> DirectoryEntry {
        let mut path: [u8; PATH_LEN] = [0x0; PATH_LEN];

        let file_size = fat_dir_entry.file_size;

        let directory_entry_type = if fat_dir_entry.attribute.is_directory() {
            DirectoryEntryType::Directory
        } else {
            DirectoryEntryType::File
        };

        let mut base_index = 0;

        loop {
            let c = base_path[base_index];
            if c == 0x0 {
                break;
            }

            path[base_index] = c;
            base_index += 1;
        }

        for (index, c) in fat_dir_entry
            .file_name
            .as_bytes()
            .iter()
            .enumerate()
            .take(PATH_LEN - base_index)
        {
            path[base_index + index] = *c;
        }

        DirectoryEntry {
            path,
            // We don't support the archive bit so we always return 0.
            attribute: 0,
            directory_entry_type,
            file_size: u64::from(file_size),
        }
    }
}

impl DirectoryOperations for DirectoryInterface {
    fn read(&mut self, buf: &mut [DirectoryEntry]) -> LibUserResult<u64> {
        for (index, entry) in buf.iter_mut().enumerate() {
            let mut raw_dir_entry;
            loop {
                let filesystem = self.inner_fs.lock();
                let entry_opt = self.internal_iter.next(&filesystem);

                // Prematury ending
                if entry_opt.is_none() {
                    return Ok(index as u64);
                }

                raw_dir_entry = entry_opt.unwrap();
                let filter_fn = self.filter_fn;

                if filter_fn(&raw_dir_entry) {
                    break;
                }
            }

            *entry = Self::convert_entry(
                raw_dir_entry.map_err(from_driver)?,
                &self.base_path,
            );
        }

        // everything was read correctly
        Ok(buf.len() as u64)
    }

    fn entry_count(&self) -> LibUserResult<u64> {
        Ok(self.entry_count)
    }
}