//! Driver interfaces
//! Allows to detect and select *filesystem drivers* (e.g. FAT32, ext2, nfs, ...) accordingly.

use alloc::boxed::Box;

use sunrise_libuser::fs::FileSystemType;
use crate::LibUserResult;
use super::storage::PartitionStorage;
use super::filesystem::IFileSystem;

/// Driver instance.
pub trait FileSystemDriver: Send {
    /// Construct a new filesystem instance if the driver identifies the storage as a valid one.
    fn construct(&self, storage: PartitionStorage) -> LibUserResult<Box<dyn IFileSystem>>;

    /// Proble the detected filesystem on the given partition.
    fn probe(&self, storage: &mut PartitionStorage) -> Option<FileSystemType>;

    /// Check if this driver support the given filesystem type.
    fn is_supported(&self, filesytem_type: FileSystemType) -> bool;

    /// Format a given storage to hold a filesystem supported by this driver.
    fn format(&self, storage: PartitionStorage, filesytem_type: FileSystemType) -> LibUserResult<()>;
}


