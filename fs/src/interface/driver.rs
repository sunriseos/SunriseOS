//! Driver interfaces
//! Allows to dectect and select filesystem drivers accordingly.

use alloc::boxed::Box;

use sunrise_libuser::fs::FileSystemType;
use crate::LibUserResult;
use super::storage::PartitionStorage;
use super::filesystem::IFileSystem;

/// Driver instance.
pub trait FileSystemDriver: Send {
    /// Construct a new filesystem instance if the driver identify the storage as a valid one.
    fn construct(&self, storage: PartitionStorage) -> LibUserResult<Box<dyn IFileSystem>>;

    /// Check if the given storage hold a filesystem supported by this driver.
    fn is_valid(&self, storage: &mut PartitionStorage) -> bool;

    /// Check if this driver support the given filesystem type.
    fn is_supported(&self, filesytem_type: FileSystemType) -> bool;

    /// Format a given storage to hold a filesystem supported by this driver.
    fn format(&self, storage: PartitionStorage, filesytem_type: FileSystemType) -> LibUserResult<()>;
}


