//! FAT driver implementation layer

use alloc::boxed::Box;
use crate::LibUserResult;
use crate::interface::driver::FileSystemDriver;
use crate::interface::storage::{PartitionStorage};
use crate::interface::filesystem::IFileSystem;

use libfat;
use libfat::FatFsType;

mod directory;
mod file;
mod filesystem;
mod error;

use sunrise_libuser::fs::FileSystemType;
use filesystem::FatFileSystem;

use error::from_driver;

/// A FAT driver.
pub struct FATDriver;

impl FileSystemDriver for FATDriver {
    fn construct(&self, storage: PartitionStorage) -> LibUserResult<Box<dyn IFileSystem>> {
        let filesystem_instance = FatFileSystem::from_storage(storage)?;
        Ok(Box::new(filesystem_instance) as Box<dyn IFileSystem>)
    }

    fn is_valid(&self, storage: &mut PartitionStorage) -> bool {
        libfat::get_fat_type(storage, 0).is_ok()
    }

    fn is_supported(&self, filesytem_type: FileSystemType) -> bool {
        match filesytem_type {
            FileSystemType::FAT12 | FileSystemType::FAT16 | FileSystemType::FAT32 => true,
            _ => false
        }
    }

    fn format(&self, storage: PartitionStorage, filesytem_type: FileSystemType) -> LibUserResult<()> {

        let fat_type = match filesytem_type {
            FileSystemType::FAT12 => FatFsType::Fat12,
            FileSystemType::FAT16 => FatFsType::Fat16,
            FileSystemType::FAT32 => FatFsType::Fat32,
            _ => panic!("Unknown FatFsType!")
        };

        libfat::format_raw_partition(storage, fat_type).map_err(from_driver)
    }
}