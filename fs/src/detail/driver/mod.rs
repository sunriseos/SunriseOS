//! Contains driver implementations of file system.

pub mod fat;

use alloc::boxed::Box;
use alloc::vec::Vec;
use spin::Mutex;

use crate::LibUserResult;
use crate::interface::driver::FileSystemDriver;
use crate::interface::filesystem::FileSystemOperations;

use storage_device::block::Block;
use storage_device::block_device::*;
use storage_device::storage_device::StorageBlockDevice;
use storage_device::cached_block_device::CachedBlockDevice;

use sunrise_libuser::fs::{DiskId, FileSystemType, PartitionId};
use sunrise_libuser::ahci::*;
use sunrise_libuser::ahci::Block as AhciBlock;
use sunrise_libuser::error::{Error, FileSystemError};

use lazy_static::lazy_static;
use alloc::sync::{Arc, Weak};
use crate::interface::storage::{PartitionStorage, IStorage};

use hashbrown::HashMap;

/// A type to let clippy slide over it.
type PartitionHashMap<T> = HashMap<DiskId, HashMap<PartitionId, Weak<Mutex<T>>>>;

/// A boxed IStorage using the proper Error type.
type BoxedIStorage = Box<dyn IStorage<Error = Error>>;

/// Instance handling drivers registration and usage.
pub struct DriverManager {
    /// The registry of the drivers availaible.
    registry: Vec<Box<dyn FileSystemDriver>>,

    /// The drives actually opened.
    drives: HashMap<DiskId, Arc<Mutex<BoxedIStorage>>>,

    /// The partitions opened in drives.
    partitions: PartitionHashMap<Box<dyn FileSystemOperations>>,

    /// AHCI IPC interface.
    ahci_interface: AhciInterfaceProxy
}

impl Default for DriverManager {
    fn default() -> Self {
        DriverManager {
            registry: Vec::new(),
            ahci_interface: AhciInterfaceProxy::raw_new().expect("Cannot create AHCI interface"),
            drives: HashMap::new(),
            partitions: HashMap::new()
        }
    }
}

impl DriverManager {
    /// Register a new driver
    pub fn register_driver(&mut self, driver: Box<dyn FileSystemDriver>) {
        self.registry.push(driver);
    }

    /// Add a new drive to the open hashmap.
    pub fn add_opened_drive(&mut self, disk_id: DiskId, drive: Arc<Mutex<BoxedIStorage>>) {
        self.drives.insert(disk_id, drive);
        self.partitions.insert(disk_id, HashMap::new());
    }

    /// Do the disk init using AHCI
    pub fn init_drives(&mut self) -> LibUserResult<()> {
        let disk_count = self.ahci_interface.discovered_disks_count()?;
        if disk_count == 0 {
            warn!("No drive have been found!");
        }

        for disk_id in 0..disk_count {
            let ahci_disk = self.ahci_interface.get_disk(disk_id)?;
            let device = Arc::new(Mutex::new(Box::new(StorageBlockDevice::new(CachedBlockDevice::new(AhciDiskStorage::new(ahci_disk), 0x100))) as BoxedIStorage));
            self.add_opened_drive(disk_id, device);
        }

        Ok(())
    }

    /// Open a AHCI disk as a IStorage.
    pub fn open_disk_storage(&mut self, disk_id: DiskId) -> LibUserResult<Arc<Mutex<BoxedIStorage>>> {
        self.drives.get(&disk_id).ok_or_else(|| FileSystemError::DiskNotFound.into()).map(|arc| arc.clone())
    }

    /// Get the count of disks availaible.
    pub fn get_disks_count(&mut self) -> u32 {
        self.drives.len() as u32
    }

    /// Open an instance of a filesystem.
    pub fn construct_filesystem_from_disk_partition(&mut self, disk_id: DiskId, partition_id: PartitionId, mut storage: PartitionStorage) -> LibUserResult<Arc<Mutex<Box<dyn FileSystemOperations>>>> {
        let disk_hashmap_opt  = self.partitions.get_mut(&disk_id);
        if disk_hashmap_opt.is_none() {
            return Err(FileSystemError::DiskNotFound.into())
        }

        let disk_hashmap = disk_hashmap_opt.unwrap();
        let cached_res: LibUserResult<_> = disk_hashmap.get(&partition_id).ok_or_else(|| FileSystemError::InvalidPartition.into()).map(|arc| arc.upgrade());

        // If the value is in cache just return it
        if let Ok(Some(res)) = cached_res {
            return Ok(res);
        }

        // No instance found, create a new one and cache it.
        for driver in &self.registry {
            if driver.probe(&mut storage).is_some() {
                let res = Arc::new(Mutex::new(driver.construct(Box::new(storage))?));

                disk_hashmap.insert(partition_id, Arc::downgrade(&res));
                return Ok(res)
            }
        }

        Err(FileSystemError::InvalidPartition.into())
    }

    /// Format a partition storage to a given filesystem.
    pub fn format_disk_partition(&self, storage: PartitionStorage, filesytem_type: FileSystemType) -> LibUserResult<()> {
        for driver in &self.registry {
            if driver.is_supported(filesytem_type) {
                return driver.format(Box::new(storage), filesytem_type)
            }
        }

        Err(FileSystemError::InvalidPartition.into())
    }
}

lazy_static! {
    pub static ref DRIVER_MANAGER: Mutex<DriverManager> = Mutex::default();
}

#[derive(Debug)]
/// A wrapper to a ahci IDisk.
pub struct AhciDiskStorage {
    /// The inner IDisk.
    inner: IDiskProxy
}

impl AhciDiskStorage {
    /// Create a new AhciDiskStorage.
    pub fn new(device: IDiskProxy) -> Self {
        AhciDiskStorage {
            inner: device
        }
    }
}

impl BlockDevice for AhciDiskStorage {
    type Block = Block;
    type Error = Error;

    /// Read blocks from the block device starting at the given ``index``.
    fn read(&mut self, blocks: &mut [Self::Block], index: BlockIndex) -> Result<(), Error> {
        self.inner.read_dma(index.0, unsafe {
            // Safety: This operation is safe as AhciBlock and Block have the same memory representation and the same alignment requirements.
            core::slice::from_raw_parts_mut(blocks.as_mut_ptr() as *mut AhciBlock, blocks.len())
        })
    }

    /// Write blocks to the block device starting at the given ``index``.
    fn write(&mut self, blocks: &[Self::Block], index: BlockIndex) -> Result<(), Error> {
        self.inner.write_dma(index.0, unsafe {
            // Safety: This operation is safe as AhciBlock and Block have the same memory representation and the same alignment requirements.
            core::slice::from_raw_parts(blocks.as_ptr() as *const AhciBlock, blocks.len())
        })
    }

    /// Return the amount of blocks hold by the block device.
    fn count(&mut self) -> Result<BlockCount, Error> {
        self.inner.sector_count().map(|result| BlockCount(result))
    }
}
