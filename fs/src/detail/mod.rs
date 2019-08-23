//! Detail module
//! 
//! Contains implementations of various trait defined in the interface module.

use sunrise_libuser::fs::{DiskId, FileSystemType, PartitionId};
use alloc::boxed::Box;
use alloc::sync::Arc;
use crate::LibUserResult;
use crate::interface::storage::{PartitionStorage, IStorage};
use crate::interface::filesystem::FileSystemOperations;
use storage_device::Block;
use sunrise_libuser::error::{FileSystemError};

use crc::{crc32, Hasher32};
use spin::Mutex;
use uuid::Uuid;

use alloc::vec::Vec;
use byteorder::{LE, ByteOrder};

pub mod driver;
mod gpt;
mod utils;

use gpt::{GPTHeader, GPTPartitionEntry};
use utils::lba_to_cls;

use driver::DRIVER_MANAGER;

/// Manage partition of a IStorage.
pub struct PartitionManager<'a> {
    /// The IStorage used.
    inner: &'a mut dyn IStorage
}

impl<'a> PartitionManager<'a> {
    /// Create a new partition manager.
    pub fn new(inner: &'a mut dyn IStorage) -> Self {
        PartitionManager { inner }
    }

    /// Check if the partition table is valid.
    #[allow(clippy::wrong_self_convention)]
    pub fn is_valid(&mut self) -> bool {
        let res = GPTHeader::from_storage_device(self.inner, 1);

        if let Ok(res) = res {
            return res.is_valid()
        }

        false
    }

    /// Create a protective MBR
    pub fn create_protective_mbr(&mut self) -> LibUserResult<()> {
        let mut mbr = [0x0; Block::LEN];

        let partition_offset = 1;
        let partition_number = 1;
        let head_count = 64;
        let mut sector_count = self.inner.get_size()? / Block::LEN_U64;
        if sector_count > u64::from(u32::max_value()) {
            sector_count = u64::from(u32::max_value());
        }

        let (head_number, sector_number, cylinder_number) = lba_to_cls(partition_number, head_count, sector_count);

        // Setup first fake partition.
        mbr[0x1BE] = 0x0; // not bootable

        // start CHS
        mbr[0x1BF] = head_number;
        mbr[0x1C0] = sector_number;
        mbr[0x1C1] = cylinder_number;

        // GPT protective
        mbr[0x1C2] = 0xEE;

        let (head_number, sector_number, cylinder_number) = lba_to_cls(sector_count - 1, head_count, sector_count);

        // end CHS
        mbr[0x1C3] = head_number;
        mbr[0x1C4] = sector_number;
        mbr[0x1C5] = cylinder_number;

        // finally start/end LBA.
        LE::write_u32(&mut mbr[0x1C6..0x1CA], partition_offset as u32);
        LE::write_u32(&mut mbr[0x1CA..0x1CE], sector_count as u32 - partition_offset);

        // And finally the "valid signature"
        mbr[0x1FE] = 0x55;
        mbr[0x1FF] = 0xAA;

        self.inner.write(0, &mbr)?;
        self.inner.flush()
    }

    /// Initialize a IStorage partition table.
    pub fn initialize(&mut self) -> LibUserResult<()> {
        self.create_protective_mbr()?;
        let sector_count = self.inner.get_size()? / Block::LEN_U64;

        assert!(sector_count > 34, "The storage is too small to hold a GPT partition schema");

        // first setup the GPT header
        let mut primary_gpt_header = GPTHeader::default();

        // one disk id for the sake of completness
        primary_gpt_header.set_disk_guid(Uuid::parse_str("CAFECAFE-CAFE-CAFE-CAFE-CAFECAFECAFE").unwrap());
        primary_gpt_header.current_lba = 1;
        primary_gpt_header.backup_lba = sector_count - 1;
        primary_gpt_header.first_usable = 34;
        primary_gpt_header.last_usable = sector_count - 34;
        primary_gpt_header.partition_table_start = 2;

        let mut partition_table = Vec::new();

        let mut main_partition = GPTPartitionEntry::default();
        // Microsoft basic data GUID
        main_partition.set_partition_type(Uuid::parse_str("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").unwrap());

        // Some GUID selected for the sake of randomness
        main_partition.set_unique_id(Uuid::parse_str("BA3E4ADC-EB06-11E7-8AD3-9570BEC474F8").unwrap());

        // some name
        main_partition.set_name("SunriseOS System");

        // Set the start of the partition at the first LBA availaible.
        main_partition.first_lba = 34;

        // Set the last LBA just before the backup GPT
        main_partition.last_lba = sector_count - 34;

        partition_table.push(main_partition);

        // By standard, there should be at least 128 entries in the partition table.
        if partition_table.len() < 128 {
            partition_table.resize(128, GPTPartitionEntry::default());
        }

        primary_gpt_header.partition_entry_count = partition_table.len() as u32;

        let main_partition_bytes = main_partition.write();

        let mut partition_table_digest = crc32::Digest::new(crc32::IEEE);


        for (i, partition) in partition_table.iter().enumerate() {
            let raw_partition = partition.write();
            
            let i = (i * core::mem::size_of::<GPTPartitionEntry>()) as u64;
            self.inner.write(primary_gpt_header.partition_table_start * Block::LEN_U64 + i, &raw_partition)?;
            partition_table_digest.write(&raw_partition);
        }

        // Setup the CRC of the partition table.
        primary_gpt_header.partition_table_crc32 = partition_table_digest.sum32();

        // Finally update the CRC32
        primary_gpt_header.update_header_crc();

        // Time to write all headers now
        self.inner.write(primary_gpt_header.current_lba * Block::LEN_U64, &primary_gpt_header.write(true))?;

        // AND finally, setup and write the backup GPT
        primary_gpt_header.current_lba = sector_count - 1;
        primary_gpt_header.backup_lba = 1;
        primary_gpt_header.partition_table_start = sector_count - 33;
        primary_gpt_header.update_header_crc();
        self.inner.write(primary_gpt_header.current_lba * Block::LEN_U64, &primary_gpt_header.write(true))?;
        self.inner.write(primary_gpt_header.partition_table_start * Block::LEN_U64, &main_partition_bytes)?;

        self.inner.flush()
    }
}

/// Iterator over GPT partitions
#[derive(Debug)]
struct PartitionIterator<'a> {
    /// The IStorage used.
    inner: &'a mut dyn IStorage,

    /// Partition sector start.
    partition_table_start: u64,

    /// Partition count.
    partition_entry_count: u64,

    /// Partition entry size
    partition_entry_size: u64,

    /// Current position of the iterator.
    position: u64,

    /// Stop the iterator at free entries.
    block_at_free_entry: bool
}

impl<'a> PartitionIterator<'a> {
    /// Create a new partition iterator.
    pub fn new(inner: &'a mut dyn IStorage, block_at_free_entry: bool) -> LibUserResult<Self> {
        let mut res = PartitionIterator {
            inner,
            partition_table_start: 0,
            partition_entry_count: 0,
            partition_entry_size: 0,
            position: 0,
            block_at_free_entry
        };

        let partition_header = GPTHeader::from_storage_device(res.inner, 1)?;

        if !partition_header.is_valid() {
            return Err(FileSystemError::PartitionNotFound.into());
        }

        res.partition_table_start = partition_header.partition_table_start;
        res.partition_entry_count = u64::from(partition_header.partition_entry_count);
        res.partition_entry_size = u64::from(partition_header.partition_entry_size);
        Ok(res)
    }
}

impl<'a> Iterator for PartitionIterator<'a> {
    type Item = LibUserResult<GPTPartitionEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.partition_entry_count {
            let mut partition_data = [0x0; core::mem::size_of::<GPTPartitionEntry>()];
            if let Err(error) = self.inner.read(self.partition_table_start * Block::LEN_U64 + self.position * self.partition_entry_size, &mut partition_data) {
                return Some(Err(error));
            }

            self.position += 1;

            let res = GPTPartitionEntry::from_bytes(partition_data);

            //If the next entry is a free entry, ignore and terminate the iterator.
            if res.partition_type.to_uuid().is_nil() {
                self.position = self.partition_entry_count;
                return None;
            }
            return Some(Ok(res))
        }
        None
    }
}

/// Entry point of the file system interface.
///
/// Allows to interract with various filesytem.
#[derive(Debug, Default)]
pub struct FileSystemProxy {

}

impl FileSystemProxy {
    /// Open a disk partition filesystem.
    /// This may fail if no compatible driver i
    pub fn open_disk_partition(&mut self, disk_id: DiskId, partition_id: PartitionId) -> LibUserResult<Arc<Mutex<Box<dyn FileSystemOperations>>>> {
        let storage = self.open_disk_storage(disk_id)?;
        let partition_option = PartitionIterator::new(storage.lock().as_mut(), true)?.nth(partition_id as usize);

        if let Some(partition) = partition_option {
            let partition = partition?;

            let partition_start = partition.first_lba * Block::LEN_U64;
            let partition_len = (partition.last_lba * Block::LEN_U64) - partition_start;

            let storage = PartitionStorage::new(storage, partition_start, partition_len);
            return DRIVER_MANAGER.lock().construct_filesystem_from_disk_partition(disk_id, partition_id, storage);
        }


        Err(FileSystemError::PartitionNotFound.into())
    }

    /// Open a disk as a block device.
    /// This may fail if no partition table is found.
    pub fn open_disk_storage(&mut self, disk_id: DiskId) -> LibUserResult<Arc<Mutex<Box<dyn IStorage>>>> {
        DRIVER_MANAGER.lock().open_disk_storage(disk_id)
    }

    /// Format a disk partition to the given filesystem type.
    pub fn format_disk_partition(&mut self, disk_id: DiskId, partition_id: PartitionId, filesytem_type: FileSystemType) -> LibUserResult<()> {
        let storage = self.open_disk_storage(disk_id)?;
        let partition_option = PartitionIterator::new(storage.lock().as_mut(), true)?.nth(partition_id as usize);

        if let Some(partition) = partition_option {
            let partition = partition?;

            let partition_start = partition.first_lba * Block::LEN_U64;
            let partition_len = (partition.last_lba * Block::LEN_U64) - partition_start;

            let storage = PartitionStorage::new(storage, partition_start, partition_len);
            return DRIVER_MANAGER.lock().format_disk_partition(storage, filesytem_type);
        }


        Err(FileSystemError::PartitionNotFound.into())
    }

    /// Initialize a disk partition table
    pub fn initialize_disk(&mut self, disk_id: DiskId) -> LibUserResult<()> {
        let storage_arc = self.open_disk_storage(disk_id)?;
        let mut storage = storage_arc.lock();
        let mut partition_manager = PartitionManager::new(storage.as_mut());
        partition_manager.initialize()
    }
}

