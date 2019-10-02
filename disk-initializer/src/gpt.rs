//! GPT definition module.
//!
//! Specs: https://web.archive.org/web/20190822022034/https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf

use uuid::Uuid;

use byteorder::{ByteOrder, LE};
use static_assertions::assert_eq_size;

use storage_device::StorageDevice;

use crc::{crc32, Hasher32};

use core::fmt::{self, Debug};

use super::{BLOCK_SIZE, BLOCK_SIZE_U64};

/// A raw uuid representation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct RawUUID {
    /// Time low part.
    pub d1: u32,
    /// Time mid part.
    pub d2: u16,
    /// Time high part and version.
    pub d3: u16,
    /// Node.
    pub d4: [u8; 0x8],
}

impl Default for RawUUID {
    fn default() -> Self {
        RawUUID {
            d1: 0,
            d2: 0,
            d3: 0,
            d4: [0x0; 0x8],
        }
    }
}

impl RawUUID {
    /// Create a RawUUID from raw parts
    pub fn from_fields(d1: u32, d2: u16, d3: u16, d4: [u8; 0x8]) -> Self {
        RawUUID { d1, d2, d3, d4 }
    }

    /// Convert to a UUID instance.
    pub fn to_uuid(self) -> Uuid {
        Uuid::from_fields(self.d1, self.d2, self.d3, &self.d4).unwrap()
    }

    /// Convert a UUID to a RawUUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        let (d1, d2, d3, d4) = uuid.as_fields();
        Self::from_fields(d1, d2, d3, *d4)
    }

    /// Create a RawUUID from a little endian slice of bytes.
    pub fn from_slice_le(data: &[u8]) -> Self {
        let d1 = LE::read_u32(&data[0..4]);
        let d2 = LE::read_u16(&data[4..6]);
        let d3 = LE::read_u16(&data[6..8]);
        let mut d4 = [0x0; 0x8];

        d4.copy_from_slice(&data[8..16]);

        Self::from_fields(d1, d2, d3, d4)
    }

    /// Convert to a little endian byte array.
    pub fn to_bytes_le(&self) -> [u8; 0x10] {
        let mut data = [0x0; 0x10];

        LE::write_u32(&mut data[0..4], self.d1);
        LE::write_u16(&mut data[4..6], self.d2);
        LE::write_u16(&mut data[6..8], self.d3);
        (&mut data[8..16]).copy_from_slice(&self.d4);

        data
    }
}

/// The header of a GPT table.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(packed)]
pub struct GPTHeader {
    /// Signature of a GPT header.
    pub signature: u64,
    /// GPT revision.
    pub revision: u32,
    /// Header size.
    pub header_size: u32,
    /// CRC over the header.
    pub crc32: u32,
    /// Reserved field.
    reserved: u32,
    /// The LBA of this header.
    pub current_lba: u64,
    /// The LBA of the backup header.
    pub backup_lba: u64,
    /// The first usable LBA. (partition table entries)
    pub first_usable: u64,
    /// The last usable LBA.
    pub last_usable: u64,
    /// The GUID of this disk.
    pub disk_guid: RawUUID,
    /// The LBA of the first partition entry.
    pub partition_table_start: u64,
    /// The count of partition entries.
    pub partition_entry_count: u32,
    /// The size of a partition entry.
    pub partition_entry_size: u32,
    /// The CRC over all partition entries.
    pub partition_table_crc32: u32,
}

assert_eq_size!(GPTHeader, [u8; 0x5C]);

/// A GPT partition entry.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct GPTPartitionEntry {
    /// Partition type GUID.
    pub partition_type: RawUUID,
    /// Partition GUID.
    pub unique_id: RawUUID,
    /// First LBA of the partition.
    pub first_lba: u64,
    /// Last LBA of the partition (inclusive).
    pub last_lba: u64,
    /// Attribute flags.
    pub attribute: u64,
    /// Partition name in UTF16LE.
    pub partition_name: [u16; 0x24],
}

impl Default for GPTPartitionEntry {
    fn default() -> Self {
        GPTPartitionEntry {
            partition_type: RawUUID::default(),
            unique_id: RawUUID::default(),
            first_lba: 0,
            last_lba: 0,
            attribute: 0,
            partition_name: [0x0; 0x24],
        }
    }
}

impl fmt::Debug for GPTPartitionEntry {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.debug_struct("GPTPartitionEntry")
                .field("partition_type", &self.partition_type)
                .field("unique_id", &self.unique_id)
                .field("first_lba", &self.first_lba)
                .field("last_lba", &self.last_lba)
                .field("attribute", &self.attribute)
                .field("partition_name", &&self.partition_name[..])
                .finish()
    }
}

impl GPTPartitionEntry {
    /// Set the partition type GUID.
    pub fn set_partition_type(&mut self, uuid: Uuid) {
        self.partition_type = RawUUID::from_uuid(uuid);
    }

    /// Set the unique partition GUID.
    pub fn set_unique_id(&mut self, uuid: Uuid) {
        self.unique_id = RawUUID::from_uuid(uuid);
    }

    /// Set the name of the partition.
    pub fn set_name(&mut self, name: &str) {
        let name_size_utf16 = name.chars().fold(0, |acc, c| acc + c.len_utf16());
        assert!(
            name_size_utf16 <= self.partition_name.len() * core::mem::size_of::<u16>(),
            "Partition name is too long"
        );

        let mut i = 0;
        for c in name.chars() {
            c.encode_utf16(&mut self.partition_name[i..i + c.len_utf16()]);
            i += c.len_utf16();
        }
    }

    /// Create a GPTPartitionEntry from bytes.
    pub fn from_bytes(bytes: [u8; 0x80]) -> Self {
        let mut res = GPTPartitionEntry::default();
        res.read(bytes);
        res
    }

    /// Read the content of a raw array into a GPTPartitionEntry.
    pub fn read(&mut self, bytes: [u8; 0x80]) {
        self.partition_type = RawUUID::from_slice_le(&bytes[0x0..0x10]);
        self.unique_id = RawUUID::from_slice_le(&bytes[0x10..0x20]);
        self.first_lba = LE::read_u64(&bytes[0x20..0x28]);
        self.last_lba = LE::read_u64(&bytes[0x28..0x30]);
        self.attribute = LE::read_u64(&bytes[0x30..0x38]);

        let partition_name_u8 = unsafe {
            // Safety: array of u16 can be represented as array of u8 so this is safe.
            plain::as_mut_bytes(&mut self.partition_name[..])
        };

        partition_name_u8.copy_from_slice(&bytes[0x38..0x80]);
    }

    /// Conver the structure data to a raw array.
    pub fn write(&self) -> [u8; 0x80] {
        let mut bytes = [0x0; 0x80];

        (&mut bytes[0x0..0x10]).copy_from_slice(&self.partition_type.to_bytes_le());
        (&mut bytes[0x10..0x20]).copy_from_slice(&self.unique_id.to_bytes_le());
        LE::write_u64(&mut bytes[0x20..0x28], self.first_lba);
        LE::write_u64(&mut bytes[0x28..0x30], self.last_lba);
        LE::write_u64(&mut bytes[0x30..0x38], self.attribute);

        let partition_name_u8 = unsafe {
            // Safety: array of u16 can be represented as array of u8 so this is safe.
            plain::as_bytes(&self.partition_name[..])
        };

        (&mut bytes[0x38..0x80]).copy_from_slice(&partition_name_u8);

        bytes
    }
}

assert_eq_size!(GPTPartitionEntry, [u8; 0x80]);

impl Default for GPTHeader {
    fn default() -> Self {
        GPTHeader {
            signature: GPTHeader::MAGIC,
            revision: 0x10000,
            header_size: core::mem::size_of::<GPTHeader>() as u32,
            crc32: 0,
            reserved: 0,
            current_lba: 0,
            backup_lba: 0,
            first_usable: 0,
            last_usable: 0,
            disk_guid: RawUUID::default(),
            partition_table_start: 0,
            partition_entry_count: 0,
            partition_entry_size: 0x80,
            partition_table_crc32: 0,
        }
    }
}

impl GPTHeader {
    /// The magic of a GPT header ("EFI PART")
    pub const MAGIC: u64 = 0x5452415020494645;

    /// Read the GPT header from the disk
    pub fn from_storage_device<E: Debug>(storage_device: &mut dyn StorageDevice<Error = E>, lba_index: u64) -> Result<Self, E> {
        let mut data = [0x0; 0x5C];

        storage_device.read(lba_index * BLOCK_SIZE_U64, &mut data)?;

        Ok(Self::from_bytes(data))
    }

    /// Create a GPTHeader from a raw array.
    pub fn from_bytes(bytes: [u8; 0x5C]) -> Self {
        let mut res = GPTHeader::default();
        res.read(bytes);
        res
    }

    /// Read the content of a raw array into a GPTHeader.
    pub fn read(&mut self, bytes: [u8; 0x5C]) {
        self.signature = LE::read_u64(&bytes[0x0..0x8]);
        self.revision = LE::read_u32(&bytes[0x8..0xC]);
        self.header_size = LE::read_u32(&bytes[0xC..0x10]);
        self.crc32 = LE::read_u32(&bytes[0x10..0x14]);
        self.reserved = LE::read_u32(&bytes[0x14..0x18]);
        self.current_lba = LE::read_u64(&bytes[0x18..0x20]);
        self.backup_lba = LE::read_u64(&bytes[0x20..0x28]);
        self.first_usable = LE::read_u64(&bytes[0x28..0x30]);
        self.last_usable = LE::read_u64(&bytes[0x30..0x38]);
        self.disk_guid = RawUUID::from_slice_le(&bytes[0x38..0x48]);
        self.partition_table_start = LE::read_u64(&bytes[0x48..0x50]);
        self.partition_entry_count = LE::read_u32(&bytes[0x50..0x54]);
        self.partition_entry_size = LE::read_u32(&bytes[0x54..0x58]);
        self.partition_table_crc32 = LE::read_u32(&bytes[0x58..0x5C]);
    }

    /// Conver the structure data to a raw array.
    pub fn write(&self, include_crc: bool) -> [u8; 0x5C] {
        let mut bytes = [0x0; 0x5C];

        LE::write_u64(&mut bytes[0x0..0x8], self.signature);
        LE::write_u32(&mut bytes[0x8..0xC], self.revision);
        LE::write_u32(&mut bytes[0xC..0x10], self.header_size);
        if include_crc {
            LE::write_u32(&mut bytes[0x10..0x14], self.crc32);
        }
        LE::write_u32(&mut bytes[0x14..0x18], self.reserved);
        LE::write_u64(&mut bytes[0x18..0x20], self.current_lba);
        LE::write_u64(&mut bytes[0x20..0x28], self.backup_lba);
        LE::write_u64(&mut bytes[0x28..0x30], self.first_usable);
        LE::write_u64(&mut bytes[0x30..0x38], self.last_usable);
        let disk_guid = self.disk_guid;
        (&mut bytes[0x38..0x48]).copy_from_slice(&disk_guid.to_bytes_le());
        LE::write_u64(&mut bytes[0x48..0x50], self.partition_table_start);
        LE::write_u32(&mut bytes[0x50..0x54], self.partition_entry_count);
        LE::write_u32(&mut bytes[0x54..0x58], self.partition_entry_size);
        LE::write_u32(&mut bytes[0x58..0x5C], self.partition_table_crc32);

        bytes
    }

    /// Update the CRC32 of the header.
    ///
    /// Note:
    ///
    /// This should be called after having manually update the CRC32 of the partition table.
    pub fn update_header_crc(&mut self) {
        self.crc32 = calculate_crc32(&self.write(false));
    }

    /// Set the disk GUID.
    pub fn set_disk_guid(&mut self, uuid: Uuid) {
        self.disk_guid = RawUUID::from_uuid(uuid);
    }
}

/// Manage partition of a IStorage.
pub struct PartitionManager<'a, E> {
    /// The IStorage used.
    inner: &'a mut dyn StorageDevice<Error = E>,
}

/// Compute the CRC32 of a given slice.
pub fn calculate_crc32(b: &[u8]) -> u32 {
    let mut digest = crc32::Digest::new(crc32::IEEE);
    digest.write(b);

    digest.sum32()
}

/// Convert a LBA to a CLS address.
pub fn lba_to_cls(disk_lba: u64, head_count: u64, sector_count: u64) -> (u8, u8, u8) {
    let mut sector_number = (disk_lba % sector_count) + 1;;
    let tmp = disk_lba / sector_count;
    let mut head_number = tmp % head_count;
    let mut cylinder_number = tmp / head_count;

    if cylinder_number > 0x400 {
        cylinder_number = 0x3FF;
        head_number = head_count;
        sector_number = sector_count;
    }

    sector_number |= (cylinder_number & 0x300) >> 2;
    cylinder_number &= 0xFF;

    (
        head_number as u8,
        sector_number as u8,
        cylinder_number as u8,
    )
}

impl<'a, E: Debug> PartitionManager<'a, E> {
    /// Create a new partition manager.
    pub fn new(inner: &'a mut dyn StorageDevice<Error = E>) -> Self {
        PartitionManager { inner }
    }

    /// Create a protective MBR
    pub fn create_protective_mbr(&mut self) -> Result<(), E> {
        let mut mbr = [0x0; BLOCK_SIZE];

        let partition_offset = 1;
        let partition_number = 1;
        let head_count = 64;
        let mut sector_count = self.inner.len()? / BLOCK_SIZE_U64;
        if sector_count > u64::from(u32::max_value()) {
            sector_count = u64::from(u32::max_value());
        }

        let (head_number, sector_number, cylinder_number) =
            lba_to_cls(partition_number, head_count, sector_count);

        // Setup first fake partition.
        mbr[0x1BE] = 0x0; // not bootable

        // start CHS
        mbr[0x1BF] = head_number;
        mbr[0x1C0] = sector_number;
        mbr[0x1C1] = cylinder_number;

        // GPT protective
        mbr[0x1C2] = 0xEE;

        let (head_number, sector_number, cylinder_number) =
            lba_to_cls(sector_count - 1, head_count, sector_count);

        // end CHS
        mbr[0x1C3] = head_number;
        mbr[0x1C4] = sector_number;
        mbr[0x1C5] = cylinder_number;

        // finally start/end LBA.
        LE::write_u32(&mut mbr[0x1C6..0x1CA], partition_offset as u32);
        LE::write_u32(
            &mut mbr[0x1CA..0x1CE],
            sector_count as u32 - partition_offset,
        );

        // And finally the "valid signature"
        mbr[0x1FE] = 0x55;
        mbr[0x1FF] = 0xAA;

        self.inner.write(0, &mbr)
    }

    /// Initialize a IStorage partition table.
    pub fn initialize(&mut self) -> Result<(), E> {
        self.create_protective_mbr()?;
        let sector_count = self.inner.len()? / BLOCK_SIZE_U64;

        assert!(
            sector_count > 34,
            "The storage is too small to hold a GPT partition schema"
        );

        // first setup the GPT header
        let mut primary_gpt_header = GPTHeader::default();

        // one disk id for the sake of completness
        primary_gpt_header
            .set_disk_guid(Uuid::parse_str("CAFECAFE-CAFE-CAFE-CAFE-CAFECAFECAFE").unwrap());
        primary_gpt_header.current_lba = 1;
        primary_gpt_header.backup_lba = sector_count - 1;
        primary_gpt_header.first_usable = 34;
        primary_gpt_header.last_usable = sector_count - 34;
        primary_gpt_header.partition_table_start = 2;

        let mut partition_table = Vec::new();

        let mut main_partition = GPTPartitionEntry::default();
        // Microsoft basic data GUID
        main_partition
            .set_partition_type(Uuid::parse_str("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").unwrap());

        // Some GUID selected for the sake of randomness
        main_partition
            .set_unique_id(Uuid::parse_str("BA3E4ADC-EB06-11E7-8AD3-9570BEC474F8").unwrap());

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
            self.inner.write(
                primary_gpt_header.partition_table_start * BLOCK_SIZE_U64 + i,
                &raw_partition,
            )?;
            partition_table_digest.write(&raw_partition);
        }

        // Setup the CRC of the partition table.
        primary_gpt_header.partition_table_crc32 = partition_table_digest.sum32();

        // Finally update the CRC32
        primary_gpt_header.update_header_crc();

        // Time to write all headers now
        self.inner.write(
            primary_gpt_header.current_lba * BLOCK_SIZE_U64,
            &primary_gpt_header.write(true),
        )?;

        // AND finally, setup and write the backup GPT
        primary_gpt_header.current_lba = sector_count - 1;
        primary_gpt_header.backup_lba = 1;
        primary_gpt_header.partition_table_start = sector_count - 33;
        primary_gpt_header.update_header_crc();
        self.inner.write(
            primary_gpt_header.current_lba * BLOCK_SIZE_U64,
            &primary_gpt_header.write(true),
        )?;
        self.inner.write(
            primary_gpt_header.partition_table_start * BLOCK_SIZE_U64,
            &main_partition_bytes,
        )
    }
}

/// Iterator over GPT partitions
pub struct PartitionIterator<'a, E> {
    /// The IStorage used.
    inner: &'a mut dyn StorageDevice<Error = E>,

    /// Partition sector start.
    partition_table_start: u64,

    /// Partition count.
    partition_entry_count: u64,

    /// Partition entry size
    partition_entry_size: u64,

    /// Current position of the iterator.
    position: u64,
}

impl<'a, E: Debug> PartitionIterator<'a, E> {
    /// Create a new partition iterator.
    pub fn new(inner: &'a mut dyn StorageDevice<Error = E>) -> Result<Self, E> {
        let mut res = PartitionIterator {
            inner,
            partition_table_start: 0,
            partition_entry_count: 0,
            partition_entry_size: 0,
            position: 0,
        };

        let partition_header = GPTHeader::from_storage_device(res.inner, 1)?;

        res.partition_table_start = partition_header.partition_table_start;
        res.partition_entry_count = u64::from(partition_header.partition_entry_count);
        res.partition_entry_size = u64::from(partition_header.partition_entry_size);
        Ok(res)
    }
}

impl<'a, E: Debug> Iterator for PartitionIterator<'a, E> {
    type Item = Result<GPTPartitionEntry, E>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position < self.partition_entry_count {
            let mut partition_data = [0x0; core::mem::size_of::<GPTPartitionEntry>()];
            if let Err(error) = self.inner.read(
                self.partition_table_start * BLOCK_SIZE_U64
                    + self.position * self.partition_entry_size,
                &mut partition_data,
            ) {
                return Some(Err(error));
            }

            self.position += 1;

            let res = GPTPartitionEntry::from_bytes(partition_data);

            //If the next entry is a free entry, ignore and terminate the iterator.
            if res.partition_type.to_uuid().is_nil() {
                self.position = self.partition_entry_count;
                return None;
            }
            return Some(Ok(res));
        }
        None
    }
}
