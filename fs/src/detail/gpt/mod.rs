//! GPT definition module.
//! 
//! Specs: https://web.archive.org/web/20190822022034/https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf

use uuid::Uuid;

use byteorder::{LE, ByteOrder};
use super::utils::calculate_crc32;

use core::fmt;

/// A raw uuid representation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct RawUUID {
    /// Low part.
    pub d1: u32,
    /// Mid part.
    pub d2: u16,
    /// High part and version.
    pub d3: u16,
    /// Node.
    pub d4: [u8; 0x8]
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
        RawUUID {
            d1,
            d2,
            d3,
            d4
        }
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
    pub partition_name: [u16; 0x24]
}

impl Default for GPTPartitionEntry {
    fn default() -> Self {
        GPTPartitionEntry {
            partition_type: RawUUID::default(),
            unique_id: RawUUID::default(),
            first_lba: 0,
            last_lba: 0,
            attribute: 0,
            partition_name: [0x0; 0x24]
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

    /// Get the partition type GUID.
    pub fn get_partition_type(&self) -> uuid::Uuid {
        self.partition_type.to_uuid()
    }

    /// Set the unique partition GUID.
    pub fn set_unique_id(&mut self, uuid: Uuid) {
        self.unique_id = RawUUID::from_uuid(uuid);
    }

    /// Get the unique partition GUID.
    pub fn get_unique_id(&self) -> uuid::Uuid {
        self.unique_id.to_uuid()
    }

    /// Set the name of the partition.
    pub fn set_name(&mut self, name: &str) {
        let name_size_utf16 = name.chars().fold(0, |acc, c| acc + c.len_utf16());
        assert!(name_size_utf16 <= self.partition_name.len() * core::mem::size_of::<u16>(), "Partition name is too long");

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

    /// Check if the GPT Header looks valid.
    pub fn is_valid(&self) -> bool {
        if self.signature == GPTHeader::MAGIC {
            return self.crc32 == calculate_crc32(&self.write(false));
        }

        false
    }

    /// Set the disk GUID.
    pub fn set_disk_guid(&mut self, uuid: Uuid) {
        self.disk_guid = RawUUID::from_uuid(uuid);
    }

    /// Get the disk GUID.
    pub fn get_disk_guid(&self) -> uuid::Uuid {
        self.disk_guid.to_uuid()
    }
}