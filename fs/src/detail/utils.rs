//! Utils of the detail module.

use crc::{crc32, Hasher32};

/// Compute the CRC32 of a given slice.
pub fn calculate_crc32(b: &[u8]) -> u32 {
    let mut digest = crc32::Digest::new(crc32::IEEE);
    digest.write(b);

    digest.sum32()
}

/// Convert a LBA to a CLS address.
pub fn lba_to_cls(
    disk_lba: u64,
    head_count: u64,
    sector_count: u64,
) -> (u8, u8, u8)
{
    let mut sector_number = (disk_lba % sector_count) + 1;
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

    (head_number as u8, sector_number as u8, cylinder_number as u8)
}