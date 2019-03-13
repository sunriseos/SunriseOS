//! Frame Information Structures
//!
//! A FIS is a packet or frame of information that is transferred between the host and device.
//! Refer to the Serial ATA specification for more information.

#![allow(clippy::missing_docs_in_private_items)] // just read the spec, ok !?

use kfs_libuser::io::Mmio;

/// The types of a FIS.
///
/// Stored on byte 0 of every FIS, determines the length of the structure to be read.
#[repr(u8)]
pub enum FisType {
    /// Register FIS - host to device
    RegH2D = 0x27,
    /// Register FIS - device to host
    RegD2H = 0x34,
    /// DMA activate FIS - device to host
    DmaAct = 0x39,
    /// DMA setup FIS - bidirectional
    DmaSetup = 0x41,
    /// Data FIS - bidirectional
    Data = 0x46,
    /// BIST activate FIS - bidirectional
    Bist = 0x58,
    /// PIO setup FIS - device to host
    PioSetup = 0x5F,
    /// Set device bits FIS - device to host
    DevBits = 0xA1
}

/// Register FIS - host to device
///
/// `fis_type` must be set to 0x27.
#[repr(packed)]
pub struct FisRegH2D {
    // DWORD 0
    pub fis_type: Mmio<u8>, // FIS_TYPE_REG_H2D

    pub pm: Mmio<u8>, // Port multiplier, 1: Command, 0: Control

    pub command: Mmio<u8>, // Command register
    pub featurel: Mmio<u8>, // Feature register, 7:0

    // DWORD 1
    pub lba0: Mmio<u8>, // LBA low register, 7:0
    pub lba1: Mmio<u8>, // LBA mid register, 15:8
    pub lba2: Mmio<u8>, // LBA high register, 23:16
    pub device: Mmio<u8>, // Device register

    // DWORD 2
    pub lba3: Mmio<u8>, // LBA register, 31:24
    pub lba4: Mmio<u8>, // LBA register, 39:32
    pub lba5: Mmio<u8>, // LBA register, 47:40
    pub featureh: Mmio<u8>, // Feature register, 15:8

    // DWORD 3
    pub countl: Mmio<u8>, // Count register, 7:0
    pub counth: Mmio<u8>, // Count register, 15:8
    pub icc: Mmio<u8>, // Isochronous command completion
    pub control: Mmio<u8>, // Control register

    // DWORD 4
    pub rsv1: [Mmio<u8>; 4], // Reserved
}

/// Register FIS - device to host
#[repr(packed)]
pub struct FisRegD2H {
    // DWORD 0
    pub fis_type: Mmio<u8>, // FIS_TYPE_REG_D2H

    pub pm: Mmio<u8>, // Port multiplier, Interrupt bit: 2

    pub status: Mmio<u8>, // Status register
    pub error: Mmio<u8>, // Error register

    // DWORD 1
    pub lba0: Mmio<u8>, // LBA low register, 7:0
    pub lba1: Mmio<u8>, // LBA mid register, 15:8
    pub lba2: Mmio<u8>, // LBA high register, 23:16
    pub device: Mmio<u8>, // Device register

    // DWORD 2
    pub lba3: Mmio<u8>, // LBA register, 31:24
    pub lba4: Mmio<u8>, // LBA register, 39:32
    pub lba5: Mmio<u8>, // LBA register, 47:40
    pub rsv2: Mmio<u8>, // Reserved

    // DWORD 3
    pub countl: Mmio<u8>, // Count register, 7:0
    pub counth: Mmio<u8>, // Count register, 15:8
    pub rsv3: [Mmio<u8>; 2], // Reserved

    // DWORD 4
    pub rsv4: [Mmio<u8>; 4], // Reserved
}

/// Data FIS - bidirectional
#[repr(packed)]
pub struct FisData {
    // DWORD 0
    pub fis_type: Mmio<u8>, // FIS_TYPE_DATA

    pub pm: Mmio<u8>, // Port multiplier

    pub rsv1: [Mmio<u8>; 2], // Reserved

    // DWORD 1 ~ N
    pub data: [Mmio<u8>; 252], // Payload
}

/// PIO setup FIS - device to host
#[repr(packed)]
pub struct FisPioSetup {
    // DWORD 0
    pub fis_type: Mmio<u8>, // FIS_TYPE_PIO_SETUP

    pub pm: Mmio<u8>, // Port multiplier, direction: 4 - device to host, interrupt: 2

    pub status: Mmio<u8>, // Status register
    pub error: Mmio<u8>, // Error register

    // DWORD 1
    pub lba0: Mmio<u8>, // LBA low register, 7:0
    pub lba1: Mmio<u8>, // LBA mid register, 15:8
    pub lba2: Mmio<u8>, // LBA high register, 23:16
    pub device: Mmio<u8>, // Device register

    // DWORD 2
    pub lba3: Mmio<u8>, // LBA register, 31:24
    pub lba4: Mmio<u8>, // LBA register, 39:32
    pub lba5: Mmio<u8>, // LBA register, 47:40
    pub rsv2: Mmio<u8>, // Reserved

    // DWORD 3
    pub countl: Mmio<u8>, // Count register, 7:0
    pub counth: Mmio<u8>, // Count register, 15:8
    pub rsv3: Mmio<u8>, // Reserved
    pub e_status: Mmio<u8>, // New value of status register

    // DWORD 4
    pub tc: Mmio<u16>, // Transfer count
    pub rsv4: [Mmio<u8>; 2], // Reserved
}

/// DMA setup FIS - bidirectional
#[repr(packed)]
pub struct FisDmaSetup {
    // DWORD 0
    pub fis_type: Mmio<u8>, // FIS_TYPE_DMA_SETUP

    pub pm: Mmio<u8>, // Port multiplier, direction: 4 - device to host, interrupt: 2, auto-activate: 1

    pub rsv1: [Mmio<u8>; 2], // Reserved

    // DWORD 1&2
    pub dma_buffer_id: Mmio<u64>, /* DMA Buffer Identifier. Used to Identify DMA buffer in host memory. SATA Spec says host specific and not in Spec. Trying AHCI spec might work. */

    // DWORD 3
    pub rsv3: Mmio<u32>, // More reserved

    // DWORD 4
    pub dma_buffer_offset: Mmio<u32>, // Byte offset into buffer. First 2 bits must be 0

    // DWORD 5
    pub transfer_count: Mmio<u32>, // Number of bytes to transfer. Bit 0 must be 0

    // DWORD 6
    pub rsv6: Mmio<u32>, // Reserved
}

/// Set device bits FIS - device to host
#[repr(packed)]
pub struct FisSetDeviceBits {
    // DWORD 0
    pub fis_type: Mmio<u8>, // FIS_TYPE_DMA_SETUP
    pub i:        Mmio<u8>, // interrupt bit, 6
    pub status:   Mmio<u8>, // status hi 6:4, status lo 2:0
    pub error:    Mmio<u8>, // error 7:0

    // DWORD 1
    pub _rsv: Mmio<u32>, // Reserved
}
