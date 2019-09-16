//! SecureBoot Key Generator
//!
//! Generates an NVRAM for the UEFI configured for the given PK/KEK/DB key. To
//! keep key management simple, the same key is used for all three purposes.
//!
//! This is meant to be used with the OVMF Firmware UEFI firmware.
//!
//! UEFI Specification: https://web.archive.org/web/20190822022034/https://uefi.org/sites/default/files/resources/UEFI_Spec_2_8_final.pdf
//!
//! TianoCore commit: https://github.com/tianocore/edk2/tree/e18d1c37e812284c5db1f2775db15ca349730138
#![feature(const_int_conversion)]

use std::io::{Seek, SeekFrom, Write};
use std::fs::File;
use std::convert::TryFrom;
use std::mem::size_of;

use serde_derive::Serialize;
use chrono::prelude::*;
use bitflags::bitflags;

/// A Globally Unique Identifier. Everything that requires an ID in the EFI spec
/// uses a GUID to avoid collisions and whatnot.
#[derive(Clone, Copy, Serialize)]
struct EfiGuid {
    /// The data of the GUID, as a byte array.
    data: [u8; 16]
}

impl EfiGuid {
    /// Creates a new GUID from the subcomponent.
    const fn new(first: u32, second: u16, third: u16, rest: [u8; 8]) -> EfiGuid {
        let f = first.to_le_bytes();
        let s = second.to_le_bytes();
        let t = third.to_le_bytes();
        let r = rest;
        EfiGuid {
            data: [f[0], f[1], f[2], f[3], s[0], s[1], t[0], t[1],
                   r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]]
        }
    }

    /// GUID for the VendorKeysNv variable.
    ///
    /// [Taken from TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/SecurityPkg/SecurityPkg.dec#L102)
    const EFI_VENDOR_KEYS_NV: EfiGuid =
        EfiGuid::new(0x9073e4e0, 0x60ec, 0x4b6e, [0x99, 0x03, 0x4c, 0x22, 0x3c, 0x26, 0x0f, 0x3c]);
    /// GUID for the SecureBootEnable variable.
    ///
    /// [Taken from TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/SecurityPkg/SecurityPkg.dec#L87)
    const EFI_SECURE_BOOT_ENABLE: EfiGuid =
        EfiGuid::new(0xf0a30bc7, 0xaf08, 0x4556, [0x99, 0xc4, 0x00, 0x10, 0x09, 0xc9, 0x3a, 0x44]);
    /// GUID for the CustomMode variable.
    ///
    /// [Taken from TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/SecurityPkg/SecurityPkg.dec#L96)
    const EFI_CUSTOM_MODE_ENABLE: EfiGuid =
        EfiGuid::new(0xc076ec0c, 0x7028, 0x4399, [0xa0, 0x72, 0x71, 0xee, 0x5c, 0x44, 0x8b, 0x9f]);

    /// GUID for the db variable.
    ///
    /// See UEFI Specification 32.6.1 UEFI Image Variable GUID & Variable Name.
    const EFI_IMAGE_SECURITY_DATABASE: EfiGuid =
        EfiGuid::new(0xd719b2cb, 0x3d3a, 0x4596, [0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f]);
    /// GUID for the standard UEFI variable.
    ///
    /// See UEFI Specification 3.3 Globally Defined Variables.
    const EFI_GLOBAL_VARIABLE: EfiGuid =
        EfiGuid::new(0x8be4df61, 0x93ca, 0x11d2, [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c]);
    /// ID of an NVDATA FV filesystem.
    ///
    /// [Taken from TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/OvmfPkg/VarStore.fdf.inc#L23)
    const EFI_SYSTEM_NV_DATA_FV: EfiGuid =
        EfiGuid::new(0xfff12b8d, 0x7696, 0x4c8b, [0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50]);
    /// ID of an authenticated variable.
    ///
    /// [Taken from TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/OvmfPkg/EmuVariableFvbRuntimeDxe/Fvb.c#L31)
    const EFI_AUTHENTICATED_VARIABLE: EfiGuid =
        EfiGuid::new(0xaaf32c78, 0x947b, 0x439a, [0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92]);
    /// ID of an EFI Encryption Key in x509 certificate mode.
    ///
    /// See UEFI Specification 32.4.1 Signature Database.
    const EFI_CERT_X509: EfiGuid =
        EfiGuid::new(0xa5c059a1, 0x94e4, 0x4aa7, [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72]);
}

/// Timestamps as encoded in UEFI.
///
/// See UEFI SPecification 8.3 Time Services.
#[derive(Serialize)]
struct EfiTime {
    /// The current local year. Valid range is 1900-9999.
    year: u16,
    /// The current local month. Valid range is 1-12.
    month: u8,
    /// The current local day. Valid range is 1-31.
    day: u8,
    /// The current local hour. Valid range is 0-23.
    hour: u8,
    /// The current local minute. Valid range is 0-59.
    minute: u8,
    /// The current local second. Valid range is 0-59.
    second: u8,
    #[doc(hidden)]
    pad1: u8,
    /// The current local nanosecond, as a fraction of the current second. Valid
    /// range is 0-999,999,999.
    nanosecond: u32,
    /// The time's offset in minutes from UTC. If the value is 0x7FF, then the
    /// time is interpreted as a local time.
    timezone: i16,
    /// A bitmask containing the daylight savings time information for the time.
    daylight: u8,
    #[doc(hidden)]
    pad2: u8
}

impl EfiTime {
    /// Get the current time.
    fn current() -> EfiTime {
        let curtime = Utc::now();
        EfiTime {
            year: curtime.year() as u16,
            month: curtime.month() as u8,
            day: curtime.day() as u8,
            hour: curtime.hour() as u8,
            minute: curtime.minute() as u8,
            second: curtime.second() as u8,
            pad1: 0,
            nanosecond: curtime.nanosecond() as u32,
            timezone: 0,
            daylight: 0,
            pad2: 0
        }
    }
}

/// Header of the NVRAM used by OVMF.
///
/// [Taken from TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/MdePkg/Include/Pi/PiFirmwareVolume.h#L99)
#[derive(Serialize)]
struct EfiFirmwareVolume {
    /// A vector of zero bytes.
    zero_vector: [u8; 16],
    /// The GUID of the current FirmwareVolume. OVMF will likely change this ID
    /// if they ever make breaking changes to the format to keep compatibility
    /// with the old format.
    ///
    /// The current GUID used is EFI_SYSTEM_NV_DATA_FV.
    filesystem_guid: EfiGuid,
    /// Length in bytes of the complete firmware volume, including the header.
    fv_length: u64,
    /// Should be b"_FVH".
    signature: u32,
    /// Declares capabilities and power-on defaults for the firmware volume.
    attributes: u32,
    /// Length in bytes of the complete firmware volume header. Contains the
    /// block map list.
    header_length: u16,
    /// A 16-bit checksum of the firmware volume header (from the zero_vector
    /// and using the size stored in header_length). A valid header sums to
    /// zero.
    ///
    /// [Checksum algorithm in TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/MdePkg/Library/BaseLib/CheckSum.c#L130).
    checksum: u16,
    /// Offset, relative to the start of the header, of the extended header
    /// (EFI_FIRMWARE_VOLUME_EXT_HEADER) or zero if there is no extended header.
    ext_header_offset: u16,
    /// This field must always be set to 0.
    reserved: u8,
    /// Set to 2. Future versions of this specification may define new header fields and will
    /// increment the Revision field accordingly.
    revision: u8,
    // block_map goes until it finds a {0, 0}
}

/// Taken from [TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/MdePkg/Include/Pi/PiFirmwareVolume.h#L85).
#[derive(Serialize)]
struct EfiFvBlockMapEntry {
    /// The number of sequential blocks which are of the same size.
    num_blocks: u32,
    /// The size of the blocks.
    length: u32
}

/// Variable store region header.
///
/// Taken from [TianoCore](https://github.com/tianocore/edk2/blob/e18d1c37e812284c5db1f2775db15ca349730138/MdeModulePkg/Include/Guid/VariableFormat.h#L67).
#[derive(Serialize)]
struct VariableStoreHeader {
    /// Variable store region signature. Should be EFI_AUTHENTICATED_VARIABLE.
    signature: EfiGuid,
    /// Size of entire variable store, including size of variable store header
    /// but not including the size of FvHeader.
    size: u32,
    /// Variable region format state.
    format: u8,
    /// Variable region healthy state.
    state: u8,
    #[doc(hidden)]
    reserved: u16,
    #[doc(hidden)]
    reserved1: u32
}

bitflags! {
    #[derive(Serialize)]
    struct VariableAttributes: u32 {
        /// Variable is stored in non-volatile storage and will persist across
        /// power cycles.
        const NON_VOLATILE                          = 0x00000001;
        /// Behavior is not documented in UEFI spec...
        const BOOTSERVICE_ACCESS                    = 0x00000002;
        /// If EFI_BOOT_SERVICES.ExitBootServices() has already been executed,
        /// data variables without the RUNTIME_ACCESS attribute set will not be
        /// visible to GetVariable() and will return an EFI_NOT_FOUND error.
        const RUNTIME_ACCESS                        = 0x00000004;
        /// If HARDWARE_ERROR_RECORD attribute is set, VariableName and
        /// VendorGuid must comply with the rules stated in Section 8.2.4.2 and
        /// Appendix P of the UEFI Spec. Otherwise, the SetVariable() call shall
        /// return EFI_INVALID_PARAMETER.
        const HARDWARE_ERROR_RECORD                 = 0x00000008;
        /// AUTHENTICATED_WRITE_ACCESS is deprecated and should be considered
        /// reserved.
        const AUTHENTICATED_WRITE_ACCESS            = 0x00000010;
        /// Secure Boot Policy Variable must be created with the
        /// TIME_BASED_AUTHENTICATED_WRITE_ACCESS attribute set, and the
        /// authentication shall use the EFI_VARIABLE_AUTHENTICATION_2 descriptor.
        /// If the appropriate attribute bit is not set, then the firmware shall
        /// return EFI_INVALID_PARAMETER.
        const TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x00000020;
        /// Never returned in GetVariable. Used to signal that we want to append
        /// instead of overwrite when writing a variable with SetVariable.
        const APPEND_WRITE                          = 0x00000040;
        /// This attribute indicates that the variable payload begins with an
        /// AUTHENTICATION_3 structure, and potentially more structures as
        /// indicated by fields of this structure.
        const ENHANCED_AUTHENTICATED_ACCESS         = 0x00000080;
    }
}

/// Single authenticated variable data header structure.
#[derive(Serialize)]
struct AuthenticatedVariableHeader {
    /// Variable data start flag. Should be set to 0x55AA.
    startid: u16,
    /// Variable state. 0x3F means VAR_ADDED.
    state: u8,
    #[doc(hidden)]
    reserved: u8,
    /// Attributes of variable defined in UEFI specification. See
    /// [VariableAttributes].
    attributes: VariableAttributes,
    /// Associated monotonic count value against replay attack.
    monotonic_count: u64,
    /// Associated TimeStamp value against replay attack.
    timestamp: EfiTime,
    /// Index of associated public key in database.
    pub_key_index: u32,
    /// Size of variable null-terminated Unicode string name.
    name_size: u32,
    /// Size of the variable data without this header.
    data_size: u32,
    /// A unique identifier for the vendor that produces and consumes this
    /// variable.
    vendor_guid: EfiGuid
}

/// Serialize a secure variable.
fn serialize_var(mut file: &mut File, name: &str, guid: EfiGuid, attributes: VariableAttributes, data: &[u8]) {
    let curpos = file.seek(SeekFrom::Current(0)).unwrap();
    let aligned_pos = (curpos + 4 - 1) & !(4 - 1);
    file.seek(SeekFrom::Start(aligned_pos)).unwrap();

    // The OVMF code realigns if necessary here, but it does so with an
    // alignment requirement of 1... ಠ_ಠ
    bincode::serialize_into(&mut file, &AuthenticatedVariableHeader {
        startid: 0x55AA,
        state: 0x3F,
        reserved: 0,
        attributes: attributes,
        monotonic_count: 0,
        timestamp: EfiTime::current(),
        pub_key_index: 0,
        name_size: (name.len() as u32 + 1) * 2,
        data_size: data.len() as u32,
        vendor_guid: guid,
    }).unwrap();
    let name = &name.encode_utf16().chain(std::iter::once(0)).map(|v| v.to_le_bytes()).collect::<Vec<[u8; 2]>>();
    let name = name.iter().flatten().cloned().collect::<Vec<u8>>();
    file.write_all(&name).unwrap();
    file.write_all(data).unwrap();
}

fn main() {
    const FV_LENGTH: u64 = 0x20000;
    const FV_BLOCKSIZE: u32 = 0x1000;
    let mut file = File::create("target/OVMF_VARS.fd").unwrap();
    bincode::serialize_into(&mut file, &EfiFirmwareVolume {
        zero_vector: [0; 16],
        filesystem_guid: EfiGuid::EFI_SYSTEM_NV_DATA_FV,
        fv_length: FV_LENGTH,
        signature: u32::from_le_bytes(*b"_FVH"),
        attributes: 0x4FEFF,
        header_length: u16::try_from(size_of::<EfiFirmwareVolume>() + 2 * size_of::<EfiFvBlockMapEntry>()).unwrap(),
        checksum: 0xF919,
        ext_header_offset: 0,
        reserved: 0,
        revision: 2,
    }).unwrap();
    bincode::serialize_into(&mut file, &EfiFvBlockMapEntry {
        num_blocks: u32::try_from(FV_LENGTH / u64::from(FV_BLOCKSIZE)).unwrap(),
        length: FV_BLOCKSIZE
    }).unwrap();
    bincode::serialize_into(&mut file, &EfiFvBlockMapEntry {
        num_blocks: 0,
        length:0
    }).unwrap();

    let curpos = file.seek(SeekFrom::Current(0)).unwrap();
    let aligned_pos = (curpos + 4 - 1) & !(4 - 1);
    file.seek(SeekFrom::Start(aligned_pos)).unwrap();

    bincode::serialize_into(&mut file, &VariableStoreHeader {
        signature: EfiGuid::EFI_AUTHENTICATED_VARIABLE,
        size: 0xDFB8,
        format: 0x5A,
        state: 0xFE,
        reserved: 0,
        reserved1: 0,
    }).unwrap();

    let data = std::fs::read("target/keys/PK.esl").unwrap();
    let secure_var_attrs : VariableAttributes = VariableAttributes::NON_VOLATILE |
        VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

    serialize_var(&mut file, "db", EfiGuid::EFI_IMAGE_SECURITY_DATABASE, secure_var_attrs | VariableAttributes::RUNTIME_ACCESS, &data);
    serialize_var(&mut file, "KEK", EfiGuid::EFI_GLOBAL_VARIABLE, secure_var_attrs | VariableAttributes::RUNTIME_ACCESS, &data);
    serialize_var(&mut file, "PK", EfiGuid::EFI_GLOBAL_VARIABLE, secure_var_attrs | VariableAttributes::RUNTIME_ACCESS, &data);
    serialize_var(&mut file, "VendorKeysNv", EfiGuid::EFI_VENDOR_KEYS_NV, secure_var_attrs, &[0]);
    serialize_var(&mut file, "SecureBootEnable", EfiGuid::EFI_SECURE_BOOT_ENABLE, VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS, &[1]);
    serialize_var(&mut file, "CustomMode", EfiGuid::EFI_CUSTOM_MODE_ENABLE, VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS, &[0]);
    let mut curpos = file.seek(SeekFrom::Current(0)).unwrap();
    while curpos < FV_LENGTH {
        let data = [0xFF; 0x1000];
        let maxsize = std::cmp::min(FV_LENGTH - curpos, data.len() as u64);
        let written = file.write(&data[..maxsize as usize]).unwrap();
        curpos += written as u64;
    }
}