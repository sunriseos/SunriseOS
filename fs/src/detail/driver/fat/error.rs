//! Error utils for the libuser <=> libfat

use libfat::FatError;
use sunrise_libuser::error::{Error, FileSystemError};

/// Convert a FatError to a libuser Error
pub fn from_driver(error: FatError) -> Error {
    match error {
        FatError::NotFound => FileSystemError::FileNotFound,
        FatError::NoSpaceLeft => FileSystemError::NoSpaceLeft,
        FatError::AccessDenied => FileSystemError::AccessDenied,
        FatError::WriteFailed => FileSystemError::WriteFailed,
        FatError::ReadFailed => FileSystemError::ReadFailed,
        FatError::PartitionNotFound => FileSystemError::PartitionNotFound,
        FatError::NotAFile => FileSystemError::NotAFile,
        FatError::NotADirectory => FileSystemError::NotADirectory,
        FatError::FileExists => FileSystemError::PathExists,
        FatError::PathTooLong => FileSystemError::PathTooLong,
        FatError::InvalidPartition => FileSystemError::InvalidPartition,
        _ => FileSystemError::Unknown,
    }.into()
}
