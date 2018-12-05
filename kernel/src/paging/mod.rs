//! Paging.
//!
//! ```
//! j-------------------------------j j---------------------j
//! |        Process Memory         | |    Kernel Memory    |
//! j-------------------------------j j---------------------j
//!                 |                            |
//!     j-----------------------j                |
//!     | Userspace Bookkeeping |                |
//!     j-----------------------j                |
//!                 |                            |
//! j--------------------------------+----------------~-----j
//! |           User Land            |   Kernel Land  | RTL |
//! j--------------------------------+----------------~-----j
//!                         Page tables
//! ```


pub mod process_memory;
pub mod kernel_memory;
pub mod lands;
pub mod mapping;
pub mod cross_process;
pub mod error;
mod hierarchical_table;
mod arch;
mod bookkeeping;

pub use self::arch::{PAGE_SIZE, read_cr2};
pub use self::hierarchical_table::PageState;
use kfs_libkern;

bitflags! {
    /// The flags of a mapping.
    pub struct MappingFlags : u32 {
        /// Mapping is readable.
        const READABLE =        1 << 0;
        /// Mapping is writable.
        const WRITABLE =        1 << 1;
        /// Mapping is executable.
        const EXECUTABLE =      1 << 2;
        /// Mapping can be accessed from userland,
        /// with the same permissions as the kernel.
        const USER_ACCESSIBLE = 1 << 3;
    }
}

impl From<MappingFlags> for kfs_libkern::MemoryPermissions {
    fn from(perms: MappingFlags) -> Self {
        let mut newperms = kfs_libkern::MemoryPermissions::empty();
        if !perms.contains(MappingFlags::USER_ACCESSIBLE) {
            return newperms;
        }
        newperms.set(kfs_libkern::MemoryPermissions::READABLE, perms.contains(MappingFlags::READABLE));
        newperms.set(kfs_libkern::MemoryPermissions::WRITABLE, perms.contains(MappingFlags::WRITABLE));
        newperms.set(kfs_libkern::MemoryPermissions::EXECUTABLE, perms.contains(MappingFlags::EXECUTABLE));
        newperms
    }
}

impl From<kfs_libkern::MemoryPermissions> for MappingFlags {
    fn from(perms: kfs_libkern::MemoryPermissions) -> Self {
        let mut newperms = MappingFlags::USER_ACCESSIBLE;
        newperms.set(MappingFlags::READABLE, perms.contains(kfs_libkern::MemoryPermissions::READABLE));
        newperms.set(MappingFlags::WRITABLE, perms.contains(kfs_libkern::MemoryPermissions::WRITABLE));
        newperms.set(MappingFlags::EXECUTABLE, perms.contains(kfs_libkern::MemoryPermissions::EXECUTABLE));
        newperms
    }
}

impl MappingFlags {
    /// Shorthand for READABLE
    pub fn k_r() -> MappingFlags {
        MappingFlags::READABLE
    }

    /// Shorthand for WRITABLE
    pub fn k_w() -> MappingFlags {
        MappingFlags::WRITABLE
    }

    /// Shorthand for READABLE | WRITABLE
    pub fn k_rw() -> MappingFlags {
        MappingFlags::READABLE | MappingFlags::WRITABLE
    }

    /// Shorthand for READABLE | EXECUTABLE
    pub fn k_rx() -> MappingFlags {
        MappingFlags::READABLE | MappingFlags::EXECUTABLE
    }

    /// Shorthand for USER_ACCESSIBLE | READABLE
    pub fn u_r() -> MappingFlags {
        MappingFlags::USER_ACCESSIBLE | MappingFlags::READABLE
    }

    /// Shorthand for USER_ACCESSIBLE | WRITABLE
    pub fn u_w() -> MappingFlags {
        MappingFlags::USER_ACCESSIBLE | MappingFlags::WRITABLE
    }

    /// Shorthand for USER_ACCESSIBLE | WRITABLE
    pub fn u_rw() -> MappingFlags {
        MappingFlags::USER_ACCESSIBLE | MappingFlags::READABLE | MappingFlags::WRITABLE
    }

    /// Shorthand for USER_ACCESSIBLE | WRITABLE
    pub fn u_rx() -> MappingFlags {
        MappingFlags::USER_ACCESSIBLE | MappingFlags::READABLE | MappingFlags::EXECUTABLE
    }
}
