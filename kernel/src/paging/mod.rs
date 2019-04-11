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
mod hierarchical_table;
mod arch;
mod bookkeeping;

pub use self::arch::{PAGE_SIZE, read_cr2};
pub use self::hierarchical_table::PageState;
use sunrise_libkern;

bitflags! {
    /// The flags of a mapping.
    pub struct MappingAccessRights : u32 {
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

impl From<MappingAccessRights> for sunrise_libkern::MemoryPermissions {
    fn from(perms: MappingAccessRights) -> Self {
        let mut newperms = sunrise_libkern::MemoryPermissions::empty();
        if !perms.contains(MappingAccessRights::USER_ACCESSIBLE) {
            return newperms;
        }
        newperms.set(sunrise_libkern::MemoryPermissions::READABLE, perms.contains(MappingAccessRights::READABLE));
        newperms.set(sunrise_libkern::MemoryPermissions::WRITABLE, perms.contains(MappingAccessRights::WRITABLE));
        newperms.set(sunrise_libkern::MemoryPermissions::EXECUTABLE, perms.contains(MappingAccessRights::EXECUTABLE));
        newperms
    }
}

impl From<sunrise_libkern::MemoryPermissions> for MappingAccessRights {
    fn from(perms: sunrise_libkern::MemoryPermissions) -> Self {
        let mut newperms = MappingAccessRights::USER_ACCESSIBLE;
        newperms.set(MappingAccessRights::READABLE, perms.contains(sunrise_libkern::MemoryPermissions::READABLE));
        newperms.set(MappingAccessRights::WRITABLE, perms.contains(sunrise_libkern::MemoryPermissions::WRITABLE));
        newperms.set(MappingAccessRights::EXECUTABLE, perms.contains(sunrise_libkern::MemoryPermissions::EXECUTABLE));
        newperms
    }
}

impl MappingAccessRights {
    /// Shorthand for READABLE
    pub fn k_r() -> MappingAccessRights {
        MappingAccessRights::READABLE
    }

    /// Shorthand for WRITABLE
    pub fn k_w() -> MappingAccessRights {
        MappingAccessRights::WRITABLE
    }

    /// Shorthand for READABLE | WRITABLE
    pub fn k_rw() -> MappingAccessRights {
        MappingAccessRights::READABLE | MappingAccessRights::WRITABLE
    }

    /// Shorthand for READABLE | EXECUTABLE
    pub fn k_rx() -> MappingAccessRights {
        MappingAccessRights::READABLE | MappingAccessRights::EXECUTABLE
    }

    /// Shorthand for USER_ACCESSIBLE | READABLE
    pub fn u_r() -> MappingAccessRights {
        MappingAccessRights::USER_ACCESSIBLE | MappingAccessRights::READABLE
    }

    /// Shorthand for USER_ACCESSIBLE | WRITABLE
    pub fn u_w() -> MappingAccessRights {
        MappingAccessRights::USER_ACCESSIBLE | MappingAccessRights::WRITABLE
    }

    /// Shorthand for USER_ACCESSIBLE | WRITABLE
    pub fn u_rw() -> MappingAccessRights {
        MappingAccessRights::USER_ACCESSIBLE | MappingAccessRights::READABLE | MappingAccessRights::WRITABLE
    }

    /// Shorthand for USER_ACCESSIBLE | WRITABLE
    pub fn u_rx() -> MappingAccessRights {
        MappingAccessRights::USER_ACCESSIBLE | MappingAccessRights::READABLE | MappingAccessRights::EXECUTABLE
    }
}
