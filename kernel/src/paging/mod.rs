//! Paging.

pub mod process_memory;
pub mod kernel_memory;
pub mod lands;
pub mod cross_process;
pub mod error;
mod hierarchical_table;
mod arch;
mod bookkeeping;

pub use self::arch::{PAGE_SIZE, read_cr2};
pub use self::hierarchical_table::PageState;
pub use self::bookkeeping::MappingType;

bitflags! {
    /// The flags of a mapping.
    pub struct MappingFlags : u32 {
        const READABLE =        1 << 0;
        const WRITABLE =        1 << 1;
        const EXECUTABLE =      1 << 2;
        const USER_ACCESSIBLE = 1 << 3;
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
