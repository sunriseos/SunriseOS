//! Paging.

pub mod process_memory;
pub mod kernel_memory;
pub mod lands;
mod hierarchical_table;
mod arch;

pub use self::arch::{PAGE_SIZE, read_cr2};
pub use self::hierarchical_table::PageState;

bitflags! {
    /// The flags of a mapping.
    pub struct MappingFlags : u32 {
        const WRITABLE =        1 << 0;
    }
}