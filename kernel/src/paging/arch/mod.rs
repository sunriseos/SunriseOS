//! Arch-specific implementations of paging

mod i386;

pub use self::i386::{PAGE_SIZE, ENTRY_COUNT};
pub use self::i386::table::{ActiveHierarchy, InactiveHierarchy};
pub use self::i386::entry::I386Entry as Entry;
pub use self::i386::entry::I386EntryFlags as EntryFlags;
pub use self::i386::is_paging_on;
pub use self::i386::{read_cr2, read_cr3}; // todo: expose current page directory's address in an arch-independant way.
pub use self::i386::lands::{KernelLand, UserLand, RecursiveTablesLand};
