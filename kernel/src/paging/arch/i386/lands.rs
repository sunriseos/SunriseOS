//! i386 Virtual Memory Layout
//!
//! This module describes the splitting of memory for the i386 architecture.
//!
//! The layout for the 4GB address space is the following:
//!
//! ```
//! 0x00000000 - 0xbfffffff:  3GB of virtual memory belonging to the user.
//! 0xc0000000 - 0xffbfffff: ~1GB of virtual memory belonging to the kernel.
//! 0xffc00000 - 0xffffffff:  4MB of virtual memory pointing to the page tables themselves.
//! ```

use crate::paging::lands::VirtualSpaceLand;
use crate::mem::VirtualAddress;
use super::{PAGE_SIZE, ENTRY_COUNT};

/// The virtual memory belonging to kernel.
#[derive(Debug)] pub struct KernelLand;
/// The virtual memory belonging to user.
#[derive(Debug)] pub struct UserLand;
/// The virtual memory pointing to active page tables by recursion.
#[derive(Debug)] pub struct RecursiveTablesLand;

impl VirtualSpaceLand for UserLand {
    const START: VirtualAddress = VirtualAddress(0x00000000);
    const END:   VirtualAddress = VirtualAddress(0xbfffffff);
}

impl VirtualSpaceLand for KernelLand {
    const START: VirtualAddress = VirtualAddress(0xc0000000);
    const   END: VirtualAddress = VirtualAddress(0xffbfffff);
}

impl VirtualSpaceLand for RecursiveTablesLand {
    const START: VirtualAddress = VirtualAddress(0xffc00000);
    const   END: VirtualAddress = VirtualAddress(0xffffffff);
}

/// When paging is on, accessing this address loops back to the directory itself thanks to
/// recursive mapping on directory's last entry.
pub const DIRECTORY_RECURSIVE_ADDRESS: VirtualAddress = VirtualAddress(0xffff_f000);

/// The index in page directory of the first table of UserLand.
pub const USERLAND_START_TABLE: usize = UserLand::START.addr() / (PAGE_SIZE * ENTRY_COUNT) as usize;
/// The index in page directory of the last table of UserLand.
pub const USERLAND_END_TABLE:   usize = UserLand::END.addr()   / (PAGE_SIZE * ENTRY_COUNT) as usize;

/// The index in page directory of the first table of KernelLand.
pub const KERNELLAND_START_TABLE: usize = KernelLand::START.addr() / (PAGE_SIZE * ENTRY_COUNT) as usize;
/// The index in page directory of the last table of KernelLand.
pub const KERNELLAND_END_TABLE:   usize = KernelLand::END.addr()   / (PAGE_SIZE * ENTRY_COUNT) as usize;

// Assertions to check that Kernel/User pages falls on distinct page tables
// and also that they do not overlap.

const_assert!(KernelLand::START.0 < KernelLand::END.0);
const_assert!(UserLand::START.0 < UserLand::END.0);
const_assert!(RecursiveTablesLand::START.0 < RecursiveTablesLand::END.0);
// TODO: Const FN sucks! Check that the kernelland and userland don't overlap.
//const_assert!(::core::cmp::max(KernelLand::start_addr(), UserLand::start_addr()) >=
//              ::core::cmp::min(KernelLand::end_addr(),   UserLand::end_addr()));

const_assert!(KernelLand::START.0 % (ENTRY_COUNT * PAGE_SIZE) == 0);
const_assert!(UserLand::START.0   % (ENTRY_COUNT * PAGE_SIZE) == 0);
