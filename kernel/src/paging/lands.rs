//! Module describing the split between the UserSpace and KernelSpace,
//! and a few functions to work with it.

use crate::mem::VirtualAddress;
use super::PAGE_SIZE;
use super::arch::ENTRY_COUNT;
use crate::error::KernelError;
use failure::Backtrace;

/// A trait describing the splitting of virtual memory between Kernel and User.
/// Implemented by UserLand and KernelLand
pub trait VirtualSpaceLand {
    /// The first address in this land.
    const START: VirtualAddress;
    /// The last address in this land.
    const END: VirtualAddress;

    /// The first address in this land.
    fn start_addr() -> VirtualAddress { Self::START }

    /// The last address in this land.
    fn end_addr() -> VirtualAddress { Self::END }

    /// The length of this land.
    fn length() -> usize { Self::end_addr().addr() - Self::start_addr().addr() + 1 }

    // TODO: VirtalSpaceLand start_table/ end_table is arch specific
    // BODY: These functions should be moved to `paging::arch::i386::table.rs`
    /// The index in page directory of the first table of this land.
    fn start_table() -> usize {
        Self::start_addr().addr() / (PAGE_SIZE * ENTRY_COUNT) as usize
    }

    /// The index in page directory of the last table of this land.
    fn end_table() -> usize {
        Self::end_addr().addr() / (PAGE_SIZE * ENTRY_COUNT) as usize
    }

    /// Is the address contained in this Land ?
    fn contains_address(address: VirtualAddress) -> bool {
        Self::start_addr() <= address && address <= Self::end_addr()
    }

    /// Is the region fully contained in this Land ?
    ///
    /// # Panics
    ///
    /// Panics if size is 0.
    // TODO: Land::contains_region() should not panic on 0 length
    // BODY: This function should return an error, as it really is likely someone (I)
    // BODY: will call it at some point not expecting it can panic.
    fn contains_region(start_address: VirtualAddress, size: usize) -> bool {
        assert!(size != 0, "contains_region : size == 0");
        let sum = start_address.addr().checked_add(size - 1);
        if let Some(end_address) = sum {
            Self::contains_address(start_address) && Self::contains_address(VirtualAddress(end_address))
        } else {
            false
        }
    }

    /// Checks that a given address falls in this land, or return an InvalidAddress otherwise
    fn check_contains_address(address: VirtualAddress) -> Result<(), KernelError> {
        Self::check_contains_region(address, 1)
    }

    /// Checks that a given region falls in this land, or return an InvalidAddress otherwise
    fn check_contains_region(address: VirtualAddress, length: usize) -> Result<(), KernelError> {
        if Self::contains_region(address, length) {
            Ok(())
        } else {
            Err(KernelError::InvalidAddress { address, length, backtrace: Backtrace::new() })
        }
    }
}

/// The virtual memory belonging to kernel
#[derive(Debug)] pub struct KernelLand;
/// The virtual memory belonging to user
#[derive(Debug)] pub struct UserLand;
/// The virtual memory pointing to active page tables by recursion
#[derive(Debug)] pub struct RecursiveTablesLand;

// TODO: move KernelLand Userland RTL to arch-specific paging
// BODY: They are arch dependant, we should stop trying defining them in an agnostic way,
// BODY: even if they are expected to be the same for 32 bits architectures.
// BODY:
// BODY: Especially for the Recursive Tables Land. Even if it's a agnostic concept, its size in
// BODY: virtual memory is mmu-dependant, and defined by the number of levels the mmu uses.

// if 32 bit, we define UserLand and KernelLand here
#[cfg(any(target_pointer_width = "32", test))]
impl VirtualSpaceLand for UserLand {
    const START: VirtualAddress = VirtualAddress(0x00000000);
    const END:   VirtualAddress = VirtualAddress(0xbfffffff);
}

#[cfg(any(target_pointer_width = "32", test))]
impl VirtualSpaceLand for KernelLand {
    const START: VirtualAddress = VirtualAddress(0xc0000000);
    const   END: VirtualAddress = VirtualAddress(0xffbfffff);
}

#[cfg(any(target_pointer_width = "32", test))]
impl VirtualSpaceLand for RecursiveTablesLand {
    const START: VirtualAddress = VirtualAddress(0xffc00000);
    const   END: VirtualAddress = VirtualAddress(0xffffffff);
}
// else we do it in arch-specific implementations

/// Assertions to check that Kernel/User pages falls on distinct page tables
/// and also that they do not overlap.
const_assert!(KernelLand::START.0 < KernelLand::END.0);
const_assert!(UserLand::START.0 < UserLand::END.0);
const_assert!(RecursiveTablesLand::START.0 < RecursiveTablesLand::END.0);
// TODO: Const FN sucks! Check that the kernelland and userland don't overlap.
//const_assert!(::core::cmp::max(KernelLand::start_addr(), UserLand::start_addr()) >=
//              ::core::cmp::min(KernelLand::end_addr(),   UserLand::end_addr()));

const_assert!(KernelLand::START.0 % (ENTRY_COUNT * PAGE_SIZE) == 0);
const_assert!(UserLand::START.0   % (ENTRY_COUNT * PAGE_SIZE) == 0);
