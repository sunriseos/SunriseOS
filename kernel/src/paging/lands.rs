//! Module describing the split between the UserSpace and KernelSpace,
//! and a few functions to work with it.

use mem::VirtualAddress;
use super::PAGE_SIZE;
use super::arch::ENTRY_COUNT;
use error::KernelError;
use failure::Backtrace;

/// A trait describing the splitting of virtual memory between Kernel and User.
/// Implemented by UserLand and KernelLand
pub trait VirtualSpaceLand {
    /// The first address in this land.
    fn start_addr() -> VirtualAddress;

    /// The last address in this land.
    fn end_addr() -> VirtualAddress;

    /// The length of this land.
    fn length() -> usize { Self::end_addr().addr() - Self::start_addr().addr() + 1 }

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
pub struct KernelLand;
/// The virtual memory belonging to user
pub struct UserLand;
/// The virtual memory pointing to active page tables by recursion
pub struct RecursiveTablesLand;

// if 32 bit, we define UserLand and KernelLand here
#[cfg(any(target_pointer_width = "32", test))]
impl UserLand {
    const fn start_addr() -> VirtualAddress { VirtualAddress(0x00000000) }
    const fn end_addr()   -> VirtualAddress { VirtualAddress(0xbfffffff) }
}

#[cfg(any(target_pointer_width = "32", test))]
impl KernelLand {
    const fn start_addr() -> VirtualAddress { VirtualAddress(0xc0000000) }
    const fn end_addr()   -> VirtualAddress { VirtualAddress(0xffbfffff) }
}

#[cfg(any(target_pointer_width = "32", test))]
impl RecursiveTablesLand {
    const fn start_addr() -> VirtualAddress { VirtualAddress(0xffc00000) }
    const fn end_addr()   -> VirtualAddress { VirtualAddress(0xffffffff) }
}
// else we do it in arch-specific implementations

impl VirtualSpaceLand for KernelLand {
    fn start_addr() -> VirtualAddress { Self::start_addr() }
    fn end_addr()   -> VirtualAddress { Self::end_addr() }
}

impl VirtualSpaceLand for UserLand {
    fn start_addr() -> VirtualAddress { Self::start_addr() }
    fn end_addr()   -> VirtualAddress { Self::end_addr() }
}

impl VirtualSpaceLand for RecursiveTablesLand {
    fn start_addr() -> VirtualAddress { Self::start_addr() }
    fn end_addr()   -> VirtualAddress { Self::end_addr() }
}

// Assertions to check that Kernel/User pages falls on distinct page tables
// and also that they do not overlap
fn __land_assertions() {
    const_assert!(KernelLand::start_addr().0 < KernelLand::end_addr().0);
    const_assert!(UserLand::start_addr().0 < UserLand::end_addr().0);
    // TODO: Const FN sucks! Check that the kernelland and userland don't overlap.
    //const_assert!(::core::cmp::max(KernelLand::start_addr(), UserLand::start_addr()) >=
    //              ::core::cmp::min(KernelLand::end_addr(),   UserLand::end_addr()));

    const_assert!(KernelLand::start_addr().0 % (ENTRY_COUNT * PAGE_SIZE) == 0);
    const_assert!(UserLand::start_addr().0   % (ENTRY_COUNT * PAGE_SIZE) == 0);
}

