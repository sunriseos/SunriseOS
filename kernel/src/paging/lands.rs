//! Module describing the split between the UserSpace and KernelSpace,
//! and a few functions to work with it.

pub use super::arch::{KernelLand, UserLand, RecursiveTablesLand};

use crate::mem::VirtualAddress;
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
            Err(KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new() })
        }
    }
}
