//! Bookkeeping of mappings in UserLand

use crate::mem::VirtualAddress;
use crate::paging::lands::{UserLand, KernelLand, RecursiveTablesLand, VirtualSpaceLand};
use crate::paging::mapping::MappingFrames;
use crate::paging::MappingAccessRights;
use sunrise_libkern::MemoryType;
use alloc::collections::BTreeMap;
use crate::error::KernelError;
use crate::utils::check_nonzero_length;
use failure::Backtrace;
use super::mapping::Mapping;

/// A bookkeeping is just a list of Mappings
///
/// We store them in a BTreeMap where the address is the key, to obtain O(log(n)) search time
/// for the closest mapping of a given address.
///
/// We do not store Available mappings in it, as it would require a lot of splitting overhead,
/// and instead consider holes as Available mappings.
#[derive(Debug)]
pub struct UserspaceBookkeeping {
    /// The list of mappings of this process.
    mappings: BTreeMap<VirtualAddress, Mapping>
}

/// Because we do not store Available mappings internally, we need this enum to return
/// a new available mappings, or a reference to the stored mapping.
#[derive(Debug)]
#[allow(missing_docs)]
pub enum QueryMemory<'a> {
    /// The address fell in an available range.
    Available(Mapping),
    /// The address fell in an existing mapping.
    Used(&'a Mapping)
}

impl<'a> QueryMemory<'a> {
    /// Returns a reference to the underlying mapping.
    pub fn mapping(&self) -> &Mapping {
        match self {
            QueryMemory::Available(mem) => mem,
            QueryMemory::Used(mem) => mem,
        }
    }
}

impl UserspaceBookkeeping {
    /// Constructs a UserspaceBookkeeping
    ///
    /// Initially contains only SystemReserved regions for KernelLand and RecursiveTableLand
    pub fn new() -> Self {
        let mut mappings = BTreeMap::new();
        let kl = Mapping::new(KernelLand::start_addr(), MappingFrames::None, 0, KernelLand::length(), MemoryType::Reserved, MappingAccessRights::empty())
            .expect("Cannot create KernelLand system_reserved mapping");
        let rtl = Mapping::new(RecursiveTablesLand::start_addr(), MappingFrames::None, 0, RecursiveTablesLand::length(), MemoryType::Reserved, MappingAccessRights::empty())
            .expect("Cannot create RecursiveTableLand system_reserved mapping");
        mappings.insert(kl.address(), kl);
        mappings.insert(rtl.address(), rtl);
        UserspaceBookkeeping { mappings }
    }

    /// Returns the mapping `address` falls into, or if it is available,
    /// the first following mapping.
    ///
    /// If no mapping follows `address`, returns None
    pub fn mapping_at_or_following(&self, address: VirtualAddress) -> Option<&Mapping> {
        self.mappings.range(address..).next()
            .map(|(_, mapping)| mapping)
    }

    /// Returns the mapping `address` falls into, or if it is available,
    /// the first preceding mapping.
    ///
    /// If no mapping precedes `address`, returns None
    pub fn mapping_at_or_preceding(&self, address: VirtualAddress) -> Option<&Mapping> {
        self.mappings.range(VirtualAddress(0)..=address).rev().next()
            .map(|(_, mapping)| mapping)
    }

    /// Returns the mapping `address` falls into.
    pub fn mapping_at(&self, address: VirtualAddress) -> QueryMemory<'_> {
        let start_addr = match self.mapping_at_or_preceding(address) {
            // check cannot overflow
            Some(m) if m.length() - 1 + m.address() >= address => return QueryMemory::Used(m), // address falls in m
            Some(m) => m.address() + m.length(),
            None => VirtualAddress(0x00000000),
        };
        let length = match self.mapping_at_or_following(address) {
            Some(m) => m.address() - start_addr,
            None => usize::max_value() - start_addr.addr() + 1
            // todo this could overflow for 0x00000000-0xffffffff.
        };
        QueryMemory::Available(
            Mapping::new(start_addr, MappingFrames::None, 0, length, MemoryType::Unmapped, MappingAccessRights::empty())
                .expect("Failed creating an available mapping")
        )
    }

    /// Returns the mapping `address` falls into.
    ///
    /// Fails if there is no occupied mapping at `address`.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * mapping pointed to by address is vacant.
    pub fn occupied_mapping_at(&self, address: VirtualAddress) -> Result<&Mapping, KernelError> {
        match self.mapping_at_or_preceding(address) {
            // check cannot overflow
            Some(m) if m.length() - 1 + m.address() >= address => Ok(m),
            _ => Err(KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new() })
        }
    }

    /// Checks that a given range is unoccupied.
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * `address + length - 1` would overflow
    /// * `InvalidSize`:
    ///     * `length` is 0.
    pub fn is_vacant(&self, address: VirtualAddress, length: usize) -> Result<bool, KernelError> {
        check_nonzero_length(length)?;
        let end_addr = address.checked_add(length - 1)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new()})?;
        Ok(self.mappings.range(address..=end_addr).next().is_none())
    }

    /// Asserts that a given range is unoccupied
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * range is occupied.
    ///     * `address + length - 1` would overflow
    /// * `InvalidSize`:
    ///     * `length` is 0.
    pub fn check_vacant(&self, address: VirtualAddress, length: usize) -> Result<(), KernelError> {
        if !self.is_vacant(address, length)? {
            Err(KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new() })
        } else {
            Ok(())
        }
    }

    /// Adds a mapping to the list of tracked mappings
    ///
    /// # Errors
    ///
    /// * `InvalidAddress`:
    ///     * range is not vacant.
    pub fn add_mapping(&mut self, mapping: Mapping) -> Result<(), KernelError> {
        self.check_vacant(mapping.address(), mapping.length())?;
        self.mappings.insert(mapping.address(), mapping);
        Ok(())
    }

    /// Removes a mapping from the tracked mappings, and returns it.
    ///
    /// This function will never split an existing tracked mapping.
    ///
    /// # Errors
    ///
    /// `InvalidAddress`:
    ///     * `address` does not correspond to the start of a mapping.
    /// `InvalidSize`:
    ///     * `length` is not the size of the mapping at `address`.
    pub fn remove_mapping(&mut self, address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        if self.mappings.get(&address)
            .ok_or_else(|| KernelError::InvalidAddress { address: address.addr(), backtrace: Backtrace::new() })?
        .length() != length {
            Err(KernelError::InvalidSize { size: length, backtrace: Backtrace::new() })
        } else {
            Ok(self.mappings.remove(&address).unwrap())
        }
    }

    /// Removes part of a mapping from the tracked mappings, and returns it.
    ///
    /// If the range given by address-length falls inside an existing mapping,
    /// and this region is bigger than the range, the region is splitted in parts,
    /// and the part corresponding to the requested range is removed and returned.
    ///
    /// # Error
    ///
    /// Returns a KernelError if address falls in an available mapping.
    /// Returns a KernelError if the range spans multiple mappings.
    /// Returns a KernelError if the range falls in a Shared mapping, as it cannot be splitted.
    pub fn remove_mapping_split(&mut self, _address: VirtualAddress, _length: usize) -> Result<Mapping, KernelError> {
        unimplemented!()
    }

    /// Finds a hole in virtual space at least `length` long.
    ///
    /// # Error
    ///
    /// Returns a KernelError if no sufficiently big hole was found.
    /// Returns a KernelError if `length` is 0.
    pub fn find_available_space(&self, length: usize) -> Result<VirtualAddress, KernelError> {
        check_nonzero_length(length)?;
        let mut last_address = UserLand::START;
        for m in self.mappings.values() {
            if m.address() - last_address >= length {
                return Ok(last_address)
            }
            last_address = VirtualAddress(m.address().addr().wrapping_add(m.length()));
            // will overflow for last mapping, but we'll return right after, so it's ok
        }
        Err(KernelError::VirtualMemoryExhaustion { backtrace: Backtrace::new() })
    }
}
