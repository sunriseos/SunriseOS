//! Bookkeeping of mappings in UserLand

use mem::VirtualAddress;
use paging::{PAGE_SIZE, MappingFlags};
use paging::lands::{UserLand, KernelLand, RecursiveTablesLand, VirtualSpaceLand};
use frame_allocator::PhysicalMemRegion;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use error::{KernelError, UserspaceError};
use super::error::MmError;
use utils::{Splittable, check_aligned, check_nonzero_length};
use failure::Backtrace;
use super::mapping::{Mapping, MappingType};

/// A bookkeeping is just a list of Mappings
///
/// We store them in a BTreeMap where the address is the key, to obtain O(log(n)) search time
/// for the closest mapping of a given address.
///
/// We do not store Available mappings in it, as it would require a lot of splitting overhead,
/// and instead consider holes as Available mappings.
#[derive(Debug)]
pub struct UserspaceBookkeeping {
    mappings: BTreeMap<VirtualAddress, Mapping>
}

/// Because we do not store Available mappings internally, we need this enum to return
/// a new available mappings, or a reference to the stored mapping.
#[derive(Debug)]
pub enum QueryMemory<'a> {
    Available(Mapping),
    Used(&'a Mapping)
}

impl UserspaceBookkeeping {
    /// Constructs a UserspaceBookkeeping
    ///
    /// Initially contains only SystemReserved regions for KernelLand and RecursiveTableLand
    pub fn new() -> Self {
        let mut mappings = BTreeMap::new();
        let kl = Mapping::new_system_reserved(KernelLand::start_addr(), KernelLand::length())
            .expect("Cannot create KernelLand system_reserved mapping");
        let rtl = Mapping::new_system_reserved(RecursiveTablesLand::start_addr(), RecursiveTablesLand::length())
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
    pub fn mapping_at(&self, address: VirtualAddress) -> QueryMemory {
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
            Mapping::new_available(address, length)
                .expect("Failed creating an available mapping")
        )
    }

    /// Returns the mapping `address` falls into.
    ///
    /// # Error
    ///
    /// Returns an Error if mapping pointed to by address is vacant.
    pub fn occupied_mapping_at(&self, address: VirtualAddress) -> Result<&Mapping, KernelError> {
        match self.mapping_at_or_preceding(address) {
            // check cannot overflow
            Some(m) if m.length() - 1 + m.address() >= address => Ok(m),
            _ => Err(KernelError::MmError(MmError::WasAvailable { address, backtrace: Backtrace::new() }))
        }
    }

    /// Checks that a given range is unoccupied.
    ///
    /// # Error
    ///
    /// Returns an Error if address + length - 1 would overflow.
    /// Returns an Error if length is 0.
    pub fn is_vacant(&self, address: VirtualAddress, length: usize) -> Result<bool, KernelError> {
        check_nonzero_length(length)?;
        let end_addr = address.checked_add(length - 1)?;
        Ok(self.mappings.range(address..=end_addr).next().is_none())
    }

    /// Asserts that a given range is unoccupied
    ///
    /// # Error
    ///
    /// Returns an Error if range is occupied.
    /// Returns an Error if address + length - 1 would overflow.
    /// Returns an Error if length is 0.
    pub fn check_vacant(&self, address: VirtualAddress, length: usize) -> Result<(), KernelError> {
        if !self.is_vacant(address, length)? {
            Err(KernelError::MmError(
                MmError::OccupiedMapping { address, length, backtrace: Backtrace::new() }))
        } else {
            Ok(())
        }
    }

    /// Adds a mapping to the list of tracked mappings
    ///
    /// # Error
    ///
    /// Returns a KernelError if the space was not vacant.
    pub fn add_mapping(&mut self, mapping: Mapping) -> Result<(), KernelError> {
        self.check_vacant(mapping.address(), mapping.length())?;
        self.mappings.insert(mapping.address(), mapping);
        Ok(())
    }

    /// Removes a mapping from the tracked mappings, and returns it.
    ///
    /// This function will never split an existing tracked mapping.
    ///
    /// # Error
    ///
    /// Returns a KernelError if parameters do not span exactly the whole mapping.
    /// Returns a KernelError if address falls in an available mapping.
    pub fn remove_mapping(&mut self, address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        if self.mappings.get(&address)
            .filter(|m| m.length() == length)
            .is_none() {
            Err(KernelError::MmError(MmError::DoesNotSpanMapping { address, length, backtrace: Backtrace::new() }))
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
    pub fn remove_mapping_split(&mut self, address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
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
        let mut last_address = VirtualAddress(0x00000000);
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
