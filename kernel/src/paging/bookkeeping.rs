//! Bookkeeping of mappings in UserLand

use mem::VirtualAddress;
use paging::PAGE_SIZE;
use paging::lands::{UserLand, KernelLand, RecursiveTablesLand, VirtualSpaceLand};
use frame_allocator::PhysicalMemRegion;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::collections::BTreeMap;
use error::{KernelError, UserspaceError};
use super::error::MmError;
use utils::{Splittable, check_aligned, check_nonzero_length};
use failure::Backtrace;

/// A userspace mapping.
/// Stores the address, the length, and the type it maps.
#[derive(Debug)]
pub struct Mapping {
    pub address: VirtualAddress,
    pub length: usize,
    pub mtype: MappingType
}

/// The types that a UserSpace mapping can be in.
///
/// If it maps physical memory regions, we hold them in a Vec.
/// They will be de-allocated when this enum is dropped.
#[derive(Debug)]
pub enum MappingType {
    Available,
    Guarded,
    Regular(Vec<PhysicalMemRegion>),
    Stack(Vec<PhysicalMemRegion>),
    Shared(Arc<Vec<PhysicalMemRegion>>),
    SystemReserved // used for anything that UserSpace isn't authorized to address
}

impl Splittable for Mapping {
    /// Splits a mapping at a given offset.
    ///
    /// Because it is reference counted, a Shared mapping cannot be splitted.
    fn split_at(&mut self, offset: usize) -> Result<Option<Self>, KernelError> {
        check_aligned(offset, PAGE_SIZE)?;
        if offset == 0 || offset >= self.length { return Ok(None) };
        let right = Mapping {
            address: self.address + offset,
            length: self.length - offset,
            mtype: match &mut self.mtype {
                MappingType::Available => MappingType::Available,
                MappingType::Guarded => MappingType::Guarded,
                MappingType::Regular(ref mut frames) => MappingType::Regular(frames.split_at(offset)?.unwrap()),
                MappingType::Stack(ref mut frames) => MappingType::Stack(frames.split_at(offset)?.unwrap()),
                MappingType::Shared(arc) => return Err(KernelError::MmError(
                                                       MmError::SharedMapping { backtrace: Backtrace::new() })),
                MappingType::SystemReserved => panic!("shouldn't split a SystemReserved mapping"),
            },
            private: ()
        };
        // split succeeded, now modify left part
        self.length = offset;
        Ok(Some(right))
    }
}

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
pub enum QuerryMemory<'a> {
    Available(Mapping),
    Used(&'a Mapping)
}

impl UserspaceBookkeeping {
    /// Constructs a UserspaceBookkeeping
    ///
    /// Initially contains only SystemReserved regions for KernelLand and RecursiveTableLand
    pub fn new() -> Self {
        let mut mappings = BTreeMap::new();
        let kl = Mapping {
            address: KernelLand::start_addr(),
            length: KernelLand::length(),
            mtype: MappingType::SystemReserved
        };
        let rtl = Mapping {
            address: RecursiveTablesLand::start_addr(),
            length: RecursiveTablesLand::length(),
            mtype: MappingType::SystemReserved
        };
        mappings.insert(kl.address, kl);
        mappings.insert(rtl.address, rtl);
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

    /// Returns the mapping `address` falls into
    pub fn mapping_at(&self, address: VirtualAddress) -> QuerryMemory {
        let start_addr = match self.mapping_at_or_preceding(address) {
            Some(m) if m.address + m.length > address => return QuerryMemory::Used(m), // address falls in m
            Some(m) => m.address + m.length,
            None => VirtualAddress(0x00000000),
        };
        let length = match self.mapping_at_or_following(address) {
            Some(m) => m.address.addr() - start_addr.addr(),
            None => usize::max_value() - start_addr.addr() + 1
        };
        QuerryMemory::Available(Mapping {
            address: start_addr,
            length: length,
            mtype: MappingType::Available
        })
    }

    /// Checks that a given range is unoccupied.
    ///
    /// # Error
    ///
    /// Returns an Error if address + length would overflow.
    pub fn is_vacant(&self, address: VirtualAddress, length: usize) -> Result<bool, KernelError> {
        let end_addr = address.checked_add(length)?;
        Ok(self.mappings.range(address..end_addr).next().is_none())
    }

    /// Asserts that a given range is unoccupied
    ///
    /// # Error
    ///
    /// Returns an Error if range is occupied.
    /// Returns an Error if address + length would overflow.
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
    /// Returns a KernelError if mapping.addr + mapping.length would overflow.
    /// Returns a KernelError if mapping.length is 0.
    pub fn add_mapping(&mut self, mapping: Mapping) -> Result<(), KernelError> {
        check_nonzero_length(mapping.length)?;
        self.check_vacant(mapping.address, mapping.length)?;
        self.mappings.insert(mapping.address, mapping);
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
            .filter(|m| m.length == length)
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
}
