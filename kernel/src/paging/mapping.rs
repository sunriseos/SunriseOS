//! Mapping

use mem::VirtualAddress;
use paging::{PAGE_SIZE, MappingFlags, error::MmError};
use error::{KernelError, ArithmeticOperation};
use frame_allocator::PhysicalMemRegion;
use alloc::{vec::Vec, sync::Arc};
use utils::{check_aligned, check_nonzero_length, Splittable};
use failure::Backtrace;

/// A memory mapping.
/// Stores the address, the length, and the type it maps.
///
/// A mapping is guaranteed to have page aligned address and length,
/// and the length will never be zero.
///
/// If the mapping maps physical frames, we also guarantee that the
/// the virtual length of the mapping is equal to the physical length it maps.
///
/// Getting the last address of this mapping (length - 1 + address) is guaranteed to not overflow.
/// However we do not make any assumption on address + length, which falls outside of the mapping.
#[derive(Debug)]
pub struct Mapping {
    address: VirtualAddress,
    length: usize,
    mtype: MappingType,
    flags: MappingFlags,
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
//    Stack(Vec<PhysicalMemRegion>),
    Shared(Arc<Vec<PhysicalMemRegion>>),
    SystemReserved // used for anything that UserSpace isn't authorized to address
}

impl Mapping {
    /// Tries to construct a regular mapping.
    ///
    /// # Error
    ///
    /// Returns an Error if `address` + `frames`'s length would overflow.
    /// Returns an Error if `address` is not page aligned.
    /// Returns an Error if `length` is 0.
    pub fn new_regular(address: VirtualAddress, frames: Vec<PhysicalMemRegion>, flags: MappingFlags) -> Result<Mapping, KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        let length = frames.iter().flatten().count() * PAGE_SIZE;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)?;
        Ok(Mapping { address, length, mtype: MappingType::Regular(frames), flags })
    }

    /// Tries to construct a shared mapping.
    ///
    /// # Error
    ///
    /// Returns an Error if `address` + `frames`'s length would overflow.
    /// Returns an Error if `address` is not page aligned.
    /// Returns an Error if `length` is 0.
    pub fn new_shared(address: VirtualAddress, frames: Arc<Vec<PhysicalMemRegion>>, flags: MappingFlags) -> Result<Mapping, KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        let length = frames.iter().flatten().count() * PAGE_SIZE;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)?;
        Ok(Mapping { address, length, mtype: MappingType::Shared(frames), flags })
    }

    /// Tries to construct a guarded mapping.
    ///
    /// # Error
    ///
    /// Returns an Error if `address` + `length` would overflow.
    /// Returns an Error if `address` or `length` is not page aligned.
    /// Returns an Error if `length` is 0.
    pub fn new_guard(address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)?;
        Ok(Mapping { address, length, mtype: MappingType::Guarded, flags: MappingFlags::empty() })
    }

    /// Tries to construct an available mapping.
    ///
    /// # Error
    ///
    /// Returns an Error if `address` + `length` would overflow.
    /// Returns an Error if `address` or `length` is not page aligned.
    /// Returns an Error if `length` is 0.
    pub fn new_available(address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)?;
        Ok(Mapping { address, length, mtype: MappingType::Available, flags: MappingFlags::empty() })
    }

    /// Tries to construct a system reserved mapping.
    ///
    /// # Error
    ///
    /// Returns an Error if `address` + `length` would overflow.
    /// Returns an Error if `address` or `length` is not page aligned.
    /// Returns an Error if `length` is 0.
    pub fn new_system_reserved(address: VirtualAddress, length: usize) -> Result<Mapping, KernelError> {
        check_aligned(address.addr(), PAGE_SIZE)?;
        check_aligned(length, PAGE_SIZE)?;
        check_nonzero_length(length)?;
        address.checked_add(length - 1)?;
        Ok(Mapping { address, length, mtype: MappingType::SystemReserved, flags: MappingFlags::empty() })
    }

    /// Returns the address of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn address(&self) -> VirtualAddress { self.address }

    /// Returns the address of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn length(&self) -> usize { self.length }

    /// Returns a reference to the type of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn mtype_ref(&self) -> &MappingType { &self.mtype }

    /// Returns the type of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn mtype(self) -> MappingType { self.mtype }

    /// Returns the type of this mapping.
    ///
    /// Because we make guarantees about a mapping being always valid, this field cannot be public.
    pub fn flags(&self) -> MappingFlags { self.flags }
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
            flags: self.flags,
            mtype: match &mut self.mtype {
                MappingType::Available => MappingType::Available,
                MappingType::Guarded => MappingType::Guarded,
                MappingType::Regular(ref mut frames) => MappingType::Regular(frames.split_at(offset)?.unwrap()),
            //    MappingType::Stack(ref mut frames) => MappingType::Stack(frames.split_at(offset)?.unwrap()),
                MappingType::Shared(arc) => return Err(KernelError::MmError(
                                                       MmError::SharedMapping { backtrace: Backtrace::new() })),
                MappingType::SystemReserved => panic!("shouldn't split a SystemReserved mapping"),
            },
        };
        // split succeeded, now modify left part
        self.length = offset;
        Ok(Some(right))
    }
}
