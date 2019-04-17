//! ACPI dectection
//!
//! This module is in charge of detecting the presence of ACPI and provide other part of the kernel with the data about the system.

#![allow(dead_code)]

use acpi;
use acpi::Acpi;
use acpi::AcpiHandler;
use acpi::PhysicalMapping;

use crate::sync::Once;

use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::paging;
use crate::paging::PAGE_SIZE;
use crate::paging::MappingAccessRights;
use crate::frame_allocator::PhysicalMemRegion;

use crate::utils;

/// Stores the ACPI data
static ACPI_INFO: Once<Acpi> = Once::new();


/// Get a reference to the ACPI information.
///
/// # Panics
///
/// Panics if the module hasn't been inited yet or if ACPI isn't availaible.
pub fn get_acpi_information() -> &'static Acpi {
    ACPI_INFO.r#try().expect("Acpi is not availaible")
}

/// Tries to get a pointer to the multiboot information structure.
///
/// Returns `None` if the module hasn't been inited yet or if ACPI isn't availaible.
pub fn try_get_acpi_information() -> Option<&'static Acpi> {
    ACPI_INFO.r#try()
}

/// ACPI Memory handler
struct MemoryHandler;

impl AcpiHandler for MemoryHandler {
    fn map_physical_region<T>(
        &mut self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<T> {
        let physical_address_aligned = utils::align_down(physical_address, PAGE_SIZE);

        let offset = physical_address - physical_address_aligned;
        let aligned_size = utils::align_up(size, PAGE_SIZE);
    
        let physical_mem = unsafe { PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(physical_address_aligned), aligned_size).unwrap() };
        let virtual_address = paging::kernel_memory::get_kernel_memory().map_phys_region(physical_mem, MappingAccessRights::READABLE);
        PhysicalMapping {
            physical_start: physical_address,
            virtual_start: unsafe { core::ptr::NonNull::new_unchecked((virtual_address.0 + offset) as *mut T) },
            region_length: aligned_size,
            mapped_length: aligned_size,
        }
    }

    fn unmap_physical_region<T>(&mut self, region: PhysicalMapping<T>) {
        let virtual_address_aligned = utils::align_down(region.virtual_start.as_ptr() as usize, PAGE_SIZE);
        paging::kernel_memory::get_kernel_memory().unmap_no_dealloc(VirtualAddress(virtual_address_aligned), region.mapped_length);
    }
}

/// Parse ACPI tables and store them.
pub unsafe fn init() {
    let mut handler = MemoryHandler;
    let res = acpi::search_for_rsdp_bios(&mut handler);
    if let Ok(acpi) = res {
        info!("ACPI is supported by this system");

        ACPI_INFO.call_once(|| {
            acpi
        });
    } else {
        info!("ACPI is not supported by this system");
    }
}