//! HPET driver implementation.
use static_assertions::assert_eq_size;
use sunrise_libutils::io::{Io, Mmio};
use crate::mem::PhysicalAddress;
use crate::paging;
use crate::paging::PAGE_SIZE;
use crate::paging::MappingAccessRights;
use crate::frame_allocator::PhysicalMemRegion;

use core::fmt;
use core::fmt::Debug;
use core::fmt::Formatter;

bitfield!{
    /// Represent the lower part of the General Capabilities and ID Register.
    #[derive(Clone, Copy, Debug)]
    pub struct HpetIdRegister(u32);
    /// Indicates which revision of the function is implemented; must not be 0. 
    pub revision_id, _ : 7, 0;
    /// The amount of timers - 1.
    pub timer_count_minus_one, _ : 12, 8;

    /// If this bit is 1, HPET main counter is capable of operating in 64 bit mode. 
    pub counter_size_capability, _: 13;

    /// If this bit is 1, HPET is capable of using "legacy replacement" mapping.
    pub legacy_rt_capability, _: 15;

    /// Represent the HPET vendor id (most likely PCI vendor id?)
    pub vendor_id, _: 31, 16;
}

bitfield! {
    /// Represent the General Configuration Register.
    #[derive(Clone, Copy, Debug)]
    pub struct HpetGeneralConfigurationRegister(u64);
    /// Control "legacy replacement" mapping activation state.
    pub legacy_rt_config, set_legacy_rt_config: 1, 0;
    /// Control HPET activation (control main timer activation state and timer interrupts activation).
    pub enable_config, set_enable_config: 2, 1;
}


#[allow(clippy::missing_docs_in_private_items)]
#[repr(packed)]
/// Representation of HPET non variable registers.
pub struct HpetRegister {
    /// Information about the HPET model.
    pub identifier: Mmio<HpetIdRegister>,
    /// Main counter tick period in femtoseconds (10^-15 seconds).
    /// Must not be zero, must be less or equal to 0x05F5E100, or 100 nanoseconds.
    pub period: Mmio<u32>,
    _reserved0: u64,
    /// General Configuration Register.
    pub general_configuration: Mmio<HpetGeneralConfigurationRegister>,
    _reserved1: u64,
    /// General Interrupt Status Register.
    pub general_interrupt_status: Mmio<u32>,
    _reserved3: [u8; 0xCC],
    /// main counter value.
    pub main_counter_value: Mmio<u64>,
    _reserved4: u64,
}

impl Debug for HpetRegister {
    /// Debug does not access reserved registers.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("HpetRegister")
            .field("identifier", &self.identifier)
            .field("period", &self.period)
            .field("general_configuration", &self.general_configuration)
            .field("general_interrupt_status", &self.general_interrupt_status)
            .field("main_counter_value", &self.main_counter_value)
            .finish()
    }
}

#[derive(Debug)]
/// Represent an HPET device.
pub struct Hpet {
    /// The mmio address of this HPET device.
    inner: *mut HpetRegister,

    /// The count of timer of this HPET device.
    timer_count: u32
    
}

impl Hpet {
    /// Create a new HPET device instance from MMIO registers.
    fn new(inner: *mut HpetRegister) -> Self {
        let mut res = Hpet { inner, timer_count: 1 };
        res.timer_count = unsafe { (*res.inner).identifier.read().timer_count_minus_one() } + 1;

        res
    }

    /// Return true if the device supports "legacy mapping".
    pub fn has_legacy_mapping(&self) -> bool {
        unsafe { (*self.inner).identifier.read().legacy_rt_capability() }
    }

    /// Enable the "legacy mapping".
    pub fn enable_legacy_mapping(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_legacy_rt_config(1);
        unsafe { (*self.inner).general_configuration.write(general_configuration) }
    }

    /// Disable the "legacy mapping".
    pub fn disable_legacy_mapping(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_legacy_rt_config(0);
        unsafe { (*self.inner).general_configuration.write(general_configuration) }
    }

    /// Check "legacy mapping" status.
    pub fn is_legacy_mapping_enabled(&self) -> bool {
        let general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.legacy_rt_config() == 1
    }

    /// Enable HPET (main timer running, and timer interrupts allowed).
    pub fn enable(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_enable_config(1);
        unsafe { (*self.inner).general_configuration.write(general_configuration) }
    }

    /// Disable HPET (main timer halted, and timer interrupts disabled).
    pub fn disable(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_enable_config(0);
        unsafe { (*self.inner).general_configuration.write(general_configuration) }
    }

    /// Check HPET status.
    pub fn is_enabled(&self) -> bool {
        let general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.enable_config() == 1
    }
}

assert_eq_size!(HpetRegister, [u8; 0x100]);

/// The instance of the HPET device we are using.
static mut HPET_INSTANCE: Option<Hpet> = None;

/// Try to initialize the HPET in legacy mode.
/// TODO: switch HPET to normal mode when IO-APIC will be implemented.
pub unsafe fn init(hpet: &acpi::Hpet) -> bool {
    let physical_mem = PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(hpet.base_address.address as usize), PAGE_SIZE).unwrap();
    let virtual_address = paging::kernel_memory::get_kernel_memory().map_phys_region(physical_mem, MappingAccessRights::READABLE | MappingAccessRights::WRITABLE);
    let hpet_mmio = virtual_address.addr() as *mut HpetRegister;
    let hpet_instance = Hpet::new(hpet_mmio);

    // First disable the hpet if it's running.
    if hpet_instance.is_enabled() {
        hpet_instance.disable();
    }

    // We don't need the HPET has it's useless for us.
    if !hpet_instance.has_legacy_mapping() {
        paging::kernel_memory::get_kernel_memory().unmap(virtual_address, PAGE_SIZE);
        return false;
    }

    // TODO: enable main timer

    hpet_instance.enable_legacy_mapping();
    hpet_instance.enable();
    HPET_INSTANCE = Some(hpet_instance);
    true
}