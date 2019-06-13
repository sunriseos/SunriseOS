//! HPET driver implementation.
//!
//! HPET documentation: https://web.archive.org/web/20190411220000/https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/software-developers-hpet-spec-1-0a.pdf
use crate::frame_allocator::PhysicalMemRegion;
use crate::mem::PhysicalAddress;
use crate::paging;
use crate::paging::MappingAccessRights;
use crate::paging::PAGE_SIZE;
use static_assertions::assert_eq_size;
use sunrise_libutils::io::{Io, Mmio};

use core::fmt;
use core::fmt::Debug;
use core::fmt::Formatter;

use crate::timer;

bitfield! {
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
    pub struct HpetGeneralConfigurationRegister(u32);
    /// Control HPET activation (control main timer activation state and timer interrupts activation).
    pub enable_config, set_enable_config: 0;
    /// Control "legacy replacement" mapping activation state.
    pub legacy_rt_config, set_legacy_rt_config: 1;
}

bitfield! {
    /// Represent a Timer Configuration Register.
    #[derive(Clone, Copy, Debug)]
    pub struct HpetTimerConfigurationRegister(u32);
    /// Control Timer Interrupt Type: 0 = Edge Trigger, 1 = Level Trigger
    pub interrupt_type, set_interrupt_type: 1;
    /// Control Timer Interrupt.
    pub interrupt_enable, set_interrupt_enable: 2;
    /// Control Timer Type: 0 = One Shot, 1 = Periodic
    pub timer_type, set_timer_type: 3;

    /// true if this timer is capable of periodic timer.
    pub periodic_interrupt_capability, _: 4;

    /// If this bit is 1, this timer is capable of operating in 64 bit mode.
    pub size_capability, _: 5;

    /// Set to 1 to allow software to write the accumulator data.
    ///
    /// # Note
    ///
    /// This auto-clear.
    pub accumulator_config, set_accumulator_config: 6;

    /// Set to 1 to force a 64 bit timer to operate as 32 bit one
    ///
    /// # Note
    ///
    /// This as no effect on a 32 bit timer.
    pub is_32bit_mode, set_32bit_mode: 8;

    /// Timer Interrupt Route: This indicate the routing in the I/O APIC
    ///
    /// # Note
    ///
    /// If the LegacyReplacement Route bit is set, then Timers 0 and 1 will have a different routing, and this bit field has no effect for those two timers.
    ///
    /// If the Timer FSB Interrupt bit is set, then the interrupt will be delivered directly to the FSB, and this bit field has no effect.
    pub interrupt_route, set_interrupt_route: 13, 9;

    /// Timer FSB Interrupt: force the interrupts to be delivered directly as FSB messages, rather than using the I/O APIC.
    pub fsb_interrupt, set_fsb_interrupt: 14;

    /// Timer FSB Interrupt Delivery capability.
    pub fsb_interrupt_capability, _: 15;
}

#[allow(clippy::missing_docs_in_private_items)]
#[repr(packed)]
/// Representation of HPET non variable registers.
pub struct HpetRegister {
    /// Information about the HPET model.
    pub identifier: Mmio<HpetIdRegister>, // 0x0
    /// Main counter tick period in femtoseconds (10^-15 seconds).
    /// Must not be zero, must be less or equal to 0x05F5E100, or 100 nanoseconds.
    pub period: Mmio<u32>, // 0x4
    _reserved0: u64, // 0x8
    /// General Configuration Register.
    pub general_configuration: Mmio<HpetGeneralConfigurationRegister>, // 0x10
    _reserved1: u32, // 0x14
    _reserved2: u64, // 0x18
    /// General Interrupt Status Register.
    pub general_interrupt_status: Mmio<u32>, // 0x20
    _reserved3: [u8; 0xCC], // 0x24
    /// main counter value.
    pub main_counter_value: Mmio<u64>, // 0xF0
    _reserved4: u64, // 0xF8
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
/// Representation of an HPET timer registers.
pub struct HpetTimerRegister {
    /// The configuration and capabilities register of this timer.
    pub config: Mmio<HpetTimerConfigurationRegister>,
    /// Routing capability (IRQ0 to IRQ31 on the I/O APIC).
    pub interrupt_route_capability: Mmio<u32>,
    /// The comparator value register low part.
    pub comparator_value_low: Mmio<u32>,
    /// The comparator value register high part.
    pub comparator_value_high: Mmio<u32>,
    /// The FSB Interrupt Route register lower part (value during FSB interrupt message).
    pub fsb_value: Mmio<u32>,
    /// The FSB Interrupt Route register higher part (address used during FSB interrupt message).
    pub fsb_address: Mmio<u32>,
}

#[derive(Debug)]
/// Represent an HPET device.
pub struct Hpet {
    /// The mmio address of this HPET device.
    pub inner: *mut HpetRegister,

    /// Cached value of ``Hpet::period``.
    period: u32,

    /// The count of timer of this HPET device.
    timer_count: u32,
}

#[derive(Debug)]
/// Represent an HPET timer.
pub struct HpetTimer {
    /// The mmio address of this HPET timer.
    inner: *mut HpetTimerRegister,

    /// Cached value of ``HpetTimerConfigurationRegister::size_capability``.
    support_64bit: bool,

    /// Cached value of ``HpetTimerConfigurationRegister::periodic_interrupt_capability``.
    support_periodic_interrupt: bool,

    /// Cached value of ``HpetTimerConfigurationRegister::fsb_interrupt_capability``.
    support_fsb_interrupt: bool,

    /// Cached value of ``HpetTimerRegister::interrupt_route_capability``.
    interrupt_route_capability: u32,
}

impl HpetTimer {
    /// This is the maximum IRQ lines supported by the HPET.
    const MAX_IRQ: u32 = 0x1F;

    /// Create a new HPET timer instance from MMIO registers.
    fn new(inner: *mut HpetTimerRegister) -> Self {
        let mut res = HpetTimer {
            inner,
            support_64bit: false,
            support_periodic_interrupt: false,
            support_fsb_interrupt: false,
            interrupt_route_capability: 0,
        };

        let config = unsafe { (*inner).config.read() };

        res.support_64bit = config.size_capability();
        res.support_periodic_interrupt = config.periodic_interrupt_capability();
        res.support_fsb_interrupt = config.fsb_interrupt_capability();
        res.interrupt_route_capability = unsafe { (*inner).interrupt_route_capability.read() };
        res
    }

    /// Return true if this timer is a 64 bits timer.
    pub fn support_64bit(&self) -> bool {
        self.support_64bit
    }

    /// Return true if this timer supports periodic interrupt.
    pub fn support_periodic_interrupt(&self) -> bool {
        self.support_periodic_interrupt
    }

    /// Return true if this timer supports fsb interrupt.
    pub fn support_fsb_interrupt(&self) -> bool {
        self.support_fsb_interrupt
    }

    /// Return true if the timer support routing to the given IRQ.
    pub fn support_interrupt_routing(&self, index: u32) -> bool {
        if index > Self::MAX_IRQ {
            return false;
        }

        let irq_mask = 1 << index;
        (self.interrupt_route_capability & irq_mask) == irq_mask
    }

    /// Set the routing for the interrupt to the I/O APIC.
    ///
    /// # Panics
    ///
    /// Panics if the given interrupt route is not supported by this hpet timer.
    pub fn set_interrupt_route(&self, index: u32) {
        assert!(self.support_interrupt_routing(index), "Illegal interrupt route.");
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_interrupt_route(index);
        unsafe { (*self.inner).config.write(config); }

        let config = unsafe { (*self.inner).config.read() };
        assert!(config.interrupt_route() == index, "Illegal interrupt route.");
    }

    /// Set the timer comparactor value
    pub fn set_comparator_value(&self, value: u64) {
        unsafe {
            (*self.inner)
                .comparator_value_low
                .write((value & 0xFFFF_FFFF) as u32)
        };
        unsafe {
            (*self.inner)
                .comparator_value_high
                .write((value >> 32) as u32)
        };
    }

    /// Set the timer accumulator value.
    ///
    /// # Note
    ///
    /// The timer MUST be in periodic mode.
    pub fn set_accumulator_value(&self, value: u64) {
        // We update the accumulator register two times.
        // TODO: Test the hardware behaviour on partial write of the HPET accumulator
        // BODY: Because we are running on i386, this cause issue on QEMU.
        // BODY: In fact, QEMU clear the accumulator flag on every partial write.
        // BODY: The question here is: Is that normal or a bug in QEMU?
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_accumulator_config(true);
        unsafe { (*self.inner).config.write(config) };
        unsafe {
            (*self.inner)
                .comparator_value_low
                .write((value & 0xFFFF_FFFF) as u32)
        };

        let mut config = unsafe { (*self.inner).config.read() };
        config.set_accumulator_config(true);
        unsafe { (*self.inner).config.write(config) };
        unsafe {
            (*self.inner)
                .comparator_value_high
                .write((value >> 32) as u32)
        };
    }

    /// Set Edge Trigger.
    pub fn set_edge_trigger(&self) {
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_interrupt_type(false);
        unsafe { (*self.inner).config.write(config) };
    }

    /// Set Level Trigger.
    pub fn set_level_trigger(&self) {
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_interrupt_type(true);
        unsafe { (*self.inner).config.write(config) };
    }

    /// Set the timer in One Shot mode.
    pub fn set_one_shot_mode(&self) {
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_timer_type(false);
        unsafe { (*self.inner).config.write(config) };
    }

    /// Set the timer in Periodic mode.
    ///
    /// # Note
    ///
    /// The timer must support periodic mode.
    pub fn set_periodic_mode(&self) {
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_timer_type(true);
        unsafe { (*self.inner).config.write(config) };
    }

    /// Enable interrupt.
    pub fn enable_interrupt(&self) {
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_interrupt_enable(true);
        unsafe { (*self.inner).config.write(config) };
    }

    /// Disable interrupt.
    pub fn disable_interrupt(&self) {
        let mut config = unsafe { (*self.inner).config.read() };
        config.set_interrupt_enable(false);
        unsafe { (*self.inner).config.write(config) };
    }

    /// Determine if the interrupt is enabled.
    pub fn has_interrupt_enabled(&self) -> bool {
        unsafe { (*self.inner).config.read().interrupt_enable() }
    }
}

impl Hpet {
    /// Create a new HPET device instance from MMIO registers.
    fn new(inner: *mut HpetRegister) -> Self {
        debug!("Creating new HPET with registers at {:p}", inner);
        let mut res = Hpet {
            inner,
            timer_count: 1,
            period: 0,
        };
        res.timer_count = unsafe { (*res.inner).identifier.read().timer_count_minus_one() } + 1;
        res.period = unsafe { (*res.inner).period.read() };

        res
    }

    /// Return true if the device supports "legacy mapping".
    pub fn has_legacy_mapping(&self) -> bool {
        unsafe { (*self.inner).identifier.read().legacy_rt_capability() }
    }

    /// Return the period of the HPET device.
    pub fn get_period(&self) -> u32 {
        self.period
    }

    /// Return the frequency of the HPET device.
    pub fn get_frequency(&self) -> u64 {
        1000000000000000 / u64::from(self.get_period())
    }

    /// Enable the "legacy mapping".
    pub fn enable_legacy_mapping(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_legacy_rt_config(true);
        unsafe {
            (*self.inner)
                .general_configuration
                .write(general_configuration)
        }
    }

    /// Disable the "legacy mapping".
    pub fn disable_legacy_mapping(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_legacy_rt_config(false);
        unsafe {
            (*self.inner)
                .general_configuration
                .write(general_configuration)
        }
    }

    /// Check "legacy mapping" status.
    pub fn is_legacy_mapping_enabled(&self) -> bool {
        let general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.legacy_rt_config()
    }

    /// Enable HPET (main timer running, and timer interrupts allowed).
    pub fn enable(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_enable_config(true);
        unsafe {
            (*self.inner)
                .general_configuration
                .write(general_configuration)
        }
    }

    /// Set HPET main counter value.
    pub fn set_main_counter_value(&self, value: u64) {
        unsafe {
            (*self.inner)
                .main_counter_value
                .write(value)
        }
    }

    /// Get HPET main counter value.
    pub fn get_main_counter_value(&self) -> u64 {
        unsafe { (*self.inner).main_counter_value.read() }
    }

    /// Disable HPET (main timer halted, and timer interrupts disabled).
    pub fn disable(&self) {
        let mut general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.set_enable_config(false);
        unsafe {
            (*self.inner)
                .general_configuration
                .write(general_configuration)
        }
    }

    /// Check HPET status.
    pub fn is_enabled(&self) -> bool {
        let general_configuration = unsafe { (*self.inner).general_configuration.read() };
        general_configuration.enable_config()
    }

    /// Get a timer at the given index.
    pub fn get_timer(&self, index: u32) -> Option<HpetTimer> {
        if index >= self.timer_count {
            return None;
        }
        let mmio_base_address = self.inner as usize;

        let timer_address = mmio_base_address + 0x100 + (0x20 * index) as usize;
        Some(HpetTimer::new(timer_address as *mut HpetTimerRegister))
    }
}

assert_eq_size!(HpetRegister, [u8; 0x100]);

/// The instance of the HPET device we are using.
static mut HPET_INSTANCE: Option<Hpet> = None;

/// Try to initialize the HPET in legacy mode.
pub unsafe fn init(hpet: &acpi::Hpet) -> bool {
    let physical_mem = PhysicalMemRegion::on_fixed_mmio(
        PhysicalAddress(hpet.base_address.address as usize),
        PAGE_SIZE,
    )
    .unwrap();
    let virtual_address = paging::kernel_memory::get_kernel_memory().map_phys_region(
        physical_mem,
        MappingAccessRights::READABLE | MappingAccessRights::WRITABLE,
    );
    let hpet_mmio = virtual_address.addr() as *mut HpetRegister;
    let hpet_instance = Hpet::new(hpet_mmio);

    // First disable the hpet if it's running.
    if hpet_instance.is_enabled() {
        hpet_instance.disable();
        hpet_instance.set_main_counter_value(0);
    }

    // We don't need the HPET has it's useless for us.
    if !hpet_instance.has_legacy_mapping() {
        paging::kernel_memory::get_kernel_memory().unmap(virtual_address, PAGE_SIZE);
        return false;
    }

    let main_timer_opt = hpet_instance.get_timer(0);

    if main_timer_opt.is_none() {
        paging::kernel_memory::get_kernel_memory().unmap(virtual_address, PAGE_SIZE);
        return false;
    }

    let main_timer = main_timer_opt.unwrap();

    // The timer must support periodic interrupt otherwise we cannot use it!
    if !main_timer.support_periodic_interrupt() {
        paging::kernel_memory::get_kernel_memory().unmap(virtual_address, PAGE_SIZE);
        return false;
    }

    // Set the tick rate in femtoseconds
    // Kernel needs an update frequency of 1 milliseconds.
    // TODO: Switch to a lower update frequency in HPET
    // BODY: We will maybe prefer to have a better resolution for kernel time.
    // BODY: For that to be possible, we need to take care of the sleep_thread logic in userland first (sleep_thread(0) shouldn't be used).

    let irq_period_ns = 1 * 1_000_000;
    let irq_period_fs = irq_period_ns * 1_000_000;
    info!("HPET frequency: {} Hz", hpet_instance.get_frequency());
    info!("HPET IRQ period: {} fs", irq_period_fs);

    let irq_period_tick = irq_period_fs / u64::from(hpet_instance.get_period());

    // IO-APIC expects edge triggering by default.
    main_timer.set_edge_trigger();
    main_timer.set_periodic_mode();
    main_timer.enable_interrupt();
    main_timer.set_accumulator_value(irq_period_tick);
    main_timer.set_comparator_value(irq_period_tick);
    // Route the timer to the IRQ 2.
    // TODO: Report that IOAPIC IRQ0 is broken under qemu.
    // BODY: Ideally, we'd use IRQ0 for the timer, in order to match what we have
    // BODY: with the PIC. Unfortunately, qemu [unconditionally redirects irqs on
    // BODY: pin0 to pin2](https://github.com/qemu/qemu/blob/37560c259d7a0d6aceb96e9d6903ee002f4e5e0c/hw/intc/ioapic.c#L152).
    // BODY:
    // BODY: We should report this upstream bug, and move back to IRQ0 once it is
    // BODY: fixed.
    main_timer.set_interrupt_route(2);

    // Clear the interrupt state
    hpet_instance.enable();

    timer::set_kernel_timer_info(2, hpet_instance.get_frequency(), irq_period_ns);

    HPET_INSTANCE = Some(hpet_instance);
    true
}
