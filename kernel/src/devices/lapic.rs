//! Local APIC driver.
//!
//! Specification can be found in Intel's System Programmer's Guide. The chapters
//! used as reference here will be from [this version] of the guide.
//!
//! [this version]: https://web.archive.org/web/20190212230443/https://software.intel.com/sites/default/files/managed/a4/60/325384-sdm-vol-3abcd.pdf

use crate::frame_allocator::PhysicalMemRegion;
use crate::mem::PhysicalAddress;
use crate::paging::MappingAccessRights;
use sunrise_libutils::io::Io;
use crate::paging::PAGE_SIZE;
use crate::paging::kernel_memory::get_kernel_memory;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::fmt;
use bit_field::BitField;

/// Specifies how the APICs listed in the destination field should act upon
/// reception of this signal. Note that certain Delivery Modes only operate as
/// intended when used in conjunction with a specific trigger Mode.
#[derive(Debug, Clone, Copy)]
pub enum DeliveryMode {
    /// Delivers the interrupt specified in the vector field.
    Fixed,
    /// Delivers an SMI interrupt to the processor core through the processor’s
    /// local SMI signal path. When using this delivery mode, the vector field
    /// should be set to 0x00 for future compatibility.
    SMI,
    /// Delivers an NMI interrupt to the processor. The vector information is
    /// ignored.
    NMI,

    /// Delivers an INIT request to the processor core, which causes the
    /// processor to perform an INIT. When using this delivery mode, the vector
    /// field should be set to 0x00 for future compatibility. Not supported for
    /// the LVT CMCI register, the LVT thermal monitor register, or the LVT
    /// performance counter register.
    INIT,
    /// Causes the processor to respond to the interrupt as if the interrupt
    /// originated in an externally connected (8259A-compatible) interrupt
    /// controller. A special INTA bus cycle corresponding to ExtINT, is routed
    /// to the external controller. The external controller is expected to supply
    /// the vector information. The APIC architecture supports only one ExtINT
    /// source in a system, usually contained in the compatibility bridge. Only
    /// one processor in the system should have an LVT entry configured to use
    /// the ExtINT delivery mode. Not supported for the LVT CMCI register, the
    /// LVT thermal monitor register, or the LVT performance counter register.
    ExtINT,
    /// Unknown delivery mode encountered.
    Unknown(u32)
}

impl From<DeliveryMode> for u32 {
    fn from(mode: DeliveryMode) -> u32 {
        match mode {
            DeliveryMode::Fixed          => 0b000,
            DeliveryMode::SMI            => 0b010,
            // RESERVED                  => 0b011,
            DeliveryMode::NMI            => 0b100,
            DeliveryMode::INIT           => 0b101,
            // RESERVED                  => 0b110,
            DeliveryMode::ExtINT         => 0b111,
            DeliveryMode::Unknown(val)   => val,
        }
    }
}

impl From<u32> for DeliveryMode {
    fn from(mode: u32) -> DeliveryMode {
        match mode {
            0b000 => DeliveryMode::Fixed,
            0b010 => DeliveryMode::SMI,
            // 0b011 RESERVED
            0b100 => DeliveryMode::NMI,
            0b101 => DeliveryMode::INIT,
            // 0b110 RESERVED
            0b111 => DeliveryMode::ExtINT,
            val => DeliveryMode::Unknown(val),
        }
    }
}

/// Selects the Timer Mode of the LVT Timer.
#[derive(Debug, Clone, Copy)]
enum TimerMode {
    /// One-shot mode using a count-down value.
    OneShot,
    /// Periodic mode reloading a count-down value.
    Periodic,
    /// TSC-Deadline mode using absolute target value in IA32_TSC_DEADLINE MSR.
    TscDeadline,
    /// Reserved value, might be used in later revision.
    Reserved
}

impl From<TimerMode> for u32 {
    fn from(mode: TimerMode) -> u32 {
        match mode {
            TimerMode::OneShot     => 0b00,
            TimerMode::Periodic    => 0b01,
            TimerMode::TscDeadline => 0b10,
            TimerMode::Reserved    => 0b11,
        }
    }
}

impl From<u32> for TimerMode {
    fn from(mode: u32) -> TimerMode {
        match mode {
            0b00 => TimerMode::OneShot,
            0b01 => TimerMode::Periodic,
            0b10 => TimerMode::TscDeadline,
            0b11 => TimerMode::Reserved,
            _    => unreachable!(),
        }
    }
}

/// Local APIC Registers are 128-bit wide, with the 32 lower bits containing the
/// actual register, and the top bits being reserved for future use.
#[repr(transparent)]
#[derive(Debug)]
struct LocalApicRegister<T = u32>(u128, PhantomData<T>);

impl<T: Copy> Io for LocalApicRegister<T> {
    type Value = T;

    fn read(&self) -> Self::Value {
        unsafe { (&self.0 as *const u128 as *const T).read_volatile() }
    }

    fn write(&mut self, value: Self::Value) {
        unsafe { (&mut self.0 as *mut u128 as *mut T).write_volatile(value) }
    }
}

bitfield! {
    /// The version and associated metadata of a Local APIC are described by this
    /// struct.
    ///
    /// See chapter 10.4.8: Local APIC Version Register
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct LocalApicVersion(u32);
    impl Debug;
    /// The version numbers of the local APIC:
    ///
    /// - 00H - 0FH: 82489DX discrete APIC.
    /// - 10H - 15H: Integrated APIC.
    version, _: 7, 0;
    /// Shows the number of LVT entries minus 1.
    max_lvt_entry, _: 23, 16;
    /// Indicates whether software can inhibit the broadcast of EOI message by
    /// setting bit 12 of the Spurious Interrupt Vector Register.
    can_suppress_eoi_broadcast, _: 24;
}

bitfield! {
    /// Allows software to specify the manner in which the local interrupts are
    /// delivered to the processor core.
    ///
    /// See chapter 10.5.1: Local Vector Table
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct LocalVector(u32);
    impl Debug;
    /// Interrupt vector number.
    vector, set_vector: 7, 0;
    /// Specifies the type of interrupt to be sent to the processor. Some
    /// delivery modes will only operate as intended when used in conjunction
    /// with a specific trigger mode. See [DeliveryMode] for documentation about
    /// available modes.
    from into DeliveryMode, delivery_mode, set_delivery_mode: 10, 8;
    /// Indicates the interrupt delivery status, as follows:
    ///
    /// - `false` (Idle): There is currently no activity for this interrupt
    ///   source, or the previous in-terrupt from this source was delivered to
    ///   the processor core and accepted.
    /// - `true` (Send Pending): Indicates that an interrupt from this source has
    ///   been delivered to the pro-cessor core but has not yet been accepted.
    delivery_status, _: 12;
    /// Specifies the polarity of the corresponding interrupt pin: (`false`)
    /// active high or (`true`) active low. 
    polarity, set_polarity: 13;
    /// For fixed mode, level-triggered interrupts; this flag is set when the
    /// local APIC accepts the interrupt for servicing and is reset when an EOI
    /// command is received from the processor. The meaning of this flag is
    /// undefined for edge-triggered interrupts and other delivery modes. 
    remote_irr, _: 14;
    /// Selects the trigger mode for the local LINT0 and LINT1 pins: (`false`)
    /// edge sensitive and (`true`) level sensitive. This flag is only used when
    /// the delivery mode is Fixed. When the delivery mode is NMI, SMI, or INIT,
    /// the trigger mode is always edge sensitive. When the delivery mode is
    /// ExtINT, the trigger mode is always level sensitive. The timer and error
    /// interrupts are always treated as edge sensitive.
    ///
    /// If the local APIC is not used in conjunction with an I/O APIC and fixed
    /// delivery mode is selected; the Pentium 4, Intel Xeon, and P6 family
    /// processors will always use level-sensitive triggering, regardless if
    /// edge-sensitive triggering is selected.
    ///
    /// Software should always set the trigger mode in the LVT LINT1 register to
    /// 0 (edge sensitive). Level-sensitive interrupts are not supported for
    /// LINT1.
    trigger_mode, set_trigger_mode: 15;
    /// Interrupt mask: (`false`) enables reception of the interrupt and (`true`)
    /// inhibits reception of the interrupt. When the local APIC handles a
    /// performance-monitoring counters interrupt, it automatically sets the mask
    /// flag in the LVT performance counter register. This flag is set to true on
    /// reset. It can be cleared only by software.
    masked, set_masked: 16;
    /// Selects timer mode. See [TimerMode] for possible values.
    from into TimerMode, timer_mode, set_timer_mode: 18, 17;
}

bitfield! {
    /// See chapter 10.9: Spurious Interrupt
    #[repr(transparent)]
    #[derive(Clone, Copy)]
    pub struct SpuriousInterrupt(u32);
    impl Debug;
    /// Determines the vector number to be delivered to the processor when the
    /// local APIC generates a spurious vector.
    spurious_vector, set_spurious_vector: 7, 0;
    /// Allows software to temporarily enable (1) or disable (0) the local APIC.
    ///
    /// See Section 10.4.3, Enabling or Disabling the Local APIC.
    apic_software_enable, set_apic_software_enable: 8;
    /// Determines if focus processor checking is enabled when using the
    /// lowest-priority delivery mode. In Pentium 4 and Intel Xeon processors,
    /// this bit is reserved and should be cleared to 0.
    focus_processor_checking, _: 9;
    /// Determines whether an EOI for a level-triggered interrupt causes EOI
    /// messages to be broadcast to the I/O APICs or not. The default value for
    /// this bit is false, indicating that EOI broadcasts are performed. This bit
    /// is reserved to false if the processor does not support EOI-broadcast
    /// suppression.
    ///
    /// See chapter 10.8.5 Signaling Interrupt Servicing Completion
    suppress_eoi_broadcast, set_suppress_eoi_broadcast: 12;
}


bitflags! {
    /// Contains the set of errors the LAPIC has encountered while running.
    ///
    /// See 10.5.3: Error Handling
    struct Error: u32 {
        /// Set when the local APIC detects a checksum error for a message that
        /// it sent on the APIC bus. Used only on P6 family and Pentium
        /// processors.
        const SEND_CHECKSUM_ERROR      = 1 << 0;
        /// Set when the local APIC detects a checksum error for a message that
        /// it received on the APIC bus. Used only on P6 family and Pentium
        /// processors.
        const RECEIVE_CHECKSUM_ERROR   = 1 << 1;
        /// Set when the local APIC detects that a message it sent was not
        /// accepted by any APIC on the APIC bus. Used only on P6 family and
        /// Pentium processors.
        const SEND_ACCEPT_ERROR        = 1 << 2;
        /// Set when the local APIC detects that the message it received was not
        /// accepted by any APIC on the APIC bus, including itself. Used only on
        /// P6 family and Pentium processors
        const RECEIVE_ACCEPT_ERROR     = 1 << 3;
        /// Set when the local APIC detects an attempt to send an IPI with the
        /// lowest-priority delivery mode and the local APIC does not support the
        /// sending of such IPIs. This bit is used on some Intel Core and Intel
        /// Xeon processors. As noted in chapter 10.6.2: Determining IPI
        /// Destination, the ability of a processor to send a lowest-priority IPI
        /// is model-specific and should be avoided.
        const REDIRECTABLE_IPI         = 1 << 4;
        /// Set when the local APIC detects an illegal vector (one in the range 0
        /// to 15) in the message that it is sending. This occurs as the result
        /// of a write to the ICR (in both xAPIC and x2APIC modes) or to SELF IPI
        /// register (x2APIC mode only) with an illegal vector.
        ///
        /// If the local APIC does not support the sending of lowest-priority
        /// IPIs and software writes the ICR to send a lowest-priority IPI with
        /// an illegal vector, the local APIC sets only the "redirectable IPI"
        /// error bit. The interrupt is not processed and hence the "Send Illegal
        /// Vector" bit is not set in the ESR.
        const SEND_ILLEGAL_VECTOR      = 1 << 5;
        /// Set when the local APIC detects an illegal vector (one in the range 0
        /// to 15) in an interrupt message it receives or in an interrupt
        /// generated locally from the local vector table or via a self IPI. Such
        /// interrupts are not delivered to the processor; the local APIC will
        /// never set an IRR bit in the range 0 to 15.
        const RECEIVE_ILLEGAL_VECTOR   = 1 << 6;
        /// Set when the local APIC is in xAPIC mode and software attempts to
        /// access a register that is reserved in the processor's local-APIC
        /// register-address space; The local-APIC register-address space
        /// comprises the 4 KBytes at the physical address specified in the
        /// IA32_APIC_BASE MSR. Used only on Intel Core, Intel Atom™, Pentium 4,
        /// Intel Xeon, and P6 family processors.
        ///
        /// In x2APIC mode, software accesses the APIC registers using the RDMSR
        /// and WRMSR instructions. Use of one of these instructions to access a
        /// reserved register cause a general-protection exception. They do not
        /// set the “Illegal Register Access” bit in the ESR.
        const ILLEGAL_REGISTER_ADDRESS = 1 << 7;
    }
}

/// Local APIC Register structure.
#[repr(C)]
#[allow(clippy::missing_docs_in_private_items)]
#[allow(missing_debug_implementations)] // Implementation is on LocalApic
struct LocalApicInternal {
    reserved_000: LocalApicRegister,
    reserved_010: LocalApicRegister,

    /// Unique ID of this Local APIC. May also be used as a way to uniquely
    /// identify a CPU.
    ///
    /// On power up, system hardware assigns a unique APIC ID to each local APIC.
    /// The hardware assigned APIC ID is based on system topology and includes
    /// encoding for socket position and cluster information.
    ///
    /// See chapter 10.4.6: Local APIC ID.
    local_apic_id: LocalApicRegister,
    /// Can be used to identify the APIC version. In addition, the register
    /// specifies the number of entries in the local vector table (LVT) for a
    /// specific implementation.
    ///
    /// See chapter 10.4.8: Local APIC Version.
    local_apic_version: LocalApicRegister<LocalApicVersion>,

    reserved_040: LocalApicRegister,
    reserved_050: LocalApicRegister,
    reserved_060: LocalApicRegister,
    reserved_070: LocalApicRegister,

    /// The task priority allows software to set a priority threshold for
    /// interrupting the processor. This mechanism enables the operating system
    /// to temporarily block low priority interrupts from disturbing
    /// high-priority work that the processor is doing. The ability to block such
    /// interrupts using task priority results from the way that the TPR controls
    /// the value of the processor-priority register.
    ///
    /// See chapter 10.8.3.1: Task and Processor Priorities
    task_priority: LocalApicRegister,
    /// Priority used for lowest-priority arbitration.
    ///
    /// Only available on Nahalem CPUs.
    ///
    /// See chapter 10.6.2.4: Lowest Priority Delivery Mode.
    arbitration_priority: LocalApicRegister,
    /// The processor-priority class determines the priority threshold for
    /// interrupting the processor. The processor will deliver only those
    /// interrupts that have an interrupt-priority class higher than the
    /// processor-priority class in the PPR. If the processor-priority class is
    /// 0, the PPR does not inhibit the delivery any interrupt; if it is 15, the
    /// processor inhibits the delivery of all interrupts. (The
    /// processor-priority mechanism does not affect the delivery of interrupts
    /// with the NMI, SMI, INIT, ExtINT, INIT-deassert, and start-up delivery
    /// modes.)
    ///
    /// See chapter 10.8.3.1: Task and Processor Priorities
    processor_priority: LocalApicRegister,
    /// For all interrupts except those delivered with the NMI, SMI, INIT,
    /// ExtINT, the start-up, or INIT-Deassert delivery mode, the interrupt
    /// handler must include a write to the end-of-interrupt (EOI) register. This
    /// write must occur at the end of the handler routine, sometime before the
    /// IRET instruction. This action indicates that the servicing of the current
    /// interrupt is complete and the local APIC can issue the next interrupt
    /// from the ISR.
    ///
    /// See chapter 10.8.5: Signaling Interrupt Servicing Completion
    end_of_interrupt: LocalApicRegister,
    /// Only available on Nahalem CPUs. Undocumented...
    remote_read: LocalApicRegister,
    /// Upon receiving an interrupt that was sent using logical destination mode,
    /// a local APIC compares the Message Destination Address with the values in
    /// its Logical Destination Register and Destination Format Register to
    /// determine if it should accept and handle the interrupt request.
    ///
    /// See chapter 10.6.2.2: Logical Destination Mode
    logical_destination: LocalApicRegister,
    /// See chapter 10.6.2.2: Logical Destination Mode
    destination_format: LocalApicRegister,
    /// A special situation may occur when a processor raises its task priority
    /// to be greater than or equal to the level of the interrupt for which the
    /// processor INTR signal is currently being asserted. If at the time the
    /// INTA cycle is issued, the interrupt that was to be dispensed has become
    /// masked (programmed by software), the local APIC will deliver a
    /// spurious-interrupt vector. Dispensing the spurious-interrupt vector does
    /// not affect the ISR, so the handler for this vector should return without
    /// an EOI.
    ///
    /// See chapter 10.9: Spurious Interrupt
    spurious_interrupt_vector: LocalApicRegister<SpuriousInterrupt>,
    /// See [LocalApic::in_service()] documentation.
    in_service0: LocalApicRegister,
    /// See [LocalApic::in_service()] documentation.
    in_service1: LocalApicRegister,
    /// See [LocalApic::in_service()] documentation.
    in_service2: LocalApicRegister,
    /// See [LocalApic::in_service()] documentation.
    in_service3: LocalApicRegister,
    /// See [LocalApic::in_service()] documentation.
    in_service4: LocalApicRegister,
    /// See [LocalApic::in_service()] documentation.
    in_service5: LocalApicRegister,
    /// See [LocalApic::in_service()] documentation.
    in_service6: LocalApicRegister,
    /// See [LocalApic::in_service()] documentation.
    in_service7: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode0: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode1: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode2: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode3: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode4: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode5: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode6: LocalApicRegister,
    /// See [LocalApic::trigger_mode()] documentation.
    trigger_mode7: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request0: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request1: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request2: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request3: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request4: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request5: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request6: LocalApicRegister,
    /// See [LocalApic::interrupt_request_register()] documentation.
    interrupt_request7: LocalApicRegister,
    /// The local APIC records errors detected during interrupt handling in the
    /// error status register (ESR).
    ///
    /// See chapter 10.5.3: Error Handling.
    error_status: LocalApicRegister<Error>,

    reserved_290: LocalApicRegister,
    reserved_2a0: LocalApicRegister,
    reserved_2b0: LocalApicRegister,
    reserved_2c0: LocalApicRegister,
    reserved_2d0: LocalApicRegister,
    reserved_2e0: LocalApicRegister,

    /// Specifies interrupt delivery when an overflow condition of corrected
    /// machine check error count reaching a threshold value occurred in a
    /// machine check bank supporting CMCI.
    ///
    /// See Section 10.5.1, "Local Vector Table".
    lvt_corrected_machine_interrupt: LocalApicRegister<LocalVector>,
    /// See [LocalApic::send_interrupt_command()] documentation.
    interrupt_command_register0: LocalApicRegister,
    /// See [LocalApic::send_interrupt_command()] documentation.
    interrupt_command_register1: LocalApicRegister,
    /// Specifies interrupt delivery when the APIC timer signals an interrupt.
    ///
    /// See Section 10.5.1, "Local Vector Table".
    lvt_timer: LocalApicRegister<LocalVector>,
    /// Specifies interrupt delivery when the thermal sensor generates an
    /// interrupt.
    ///
    /// See Section 10.5.1, "Local Vector Table".
    lvt_thermal_sensor: LocalApicRegister<LocalVector>,
    /// Specifies interrupt delivery when a performance counter generates an
    /// interrupt on overflow
    ///
    /// See Section 10.5.1, "Local Vector Table".
    lvt_performance_monitoring_counter: LocalApicRegister<LocalVector>,
    /// Specifies interrupt delivery when an interrupt is signaled at the LINT0.
    ///
    /// See Section 10.5.1, "Local Vector Table".
    lvt_lint0: LocalApicRegister<LocalVector>,
    /// Specifies interrupt delivery when an interrupt is signaled at the LINT1.
    ///
    /// See Section 10.5.1, "Local Vector Table".
    lvt_lint1: LocalApicRegister<LocalVector>,
    /// Specifies interrupt delivery when the APIC detects an internal error.
    ///
    /// See Section 10.5.1, "Local Vector Table".
    lvt_error: LocalApicRegister<LocalVector>,
    /// Initial count used by the APIC Timer.
    ///
    /// See Section 10.5.4: APIC Timer.
    initial_count: LocalApicRegister,
    /// Current count used by the APIC Timer.
    ///
    /// See Section 10.5.4: APIC Timer.
    current_count: LocalApicRegister,

    reserved_3a0: LocalApicRegister,
    reserved_3b0: LocalApicRegister,
    reserved_3c0: LocalApicRegister,
    reserved_3d0: LocalApicRegister,

    /// Divide configuration used by the APIC timer.
    ///
    /// See Section 10.5.4: APIC Timer.
    divide_configuration: LocalApicRegister,

    reserved_3f0: LocalApicRegister,
}
assert_eq_size!(LocalApicInternal, [u8; 0x400]);

// LocalApic should be cpu_local.
/// LocalApic driver.
pub struct LocalApic {
    /// Pointer to the LocalApic registers.
    internal: &'static UnsafeCell<LocalApicInternal>,
}

impl fmt::Debug for LocalApic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            f.debug_struct("LocalApic")
                .field("local_apic_id", &(*self.internal.get()).local_apic_id.read())
                .field("local_apic_version", &(*self.internal.get()).local_apic_version.read())
                .field("task_priority", &(*self.internal.get()).task_priority.read())
                .field("arbitration_priority", &(*self.internal.get()).arbitration_priority.read())
                .field("processor_priority", &(*self.internal.get()).processor_priority.read())
                .field("end_of_interrupt", &(*self.internal.get()).end_of_interrupt.read())
                .field("remote_read", &(*self.internal.get()).remote_read.read())
                .field("logical_destination", &(*self.internal.get()).logical_destination.read())
                .field("destination_format", &(*self.internal.get()).destination_format.read())
                .field("spurious_interrupt_vector", &(*self.internal.get()).spurious_interrupt_vector.read())
                .field("in_service", &self.in_service())
                .field("trigger_mode", &self.trigger_mode())
                .field("interrupt_request_register", &self.interrupt_request_register())
                .field("error_status", &(*self.internal.get()).error_status.read())
                .field("lvt_corrected_machine_interrupt", &(*self.internal.get()).lvt_corrected_machine_interrupt.read())
                //.field("interrupt_command_register", &self.interrupt_command_register())
                .field("lvt_timer", &(*self.internal.get()).lvt_timer.read())
                .field("lvt_thermal_sensor", &(*self.internal.get()).lvt_thermal_sensor.read())
                .field("lvt_performance_monitoring_counter", &(*self.internal.get()).lvt_performance_monitoring_counter.read())
                .field("lvt_lint0", &(*self.internal.get()).lvt_lint0.read())
                .field("lvt_lint1", &(*self.internal.get()).lvt_lint1.read())
                .field("lvt_error", &(*self.internal.get()).lvt_error.read())
                .field("initial_count", &(*self.internal.get()).initial_count.read())
                .field("current_count", &(*self.internal.get()).current_count.read())
                .field("divide_configuration", &(*self.internal.get()).divide_configuration.read())
                .finish()
        }
    }
}

// TODO: LocalAPIC should not be Send/Sync.
// BODY: LocalApic should be stored in a cpu_local, removing the need for Send/
// BODY: Sync bounds. Problem is, we don't really have a way to create CPU Locals
// BODY: yet.
unsafe impl Send for LocalApic {}
unsafe impl Sync for LocalApic {}

impl LocalApic {
    /// Create a new LocalApic at the specified address.
    ///
    /// # Panics
    ///
    /// Panics if address is not page-aligned.
    ///
    /// # Safety
    ///
    /// `address` should be the physical address of a LocalApic device, and
    /// should not be shared.
    pub unsafe fn new(address: PhysicalAddress) -> Self {
        assert!(address.addr() % PAGE_SIZE == 0, "Unaligned local APIC address");

        let lapic = get_kernel_memory().map_phys_region(PhysicalMemRegion::on_fixed_mmio(address, 0x1000).unwrap(), MappingAccessRights::k_rw());

        let lapic = LocalApic {
            internal: (lapic.addr() as *const UnsafeCell<LocalApicInternal>).as_ref().unwrap(),
        };

        // Mask all the interrupt vectors.
        let mut masked_vector = LocalVector(0);
        masked_vector.set_masked(true);
        (*lapic.internal.get()).lvt_corrected_machine_interrupt.write(masked_vector);
        (*lapic.internal.get()).lvt_thermal_sensor.write(masked_vector);
        (*lapic.internal.get()).lvt_performance_monitoring_counter.write(masked_vector);
        (*lapic.internal.get()).lvt_lint0.write(masked_vector);
        (*lapic.internal.get()).lvt_lint1.write(masked_vector);
        (*lapic.internal.get()).lvt_error.write(masked_vector);

        lapic
    }

    /// 10.4.3 Enabling or Disabling the Local APIC
    ///
    /// The local APIC can be enabled or disabled in either of two ways:
    ///
    /// - Using the APIC global enable/disable flag in the IA32_APIC_BASE MSR (MSR address 1BH; see Figure 10-5)
    /// - Using the APIC software enable/disable flag in the spurious-interrupt vector register (see Figure 10-23)
    pub fn enable(&self) {
        // Enable the LAPIC. The MSR should be set by the BIOS, so we're only
        // going to set the spurious-interrupt vector register.
        unsafe {
            let mut val = (*self.internal.get()).spurious_interrupt_vector.read();
            val.set_apic_software_enable(true);
            (*self.internal.get()).spurious_interrupt_vector.write(val);
        }
    }

    /// Acknowledge the last interrupt, signaling an end of interrupt.
    ///
    /// See chapter 10.8: Handling Interrupts
    pub fn acknowledge(&self) {
        unsafe { (*self.internal.get()).end_of_interrupt.write(0); }
    }

    /// Unique ID of this Local APIC. May also be used as a way to uniquely
    /// identify a CPU.
    pub fn local_apic_id(&self) -> u32 {
        unsafe { (*self.internal.get()).local_apic_id.read() }
    }

    // Sucks that we don't have an u256 :').
    /// The ISR contains interrupt requests that have been dispatched to the
    /// processor for servicing, but not yet acknowledged by said processor.
    ///
    /// See chapter 10.8.4: Interrupt Acceptance for Fixed Interrupts.
    pub fn in_service(&self) -> [u32; 8] {
        unsafe {
            let in_service0 = (*self.internal.get()).in_service0.read();
            let in_service1 = (*self.internal.get()).in_service1.read();
            let in_service2 = (*self.internal.get()).in_service2.read();
            let in_service3 = (*self.internal.get()).in_service3.read();
            let in_service4 = (*self.internal.get()).in_service4.read();
            let in_service5 = (*self.internal.get()).in_service5.read();
            let in_service6 = (*self.internal.get()).in_service6.read();
            let in_service7 = (*self.internal.get()).in_service7.read();

            [
                in_service0,
                in_service1,
                in_service2,
                in_service3,
                in_service4,
                in_service5,
                in_service6,
                in_service7
            ]
        }
    }

    /// The trigger mode register (TMR) indicates the trigger mode of the
    /// interrupt. Upon acceptance of an interrupt into the IRR, the
    /// corresponding TMR bit is cleared for edge-triggered interrupts and set
    /// for level-triggered interrupts. If a TMR bit is set when an EOI cycle for
    /// its corresponding interrupt vector is generated, an EOI message is sent
    /// to all I/O APICs.
    ///
    /// See chapter 10.8.4: Interrupt Acceptance for Fixed Interrupts.
    pub fn trigger_mode(&self) -> [u32; 8] {
        unsafe {
            let trigger_mode0 = (*self.internal.get()).trigger_mode0.read();
            let trigger_mode1 = (*self.internal.get()).trigger_mode1.read();
            let trigger_mode2 = (*self.internal.get()).trigger_mode2.read();
            let trigger_mode3 = (*self.internal.get()).trigger_mode3.read();
            let trigger_mode4 = (*self.internal.get()).trigger_mode4.read();
            let trigger_mode5 = (*self.internal.get()).trigger_mode5.read();
            let trigger_mode6 = (*self.internal.get()).trigger_mode6.read();
            let trigger_mode7 = (*self.internal.get()).trigger_mode7.read();

            [
                trigger_mode0,
                trigger_mode1,
                trigger_mode2,
                trigger_mode3,
                trigger_mode4,
                trigger_mode5,
                trigger_mode6,
                trigger_mode7
            ]
        }
    }

    /// The IRR contains the active interrupt requests that have been accepted,
    /// but not yet dispatched to the processor for servicing.
    ///
    /// See chapter 10.8.4: Interrupt Acceptance for Fixed Interrupts.
    pub fn interrupt_request_register(&self) -> [u32; 8] {
        unsafe {
            let interrupt_request0 = (*self.internal.get()).interrupt_request0.read();
            let interrupt_request1 = (*self.internal.get()).interrupt_request1.read();
            let interrupt_request2 = (*self.internal.get()).interrupt_request2.read();
            let interrupt_request3 = (*self.internal.get()).interrupt_request3.read();
            let interrupt_request4 = (*self.internal.get()).interrupt_request4.read();
            let interrupt_request5 = (*self.internal.get()).interrupt_request5.read();
            let interrupt_request6 = (*self.internal.get()).interrupt_request6.read();
            let interrupt_request7 = (*self.internal.get()).interrupt_request7.read();

            [
                interrupt_request0,
                interrupt_request1,
                interrupt_request2,
                interrupt_request3,
                interrupt_request4,
                interrupt_request5,
                interrupt_request6,
                interrupt_request7
            ]
        }
    }

    /// Sends an IPI.
    ///
    /// See 10.6 Issuing Interprocessor Interrupts
    pub fn send_interrupt_command(&mut self, val: u64) {
        // First write the top bits, since writing to the low bits triggers the
        // IPI.
        unsafe {
            (*self.internal.get()).interrupt_command_register1.write(val.get_bits(32..64) as u32);
            (*self.internal.get()).interrupt_command_register0.write(val.get_bits(0..32) as u32);
        }
    }
}
