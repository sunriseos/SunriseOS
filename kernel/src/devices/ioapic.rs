//! 82093AA I/O Advanced Programmable Interrupt Controller (IOAPIC) driver
//!
//! The IO-APIC is used to dispatch external device and inter-process
//! interruptions to the correct CPU.
//!
//! The documentation for the IO-APIC can be found [here](http://web.archive.org/web/20161130153145/http://download.intel.com/design/chipsets/datashts/29056601.pdf).

use sunrise_libutils::io::Mmio;
use sunrise_libutils::io::Io;
use bit_field::BitField;

use bitfield::bitfield;
use crate::frame_allocator::PhysicalMemRegion;
use crate::mem::PhysicalAddress;
use crate::paging::MappingAccessRights;
use crate::paging::kernel_memory::get_kernel_memory;
use core::cell::UnsafeCell;
use core::fmt;

/// Internal IO-APIC registers.
///
/// IO-APIC uses a pair of addr/data registers. The address point to DWORDs
/// instead of bytes, meaning address 1 points to byte address 4.
#[repr(C)]
#[derive(Debug)]
struct IoApicInternal {
    /// Address register.
    addr_reg: Mmio<u32>,
    /// 12 bytes of padding.
    padding: [u8; 0x10-4],
    /// Data register.
    data_reg: Mmio<u32>,
}

/// See [module level documentation](crate::devices::ioapic)
pub struct IoApic {
    /// Pointer to the IO-APIC device registers.
    internal: &'static UnsafeCell<IoApicInternal>,
    /// Start of the IRQ range handled by this IO-APIC device. Systems may have
    /// more than one IO-APIC if they need to handle more than 24 IRQs.
    interrupt_base: u32,
    /// Number of entries this IO-APIC device can handled. Cached.
    redirection_entry_count: u32,
}

/// Specifies how the APICs listed in the destination field should act upon
/// reception of this signal. Note that certain Delivery Modes only operate as
/// intended when used in conjunction with a specific trigger Mode.
#[derive(Debug, Clone, Copy)]
pub enum DeliveryMode {
    /// Deliver the signal on the INTR signal of all processor cores listed in
    /// the destination. Trigger Mode for "fixed" Delivery Mode can be edge or
    /// level.
    Fixed,
    /// Deliver the signal on the INTR signal of the processor core that is
    /// executing at the lowest priority among all the processors listed in the
    /// specified destination. Trigger Mode for "lowest priority". Delivery Mode
    /// can be edge or level.
    LowestPriority,
    /// System Management Interrupt. A delivery mode equal to SMI requires an
    /// edge trigger mode. The vector information is ignored but must be
    /// programmed to all zeroes for future compatibility.
    SMI,
    /// Deliver the signal on the NMI signal of all processor cores listed in the
    /// destination. Vector information is ignored. NMI is treated as an edge
    /// triggered interrupt, even if it is programmed as a level triggered
    /// interrupt. For proper operation, this redirection table entry must be
    /// programmed to "edge" triggered interrupt.
    NMI,
    /// Deliver the signal to all processor cores listed in the destination by
    /// asserting the INIT signal. All addressed local APICs will assume their
    /// INIT state. INIT is always treated as an edge triggered interrupt, even
    /// if programmed otherwise. For proper operation, this redirection table
    /// entry must be programmed to "edge" triggered interrupt.
    INIT,
    /// Deliver the signal to the INTR signal of all processor cores listed in
    /// the destination as an interrupt that originated in an externally
    /// connected (8259A-compatible) interrupt controller. The INTA cycle that
    /// corresponds to this ExtINT delivery is routed to the external controller
    /// that is expected to supply the vector. A Delivery Mode of "ExtINT"
    /// requires an edge trigger mode.
    ExtINT,
    /// Unknown delivery mode encountered.
    Unknown(u64)
}

impl From<DeliveryMode> for u64 {
    fn from(mode: DeliveryMode) -> u64 {
        match mode {
            DeliveryMode::Fixed          => 0b000,
            DeliveryMode::LowestPriority => 0b001,
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

impl From<u64> for DeliveryMode {
    fn from(mode: u64) -> DeliveryMode {
        match mode {
            0b000 => DeliveryMode::Fixed,
            0b001 => DeliveryMode::LowestPriority,
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

// TODO: IoApic should not be Sync!
// BODY: IoApic manually implements Sync to allow it to be stored in a static.
// BODY: This is, however, wildly unsafe. It "works" today because we only have
// BODY: a single CPU and no preemption. We probably should store it in a Mutex.
unsafe impl Send for IoApic {}
unsafe impl Sync for IoApic {}

bitfield! {
    /// Description of a Redirection Entry in the IO-APIC. Unlike IRQ pins of the
    /// 8259A, the notion of interrupt priority is completely unrelated to the
    /// position of the physical interrupt input signal on the APIC. Instead,
    /// software determines the vector (and therefore the priority) for each
    /// corresponding interrupt input signal. For each interrupt signal, the
    /// operating system can also specify the signal polarity (low active or high
    /// active), whether the interrupt is signaled as edges or levels, as well as
    /// the destination and delivery mode of the interrupt. The information in
    /// the redirection table is used to translate the corresponding interrupt
    /// pin information into an inter-APIC message.
    ///
    /// The IOAPIC responds to an edge triggered interrupt as long as the
    /// interrupt is wider than one CLK cycle. The interrupt input is
    /// asynchronous; thus, setup and hold times need to be guaranteed for at
    /// lease one rising edge of the CLK input. Once the interrupt is detected, a
    /// delivery status bit internal to the IOAPIC is set. A new edge on that
    /// Interrupt input pin will not be recongnized until the IOAPIC Unit
    /// broadcasts the corresponding message over the APIC bus and the message
    /// has been accepted by the destination(s) specified in the destination
    /// field. That new edge only results in a new invocation of the handler if
    /// its acceptance by the destination APIC causes the Interrupt Request
    /// Register bit to go from 0 to 1. (In other words, if the interrupt wasn't
    /// already pending at the destination.)
    pub struct RedirectionEntry(u64);
    impl Debug;
    /// The vector field is an 8 bit field containing the interrupt vector for
    /// this interrupt. Vector values range from 0x10 to 0xFE.
    pub interrupt_vector, set_interrupt_vector: 7, 0;
    /// The Delivery Mode is a 3 bit field that specifies how the APICs listed in
    /// the destination field should act upon reception of this signal. Note that
    /// certain Delivery Modes only operate as intended when used in conjunction
    /// with a specific trigger Mode. These restrictions are indicated in the
    /// documentation of [Deliverymode].
    pub from into DeliveryMode, delivery_mode, set_delivery_mode: 10, 8;
    /// This field determines the interpretation of the Destination field. When
    /// it is `false` (physical mode), a destination APIC is identified by its
    /// ID. Bits 56 through 59 of the Destination field specify the 4 bit APIC
    /// ID.
    ///
    /// When this field is `true` (logicalmode), destinations are identified by
    /// matching on the logical destination under the control of the Destination
    /// Format Register and Logical Destination Register in each Local APIC.
    pub destination_mode, set_destination_mode: 11;
    /// The Delivery Status bit contains the current status of the delivery of
    /// this interrupt. Delivery Status is read-only and writes to this bit (as
    /// part of a 32 bitword) do not effect this bit.
    ///
    /// `false` means IDLE (there is currently no activity for this interrupt).
    ///
    /// `true` means SendPending (the interrupt has been injected but its
    /// delivery is temporarily held up due to the APIC bus being busy or the
    /// inability of the receiving APIC unit to accept that interrupt at that
    /// time).
    pub delivery_status, _: 12;
    /// This bit specifies the polarity of the interrupt signal. `false` means
    /// High active, `true` means Low active.
    pub interrupt_input_pin_polarity, set_interrupt_input_pin_polarity: 13;
    /// This bit is used for level triggered interrupts. Its meaning is undefined
    /// for edge triggered interrupts. For level triggered interrupts, this bit
    /// is set to `true` when local APIC(s) accept the level interrupt sent by
    /// the IOAPIC. The Remote IRR bit is set to `false` when an EOI message with
    /// a matching interrupt vector is received from a local APIC.
    pub remote_irr, _: 14;
    /// The trigger mode field indicates the type of signal on the interrupt pin
    /// that triggers an interrupt. `true` means Level sensitive, `false` means
    /// Edge sensitive.
    pub trigger_mode, set_trigger_mode: 15;
    /// When this bit is 1, the interrupt signal is masked. Edge-sensitive
    /// interrupts signaled on a masked interrupt pin are ignored (i.e., not
    /// delivered or held pending). Level-asserts or negates occurring on a
    /// masked level-sensitive pin are also ignored and have no side effects.
    /// Changing the mask bit from unmasked to masked after the interrupt is
    /// accepted by a local APIC has no effect on that interrupt. This behavior
    /// is identical to the case where the device withdraws the interrupt before
    /// that interrupt is posted to the processor. It is software's
    /// responsibility to handle the case where the mask bit is set after the
    /// interrupt message has been accepted by a local APIC unit but before the
    /// interrupt is dispensed to the processor. When this bit is 0, the
    /// interrupt is not masked. An edge or level on an interrupt pin that is not
    /// masked results in the delivery of the interrupt to the destination.
    pub interrupt_mask, set_interrupt_mask: 16;
    /// If the Destination Mode of this entry is Physical Mode, the first 4 bits
    /// contain an APIC ID. If Logical Mode is selected, the Destination Field
    /// potentially defines a set of processors. The Destination Field specify
    /// the logical destination address.
    pub destination_field, set_destination_field: 63, 53;
}

impl IoApic {
    /// Creates a new IO-APIC device at the given Physical Address, mapping
    /// interrupts (typically 24) starting from `interrupt_base`.
    /// 
    /// The IOAPIC will be initialized with sane values: every redirection entry
    /// will be masked, their interrupt vector set to 0x20 + interrupt_idx, and
    /// their destination CPU to `root_cpu_id`.
    ///
    /// # Safety
    ///
    /// Address should point to an IO-APIC, and must not be shared.
    pub unsafe fn new(address: PhysicalAddress, interrupt_base: u32, root_cpu_id: u32) -> IoApic {
        // TODO: Avoid mapping the same MMIO pages multiple times.
        // BODY: Currently, if we need to map distinct MMIO regions sharing the
        // BODY: same page, we do multiple mapping. This is wasteful of address
        // BODY: space, which is a relatively scarce resource.
        // BODY:
        // BODY: It might be a good idea to make an MMIO manager that hands out
        // BODY: references to the same mapping (with different offsets) when
        // BODY: a single page is shared.
        if address.floor() != (address + 8).floor() {
            panic!("Weird MMIO.")
        }

        let mmio = PhysicalMemRegion::on_fixed_mmio(address.floor(), 0x1000).unwrap();

        let vaddr = get_kernel_memory().map_phys_region(mmio, MappingAccessRights::k_rw());

        let vaddr_start = vaddr + (address - address.floor());

        let ioapic_internal = (vaddr_start.addr() as *const UnsafeCell<IoApicInternal>).as_ref().unwrap();

        let mut ret = IoApic {
            internal: ioapic_internal,
            interrupt_base,
            redirection_entry_count: 0
        };

        // Cache redirection entry count since we'll use it quite often.
        ret.redirection_entry_count = ret.read(1).get_bits(16..24);

        for i in 0..ret.redirection_entry_count() {
            let mut entry = ret.redirection_entry(i as u8);
            entry.set_interrupt_mask(true);
            entry.set_interrupt_vector((0x20 + i + interrupt_base).into());
            entry.set_destination_field(root_cpu_id.into());
            ret.set_redirection_entry(i as u8, entry);
        }

        info!("IOAPIC at {}({}) handles irq {}-{}", address, vaddr, interrupt_base, interrupt_base + ret.redirection_entry_count);
        ret
    }

    /// Reads an u32 at the specified DWORD offset.
    fn read(&self, offset: u32) -> u32 {
        unsafe {
            (*self.internal.get()).addr_reg.write(offset);
            (*self.internal.get()).data_reg.read()
        }
    }

    /// Writes an u32 at the specified DWORD offset.
    fn write(&self, offset: u32, data: u32) {
        unsafe {
            (*self.internal.get()).addr_reg.write(offset);
            (*self.internal.get()).data_reg.write(data);
        }
    }

    /// This register contains the 4-bit APIC ID. The ID serves as a physical
    /// name of the IOAPIC. All APIC devices using the APIC bus should have a
    /// unique APIC ID.
    pub fn ioapic_id(&self) -> u32 {
        self.read(0).get_bits(24..28)
    }

    /// Gets the version number of this IO-APIC device. This is expected to be
    /// 0x11 or 0x20.
    pub fn version(&self) -> u8 {
        self.read(1).get_bits(0..8) as u8
    }

    /// Start of the IRQ range handled by this IO-APIC device. Systems may have
    /// more than one IO-APIC if they need to handle more than 24 IRQs.
    pub fn interrupt_base(&self) -> u32 {
        self.interrupt_base
    }

    /// Gets the number of redirection entries in the I/O Redirection Table. This
    /// is expected to be 24, although more recent I/O-APIC devices may have
    /// more.
    pub fn redirection_entry_count(&self) -> u32 {
        self.redirection_entry_count + 1
    }

    /// Gets the bus arbitration priority for the IOAPIC. This register is loaded
    /// when the IOAPIC ID Register is written.
    ///
    /// The APIC uses a one wire arbitration to win bus ownership. A rotating
    /// priority scheme is used for arbitration. The winner of the arbitration
    /// becomes the lowest priority agent and assumes an arbitration ID of 0.
    ///
    /// All other agents, except the agent whose arbitration ID is 15, increment
    /// their arbitration IDs by one. The agent whose ID was 15 takes the
    /// winner's arbitration ID and increments it by one. Arbitration IDs are
    /// changed (incremented or asssumed) only for messages that are transmitted
    /// successfully (except, in the case of low priority messages where
    /// Arbitration ID is changed even if message was not successfully
    /// transmitted). A message is transmitted successfully if no checksum error
    /// or acceptance error is reported for that message. The register is always
    /// loaded with IOAPIC ID during a "level triggered INIT with de-assert"
    /// message.
    pub fn arbitration_id(&self) -> u32 {
        self.read(2).get_bits(24..28)
    }

    /// Gets the [RedirectionEntry] configuration of the specified pin.
    pub fn redirection_entry(&self, entry: u8) -> RedirectionEntry {
        assert!(u32::from(entry) < self.redirection_entry_count(), "Invalid entry {:#04x}", entry);
        let low = self.read(0x10 + u32::from(entry * 2));
        let hi = self.read(0x10 + u32::from(entry * 2) + 1);

        RedirectionEntry(*0u64
            .set_bits(0..32, low.into())
            .set_bits(32..64, hi.into()))
    }

    /// Configure the given pin with a [RedirectionEntry].
    pub fn set_redirection_entry(&self, entry: u8, data: RedirectionEntry) {
        assert!(u32::from(entry) < self.redirection_entry_count(), "Invalid entry {:#04x}", entry);
        self.write(0x10 + u32::from(entry * 2), data.0.get_bits(0..32) as u32);
        self.write(0x10 + u32::from(entry * 2) + 1, data.0.get_bits(32..64) as u32);
    }
}

impl fmt::Debug for IoApic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        #[allow(clippy::missing_docs_in_private_items)]
        struct RedirectionEntries<'a>(&'a IoApic);
        impl<'a> fmt::Debug for RedirectionEntries<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_list()
                    .entries((0..self.0.redirection_entry_count())
                             .map(|v| self.0.redirection_entry(v as u8)))
                    .finish()
            }
        }

        f.debug_struct("IoApic")
            .field("ioapic_id", &self.ioapic_id())
            .field("version", &self.version())
            .field("interrupt_base", &self.interrupt_base())
            .field("arbitration_id", &self.arbitration_id())
            .field("redirection_entries", &RedirectionEntries(self))
            .finish()
    }
}
