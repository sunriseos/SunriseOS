//! PCI discovery
//!
//! A minimal PCI implementation, that permits only discovering AHCI devices, and querying their BAR.

use sunrise_libutils::io::{Io, Pio};
use spin::Mutex;
use getset::Getters;
use bit_field::BitField;

/// The CONFIG_ADDRESS I/O location.
pub const CONFIG_ADDRESS: u16 = 0xCF8;
/// The CONFIG_DATA I/O location.
pub const CONFIG_DATA: u16 = 0xCFC;

/// A struct tying the two pci config ports together.
#[derive(Debug)]
struct PciConfigPortsPair {
    /// The address port.
    ///
    /// Write the '''address''' of the config-space register you want to access.
    ///
    /// An address is formatted as follow:
    ///
    /// * 31    Enable bit
    /// * 30:24 Reserved
    /// * 23:16 Bus Number
    /// * 15:11 Device Number
    /// * 10:8  Function Number
    /// * 7:0   Register Offset
    address: Pio<u32>,
    /// The data port.
    ///
    /// After having put the address of the register you want in `.address`,
    /// read this port to retrieve its value.
    data: Pio<u32>
}

/// A mutex around the two ports used to address pci configuration space.
static PCI_CONFIG_PORTS: Mutex<PciConfigPortsPair> = Mutex::new(PciConfigPortsPair {
    address: Pio::new(CONFIG_ADDRESS),
    data: Pio::new(CONFIG_DATA)
});

/// The highest addressable bus.
const MAX_BUS: u8 = 255;
/// The highest addressable slot on a bus.
const MAX_SLOT: u8 = 31;
/// The highest addressable function on a slot on a bus.
const MAX_FUNC: u8 = 15;
/// The highest addressable register on a function on a slot on a bus.
const MAX_REGISTER: u8 = 63;

/// A pci device, addressed by its bus number, slot, and function.
#[derive(Debug, Copy, Clone, Getters)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct PciDevice {
    /// The device's bus number.
    #[get = "pub"] #[deref]
    bus: u8,
    /// The device's slot number on its bus.
    #[get = "pub"] #[deref]
    slot: u8,
    /// The device's function number.
    #[get = "pub"] #[deref]
    function: u8,

    /* [register 0x00] */
    /// Identifies the particular device. Where valid IDs are allocated by the vendor.
    #[get = "pub"] #[deref]
    did: u16,
    /// Identifies the manufacturer of the device. Where valid IDs are allocated by PCI-SIG (the list
    /// is [here]) to ensure uniqueness and 0xFFFF is an invalid value that will be returned on read
    /// accesses to Configuration Space registers of non-existent devices.
    ///
    /// [here]: https://pcisig.com/membership/member-companies
    #[get = "pub"] #[deref]
    vid: u16,
    /* [register 0x01] */
    /* status + command are volatile */
    /* [register 0x02] */
    /// Specifies the type of function the device performs.
    #[get = "pub"] #[deref]
    class: u8,
    /// Specifies the specific function the device performs.
    #[get = "pub"] #[deref]
    subclass: u8,
    /// Specifies a register-level programming interface the device has, if it has any at all.
    #[get = "pub"] #[deref]
    prog_if: u8,
    /// Specifies a revision identifier for a particular device. Where valid IDs are allocated by the vendor.
    #[get = "pub"] #[deref]
    rev_id: u8,
    /* [register 0x03] */
    /* bist is volatile */
    header_type: u8,
    /// Specifies the latency timer in units of PCI bus clocks.
    #[get = "pub"] #[deref]
    latency_timer: u8,
    /// Specifies the system cache line size in 32-bit units. A device can limit the number of
    /// cacheline sizes it can support, if a unsupported value is written to this field, the device
    /// will behave as if a value of 0 was written.
    #[get = "pub"] #[deref]
    cache_line_size: u8,

    /// Remaining registers values, based on header type.
    #[get = "pub"] #[deref]
    header: PciHeader
}

/// Pci header when Header Type == 0x00 (General device).
#[derive(Copy, Clone, Debug, Getters)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct GeneralPciHeader {
    bars: [Option<BAR>; 6],
    /// Points to the Card Information Structure and is used by devices that share silicon between
    /// CardBus and PCI.
    #[get] #[deref]
    cardbus_cis_ptr: u32,
    subsystem_id: u16,
    subsystem_vendor_id: u16,
    expansion_rom_base_address: u32,
    /// Points to a linked list of new capabilities implemented by the device. Used if bit 4 of the
    /// status register (Capabilities List bit) is set to 1. The bottom two bits are reserved and
    /// should be masked before the Pointer is used to access the Configuration Space.
    #[get] #[deref]
    capabilities_ptr: u8,
    /// Specifies how often the device needs access to the PCI bus (in 1/4 microsecond units).
    #[get] #[deref]
    max_latency: u8,
    /// Specifies the burst period length, in 1/4 microsecond units, that the device needs (assuming
    /// a 33 MHz clock rate).
    #[get] #[deref]
    min_grant: u8,
    /// Specifies which interrupt pin the device uses. Where a value of 0x01 is INTA#, 0x02 is
    /// INTB#, 0x03 is INTC#, 0x04 is INTD#, and 0x00 means the device does not use an interrupt
    /// pin.
    #[get] #[deref]
    interrupt_pin: u8,
    /// Specifies which input of the system interrupt controllers the device's interrupt pin is
    /// connected to and is implemented by any device that makes use of an interrupt pin. For the
    /// x86 architecture this register corresponds to the PIC IRQ numbers 0-15 (and not I/O APIC IRQ
    /// numbers) and a value of 0xFF defines no connection.
    #[get] #[deref]
    interrupt_line: u8,
}

impl GeneralPciHeader {
    /// Get the Base Address Register at the specified index.
    ///
    /// May return None if idx bigger than 5, or if specified BAR does not exist (may happen if the
    /// previous BAR was a 64-bit BAR).
    pub fn bar(&self, idx: usize) -> Option<&BAR> {
        self.bars.get(idx).and_then(|x| x.as_ref())
    }
}

/// Contents of pci config registers 0x4-0xf, structure varies based on Header Type.
#[derive(Copy, Clone, Debug)]
pub enum PciHeader {
    /// header type == 0x00
    GeneralDevice(GeneralPciHeader),
    /// header type == 0x01, not implemented
    PCItoPCIBridge,
    /// header type == 0x02, not implemented
    CardBus,
    /// header type == other
    UnknownHeaderType(u8)
}

/// Base Address Registers. Minimal implementation, does not support 64-bits BARs.
#[derive(Copy, Clone, Debug)]
pub enum BAR {
    /// a memory space address and its size
    Memory(u32, u32),
    /// a 64-bit memory space address and its size
    Memory64(u64, u64),
    /// an IO space address
    Io(u32, u32)
}

impl PciDevice {
    /// Checks if a device exists on given bus>slot>function.
    ///
    /// This is done by reading the Device ID - Vendor ID register (register 0).
    /// If `0xFFFF_FFFF` is read back, this means that the device was non-existent, and we return None.
    #[allow(clippy::absurd_extreme_comparisons)]
    fn probe(bus: u8, slot: u8, function: u8) -> Option<Self> {
        debug_assert!(bus <= MAX_BUS);
        debug_assert!(slot <= MAX_SLOT);
        debug_assert!(function <= MAX_FUNC);
        let did_vid = pci_config_read_word(bus, slot, function, 0);
        return if did_vid == 0xFFFF_FFFF {
            None
        } else {
            Some(Self {
                bus,
                slot,
                function,
                did: (did_vid >> 16) as u16,
                vid: did_vid as u16,
                class:    (pci_config_read_word(bus, slot, function, 2) >> 24) as u8,
                subclass: (pci_config_read_word(bus, slot, function, 2) >> 16) as u8,
                prog_if:  (pci_config_read_word(bus, slot, function, 2) >>  8) as u8,
                rev_id:    pci_config_read_word(bus, slot, function, 2) as u8,
                header_type:     (pci_config_read_word(bus, slot, function, 3) >> 16) as u8,
                latency_timer:   (pci_config_read_word(bus, slot, function, 3) >>  8) as u8,
                cache_line_size:  pci_config_read_word(bus, slot, function, 3) as u8,

                header: read_header(bus, slot, function)
            })
        };

        /// Reads the remaining of the pci-registers, organising them based on header type.
        fn read_header(bus: u8, slot: u8, function: u8) -> PciHeader {
            // header_type, but bit 8 informs if device is multi-function, ignore it.
            let header_type = (pci_config_read_word(bus, slot, function, 3) >> 16) as u8;
            return match header_type & 0x7f {
                0x00 => PciHeader::GeneralDevice(GeneralPciHeader {
                    bars: decode_bars(bus, slot, function),
                    cardbus_cis_ptr: pci_config_read_word(bus, slot, function, 0xa),
                    subsystem_id:        (pci_config_read_word(bus, slot, function, 0xb) >> 16) as u16,
                    subsystem_vendor_id:  pci_config_read_word(bus, slot, function, 0xb) as u16,
                    expansion_rom_base_address: pci_config_read_word(bus, slot, function, 0xc),
                    capabilities_ptr: pci_config_read_word(bus, slot, function, 0xd) as u8,
                    max_latency:   (pci_config_read_word(bus, slot, function, 0xf) >> 24) as u8,
                    min_grant:     (pci_config_read_word(bus, slot, function, 0xf) >> 16) as u8,
                    interrupt_pin: (pci_config_read_word(bus, slot, function, 0xf) >>  8) as u8,
                    interrupt_line: pci_config_read_word(bus, slot, function, 0xf)        as u8,
                }),
                0x01 => PciHeader::PCItoPCIBridge,
                0x02 => PciHeader::CardBus,
                other => PciHeader::UnknownHeaderType(other)
            };

            /// Decode an u32 to .
            fn decode_bar(bus: u8, slot: u8, function: u8, register: u8) -> (u32, u32) {
                // read bar address
                let addr = pci_config_read_word(bus, slot, function, register);
                // write to get length
                pci_config_write_word(bus, slot, function, register, 0xFFFF_FFFF);
                // read back length
                let length = pci_config_read_word(bus, slot, function, register);
                // restore original value
                pci_config_write_word(bus, slot, function, register, addr);

                (addr, length)
            }

            fn decode_bars(bus: u8, slot: u8, function: u8) -> [Option<BAR>; 6] {
                let mut register = 4;
                let mut bars = [None; 6];
                while register < 10 {
                    let (addr, length) = decode_bar(bus, slot, function, register);
                    bars[register as usize - 4] = match (addr.get_bit(0), addr.get_bits(1..3)) {
                        (false, 0) => {
                            // memory space bar
                            Some(BAR::Memory(addr & 0xFFFF_FFF0, (!(length & 0xFFFF_FFF0)).wrapping_add(1)))
                        },
                        (false, 2) => {
                            // memory space bar
                            register += 1;
                            let (addrhigh, lengthhigh) = decode_bar(bus, slot, function, register);
                            let addr = (addr as u64 & 0xFFFF_FFF0) | ((addrhigh as u64) << 32);
                            let length = ((length as u64 & 0xFFFF_FFF0) | ((lengthhigh as u64) << 32)).wrapping_add(1);
                            Some(BAR::Memory64(addr, length))
                        },
                        (true, _) => {
                            // io space bar
                            Some(BAR::Io(addr & 0xFFFF_FFFC, (!(length & 0xFFFF_FFFC)).wrapping_add(1)))
                        },
                        _ => {
                            info!("Unsupported PCI BAR idx {} value {:#08x}", register - 4, addr);
                            None
                        }
                    };
                    register += 1;
                }
                bars
            }
        }
    }

    /// Reads a configuration space register.
    fn read_config_register(&self, register: u8) -> u32 {
        pci_config_read_word(self.bus, self.slot, self.function, register)
    }

    /// Writes to a configuration space register.
    fn write_config_register(&self, register: u8, value: u32) {
        pci_config_write_word(self.bus, self.slot, self.function, register, value)
    }

    // register 1

    /// Reads the status register.
    fn status(&self) -> u16 {
        (self.read_config_register(1) >> 16) as u16
    }

    /// Reads the command register.
    fn command(&self) -> u16 {
        (self.read_config_register(1) >> 0) as u16
    }
}

/// Read one of the 64 32-bit registers of a pci bus>device>func.
#[allow(clippy::absurd_extreme_comparisons)]
fn pci_config_read_word(bus: u8, slot: u8, func: u8, register: u8) -> u32 {
    debug_assert!(bus <= MAX_BUS);
    debug_assert!(slot <= MAX_SLOT);
    debug_assert!(func <= MAX_FUNC);
    debug_assert!(register <= MAX_REGISTER);
    let lbus = u32::from(bus);
    let lslot = u32::from(slot);
    let lfunc = u32::from(func);
    let lregister = u32::from(register);
    let mut ports = PCI_CONFIG_PORTS.lock();

    /* create the configuration address */
    let address: u32 = (lbus << 16) | (lslot << 11) |
                       (lfunc << 8) | (lregister << 2) | 0x80000000;

    /* write out the address */
    ports.address.write(address);

    /* read the data */
    ports.data.read()
}

/// Read one of the 64 32-bit registers of a pci bus>device>func.
#[allow(clippy::absurd_extreme_comparisons)]
fn pci_config_write_word(bus: u8, slot: u8, func: u8, register: u8, value: u32) {
    debug_assert!(bus <= MAX_BUS);
    debug_assert!(slot <= MAX_SLOT);
    debug_assert!(func <= MAX_FUNC);
    debug_assert!(register <= MAX_REGISTER);
    let lbus = u32::from(bus);
    let lslot = u32::from(slot);
    let lfunc = u32::from(func);
    let lregister = u32::from(register);
    let mut ports = PCI_CONFIG_PORTS.lock();

    /* create the configuration address */
    let address: u32 = (lbus << 16) | (lslot << 11) |
                       (lfunc << 8) | (lregister << 2) | 0x80000000;

    /* write out the address */
    ports.address.write(address);

    /* read the data */
    ports.data.write(value)
}

/// Iterator created with the [discover] function.
// First u8 is bus, second is slot, third is func.
#[derive(Debug)]
struct PciDeviceIterator(u8, u8, u8);

impl Iterator for PciDeviceIterator {
    type Item = PciDevice;
    fn next(&mut self) -> Option<PciDevice> {
        for bus in self.0..MAX_BUS {
            for slot in self.1..MAX_SLOT {
                // test function 0.
                if let Some(device) = PciDevice::probe(bus, slot, 0) {
                    let is_multifunction = device.header_type & 0x80 != 0;
                    if self.2 == 0 {
                        self.2 += 1;
                        return Some(device);
                    }
                    // check for other function on the same device
                    if is_multifunction {
                        for function in self.2..MAX_FUNC {
                            self.2 += 1;
                            if let Some(device) = PciDevice::probe(bus, slot, function) {
                                return Some(device);
                            }
                        }
                    }
                }
                self.2 = 0;
                self.1 += 1;
            }
            self.2 = 0;
            self.1 = 0;
            self.0 += 1;
        }
        return None;
    }
}

/// Discover all pci devices, by probing the PID-VID of every slot on every bus.
///
/// A device is discovered when its `(bus, slot, function 0x00)[register 0x00] != 0xFFFF_FFFF`.
/// Then, an additional [PciDevice] will be returned for every of its other functions that also
/// return anything different from `0xFFFF_FFFF`.
pub fn discover() -> impl Iterator<Item = PciDevice> + core::fmt::Debug {
    PciDeviceIterator(0, 0, 0)
}

