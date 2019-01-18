//! PCI discovery
//!
//! A minimal PCI implementation, that permits only discovering AHCI devices, and querying their BAR.

use kfs_libutils::io::{Io, Pio};
use spin::Mutex;
use alloc::prelude::*;

/// The CONFIG_ADDRESS I/O location.
pub const CONFIG_ADDRESS: u16 = 0xCF8;
/// The CONFIG_DATA I/O location.
pub const CONFIG_DATA: u16 = 0xCFC;

/// A struct tying the two pci config ports together.
struct PciConfigPortsPair {
    address: Pio<u32>,
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
#[derive(Debug, Copy, Clone)]
#[allow(missing_docs)]
struct PciDevice {
    /// The device's bus number.
    bus: u8,
    /// The device's slot number on its bus.
    slot: u8,
    /// The device's function number.
    function: u8,

    /* [register 0x00] */
    /// Device id.
    did: u16,
    /// Vendor id.
    vid: u16,
    /* [register 0x01] */
    /* status + command are volatile */
    /* [register 0x02] */
    class: u8,
    subclass: u8,
    prog_if: u8,
    rev_id: u8,
    /* [register 0x03] */
    /* bist is volatile */
    header_type: u8,
    latency_timer: u8,
    cache_line_size: u8,

    /// Remaining registers values, based on header type.
    header: PciHeader
}

/// Pci header when Header Type == 0x00 (General device).
#[derive(Copy, Clone, Debug)]
struct PciHeader00 {
    bar0: BAR,
    bar1: BAR,
    bar2: BAR,
    bar3: BAR,
    bar4: BAR,
    bar5: BAR,
    cardbus_cis_ptr: u32,
    subsystem_id: u16,
    subsystem_vendor_id: u16,
    expansion_rom_base_address: u32,
    capabilities_ptr: u8,
    max_latency: u8,
    min_grant: u8,
    interrupt_pin: u8,
    interrupt_line: u8,
}

/// Contents of pci config registers 0x4-0xf, structure varies based on Header Type.
#[derive(Copy, Clone, Debug)]
enum PciHeader {
    GeneralDevice(PciHeader00), // header type == 0x00
    PCItoPCIBridge,             // header type == 0x01, not implemented
    CardBus,                    // header type == 0x02, not implemented
    UnknownHeaderType(u8)       // header type == other
}

/// Base Address Registers. Minimal implementation, does not support 64-bits BARs.
#[derive(Copy, Clone, Debug)]
enum BAR {
    Memory(u32, u32), // a memory space address and its size
    Io(u32, u32)      // an IO space address
}

impl PciDevice {
    /// Checks if a device exists on given bus>slot>function.
    ///
    /// This is done by reading the Device ID - Vendor ID register (register 0).
    /// If `0xFFFF_FFFF` is read back, this means that the device was non-existent, and we return None.
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
                0x00 => PciHeader::GeneralDevice(PciHeader00 {
                    bar0: decode_bar(bus, slot, function, 4),
                    bar1: decode_bar(bus, slot, function, 5),
                    bar2: decode_bar(bus, slot, function, 6),
                    bar3: decode_bar(bus, slot, function, 7),
                    bar4: decode_bar(bus, slot, function, 8),
                    bar5: decode_bar(bus, slot, function, 9),
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

            /// Decode an u32 to BAR.
            /// 64-bit BARs are not supported.
            fn decode_bar(bus: u8, slot: u8, function: u8, register: u8) -> BAR {
                // read bar address
                let addr = pci_config_read_word(bus, slot, function, register);
                // write to get length
                pci_config_write_word(bus, slot, function, register, 0xFFFF_FFFF);
                // read back length
                let length = pci_config_read_word(bus, slot, function, register);
                // restore original value
                pci_config_write_word(bus, slot, function, register, addr);
                match addr & 0x01 {
                    0 => {
                        // memory space bar
                        BAR::Memory(addr & 0xFFFF_FFF0, (!(length & 0xFFFF_FFF0)).wrapping_add(1))
                    },
                    _ => {
                        // io space bar
                        BAR::Io(addr & 0xFFFF_FFFC, (!(length & 0xFFFF_FFFC)).wrapping_add(1))
                    }
                }
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
fn pci_config_read_word(bus: u8, slot: u8, func: u8, register: u8) -> u32 {
    debug_assert!(bus <= MAX_BUS);
    debug_assert!(slot <= MAX_SLOT);
    debug_assert!(func <= MAX_FUNC);
    debug_assert!(register <= MAX_REGISTER);
    let lbus = bus as u32;
    let lslot = slot as u32;
    let lfunc = func as u32;
    let lregister = register as u32;
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
fn pci_config_write_word(bus: u8, slot: u8, func: u8, register: u8, value: u32) {
    debug_assert!(bus <= MAX_BUS);
    debug_assert!(slot <= MAX_SLOT);
    debug_assert!(func <= MAX_FUNC);
    debug_assert!(register <= MAX_REGISTER);
    let lbus = bus as u32;
    let lslot = slot as u32;
    let lfunc = func as u32;
    let lregister = register as u32;
    let mut ports = PCI_CONFIG_PORTS.lock();

    /* create the configuration address */
    let address: u32 = (lbus << 16) | (lslot << 11) |
                       (lfunc << 8) | (lregister << 2) | 0x80000000;

    /* write out the address */
    ports.address.write(address);

    /* read the data */
    ports.data.write(value)
}

/// Discover all pci devices, by probing the PID-VID of every slot on every bus.
///
/// A device is discovered when its `(bus, slot, function 0x00)[register 0x00] != 0xFFFF_FFFF`.
/// Then, an additional [PciDevice] will be returned for every of its other functions that also
/// return anything different from `0xFFFF_FFFF`.
fn discover() -> Vec<PciDevice> {
    let mut devices = vec![];
    for bus in 0..MAX_BUS {
        for slot in 0..MAX_SLOT {
            // test function 0.
            if let Some(device) = PciDevice::probe(bus, slot, 0) {
                let is_multifunction = device.header_type & 0x80 != 0;
                devices.push(device);
                // check for other function on the same device
                if is_multifunction {
                    for function in 1..MAX_FUNC {
                        if let Some(device) = PciDevice::probe(bus, slot, function) {
                            devices.push(device);
                        }
                    }
                }
            }
        }
    }
    devices
}

/// Gets the ahci controllers found by pci discovery.
///
/// # Returns
///
/// Returns the controller's BAR5 address and size, if one was found.
pub fn get_ahci_controllers() -> Vec<(u32, u32)> {
    discover().iter()
        .filter(|device| device.class == 0x01 && device.subclass == 0x06 && device.prog_if == 0x01)
        .map(|device| {
            match device.header {
                PciHeader::GeneralDevice(header00) => {
                    match header00.bar5 {
                        BAR::Memory(addr, size) => (addr, size),
                        _ => panic!("PCI device with unexpected BAR 5")
                    }
                },
                _ => panic!("PCI device with unexpected header")
            }
        })
        .collect()
}
