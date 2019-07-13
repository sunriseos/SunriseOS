use crate::pci::{PciDevice, PciHeader};
use crate::pci::{pci_config_read_word, pci_config_write_word};
use crate::error::KernelError;
use bit_field::BitField;
use byteorder::LE;

pub(super) struct CapabilitiesIter<'a> {
    device: &'a PciDevice,
    offset: u8,
}

impl<'a> Iterator for CapabilitiesIter<'a> {
    type Item = Capability<'a>;
    fn next(&mut self) -> Option<Capability<'a>> {
        if self.offset == 0 {
            return None
        }
        info!("Reading capability at {:#02x}", self.offset);
        let (cap, next) = Capability::parse(self.device, self.offset);
        self.offset = next;
        Some(cap)
    }
}

impl<'a> CapabilitiesIter<'a> {
    pub(super) fn new(device: &'a PciDevice, offset: u8) -> CapabilitiesIter<'a> {
        CapabilitiesIter { device, offset }
    }
}

#[derive(Debug)] // TODO: More interesting debug.
pub struct MsiX<'a> {
    inner: RWCapability<'a>
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MsiXEntry {
    pub addr: u64,
    pub data: u32,
    pub ctrl: MsiXControl 
}

bitfield! {
    #[derive(Clone, Copy)]
    pub struct MsiXControl(u32);
    impl Debug;
    pub masked, set_masked: 0;
}

impl<'a> MsiX<'a> {
    pub fn enable_msix(&self, val: bool) {
        let mut val = self.inner.read_u32(0);
        val.set_bit(31, true);
        self.inner.write_u32(0, val);
    }

    pub fn table_size(&self) -> usize {
        self.inner.read_u32(0).get_bits(16..27) as usize + 1
    }

    pub fn set_message_entry(&self, entry: usize, val: MsiXEntry) -> Result<(), KernelError> {
        assert!(entry < self.table_size());
        let mut table_offset_bir = self.inner.read_u32(4);
        let bir = table_offset_bir.get_bits(0..3);
        let table_offset = *table_offset_bir.set_bits(0..3, 0) as u64;

        let PciDevice { bus, slot, function, .. } = self.inner.device;

        let header = match self.inner.device.header {
            PciHeader::GeneralDevice(header) => header,
            _ => unreachable!()
        };

        let bar = header.bar(bir as usize).expect(&format!("Device {}.{}.{} to contain BAR {}", bus, slot, function, bir));
        let mapped_bar = bar.map()?;

        mapped_bar.write_u32::<LE>(table_offset + (entry * 16) as u64, val.addr.get_bits(0..32) as u32);
        mapped_bar.write_u32::<LE>(table_offset + (entry * 16 + 4) as u64, val.addr.get_bits(32..64) as u32);
        mapped_bar.write_u32::<LE>(table_offset + (entry * 16 + 8) as u64, val.data);
        mapped_bar.write_u32::<LE>(table_offset + (entry * 16 + 12) as u64, val.ctrl.0);

        Ok(())
    }
}

#[derive(Debug)]
pub struct RWCapability<'a> {
    device: &'a PciDevice,
    offset: u8,
}

impl<'a> RWCapability<'a> {
    pub fn read_u32(&self, offset: u8) -> u32 {
        pci_config_read_word(self.device.bus, self.device.slot, self.device.function, (self.offset + offset) & 0xFC)
    }
    pub fn write_u32(&self, offset: u8, value: u32) {
        pci_config_write_word(self.device.bus, self.device.slot, self.device.function, (self.offset + offset) & 0xFC, value);
    }
}

#[derive(Debug)]
pub enum Capability<'a> {
    Reserved,
    PciPowerManagement,
    AcceleratedGraphicsPort,
    VitalProductData,
    SlotIdentification,
    Msi,
    CompactPciHotSwap,
    PciX,
    HyperTransport,
    VendorSpecific(RWCapability<'a>, u8),
    DebugPort,
    CompactPciCentralResourceControl,
    PciHotPlug,
    AcceleratedGraphicsPort8x,
    SecureDevice,
    PciExpress,
    MsiX(MsiX<'a>),
    Unknown(u8),
}

/*// TODO: Lazily read the Vendor-Specific Capabilities?
// BODY: Currently, vendor-specific capabilities are eagerly read and kept in a
// BODY: vector. This is likely suboptimal. Ideally, we should get some type that
// BODY: we can call functions on to get u32s from.
let mut size = word.get_bits(16..24) as u8;
let mut data = Vec::with_capacity(size.saturating_sub(3) as usize);

let mut idx = 4u8;
data.push(word.get_bits(24..32) as u8);
while idx < size {
    let word = pci_config_read_word(bus, slot, function, register + idx);
    for i in 0..core::cmp::min(size - idx, 4) {
        let i = i as usize;
        data.push(word.get_bits(i * 8..(i + 1) * 8) as u8);
    }
    idx += 4;
}*/
impl<'a> Capability<'a> {
    pub fn parse(device: &'a PciDevice, register: u8) -> (Capability<'a>, u8) {
        let word = pci_config_read_word(device.bus, device.slot, device.function, register);
        let ty = word.get_bits(0..8) as u8;
        let mut next = word.get_bits(8..16) as u8;
        // 6.7: Get rid of the lower 2 bits, they are reserved for future use.
        next.set_bits(0..2, 0);

        let rw_cap = RWCapability {
            device, offset: register
        };

        let cap = match ty {
            0x00 => Capability::Reserved,
            0x01 => Capability::PciPowerManagement,
            0x02 => Capability::AcceleratedGraphicsPort,
            0x03 => Capability::VitalProductData,
            0x04 => Capability::SlotIdentification,
            0x05 => Capability::Msi,
            0x06 => Capability::CompactPciHotSwap,
            0x07 => Capability::PciX,
            0x08 => Capability::HyperTransport,
            0x09 => {
                let len = word.get_bits(16..24) as u8;
                Capability::VendorSpecific(rw_cap, len)
            },
            0x0A => Capability::DebugPort,
            0x0B => Capability::CompactPciCentralResourceControl,
            0x0C => Capability::PciHotPlug,
            0x0E => Capability::AcceleratedGraphicsPort8x,
            0x0F => Capability::SecureDevice,
            0x10 => Capability::PciExpress,
            0x11 => Capability::MsiX(MsiX {
                inner: rw_cap
            }),
            id   => Capability::Unknown(id)
        };

        (cap, next)
    }
}
