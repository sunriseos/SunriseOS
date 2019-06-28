//! Network Device

use crate::VirtioDevice;
use byteorder::{LE, ByteOrder};
use crate::pci::Config;
use crate::virtqueue::VirtQueue;
use crate::{DeviceStatus, CommonFeatures};
use bitflags::bitflags;
use alloc::vec::Vec;
use smoltcp::phy::{Device, Checksum, DeviceCapabilities, ChecksumCapabilities, RxToken, TxToken};
use smoltcp::time::Instant;
use core::fmt;
use sunrise_libuser::error::Error;
use bit_field::BitField;
use log::*;

bitflags! {
    /// Features supported by the Virtio-Net driver.
    struct Features: u64 {
        /// Device handles packets with partial checksum. This “checksum offload”
        /// is a common feature on modern network cards.
        const CSUM                  = 1 << 0;
        /// Driver handles packets with partial checksum.
        const GUEST_CSUM            = 1 << 1;
        /// Control channel offloads reconfiguration support.
        const CTRL_GUEST_OFFLOADS   = 1 << 2;
        /// Device maximum MTU reporting is supported. If offered by the device,
        /// device advises driver about the value of its maximum MTU. If
        /// negotiated, the driver uses mtu as the maximum MTU value.
        const MTU                   = 1 << 3;

        /// Device has given MAC address.
        const MAC                   = 1 << 5;

        /// Driver can receive TSOv4.
        const GUEST_TSO4            = 1 << 7;
        /// Driver can receive TSOv6.
        const GUEST_TSO6            = 1 << 8;
        /// Driver can receive TSO with ECN.
        const GUEST_ECN             = 1 << 9;
        /// Driver can receive UFO.
        const GUEST_UFO             = 1 << 10;
        /// Device can receive TSOv4.
        const HOST_TSO4             = 1 << 11;
        /// Device can receive TSOv6.
        const HOST_TSO6             = 1 << 12;
        /// Device can receive TSO with ECN.
        const HOST_ECN              = 1 << 13;
        /// Device can receive UFO.
        const HOST_UFO              = 1 << 14;
        /// Driver can merge receive buffers.
        const MRG_RXBUF             = 1 << 15;
        /// Configuration status field is available.
        const STATUS                = 1 << 16;
        /// Control channel is available.
        const CTRL_VQ               = 1 << 17;
        /// Control channel RX mode support.
        const CTRL_RX               = 1 << 18;
        /// Control channel VLAN filtering.
        const CTRL_VLAN             = 1 << 19;

        /// Driver can send gratuitous packets.
        const GUEST_ANNOUNCE        = 1 << 21;
        /// Device supports multiqueue with automatic receive steering.
        const MQ                    = 1 << 22;
        /// Set MAC address through control channel.
        const CTRL_MAC_ADDR         = 1 << 23;

        /// Device can process duplicated ACKs and report number of coalesced
        /// segments and duplicated ACKs.
        const RSC_EXT               = 1 << 61;
        /// Device may act as a standby for a primary device with the same MAC
        /// address.
        const STANDBY               = 1 << 62;
    }
}

pub struct NetConfiguration {
    config: Config
}

impl fmt::Debug for NetConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NetConfiguration")
            .field("mac", &self.mac())
            .field("status", &self.status())
            .field("max_virtqueue_pairs", &self.max_virtqueue_pairs())
            .field("mtu", &self.mtu())
            .finish()
    }
}

impl NetConfiguration {
    pub fn mac(&self) -> [u8; 6] {
        let mac0 = self.config.read_u8(0);
        let mac1 = self.config.read_u8(1);
        let mac2 = self.config.read_u8(2);
        let mac3 = self.config.read_u8(3);
        let mac4 = self.config.read_u8(4);
        let mac5 = self.config.read_u8(5);
        [mac0, mac1, mac2, mac3, mac4, mac5]
    }

    pub fn status(&self) -> u16 {
        self.config.read_u16::<LE>(6)
    }

    pub fn max_virtqueue_pairs(&self) -> u16 {
        self.config.read_u16::<LE>(8)
    }

    pub fn mtu(&self) -> u16 {
        self.config.read_u16::<LE>(10)
    }
}

/// Ensure the feature bit requirements of section 5.1.3.1 are met.
fn ensure_requirements_met(bits: u64) -> bool {
    let bits = Features::from_bits_truncate(bits);
    if bits.intersects(Features::GUEST_TSO4 | Features::GUEST_TSO6 | Features::GUEST_UFO) && !bits.contains(Features::GUEST_CSUM) {
        return false;
    }

    if bits.intersects(Features::GUEST_ECN) && !bits.intersects(Features::GUEST_TSO4 | Features::GUEST_TSO6) {
        return false
    }

    if bits.intersects(Features::HOST_TSO4 | Features::HOST_TSO6 | Features::HOST_UFO) && !bits.contains(Features::CSUM) {
        return false;
    }

    if bits.intersects(Features::HOST_ECN | Features::RSC_EXT) && !bits.intersects(Features::HOST_TSO4 | Features::HOST_TSO6) {
        return false
    }

    if bits.intersects(Features::CTRL_RX | Features::CTRL_VLAN | Features::GUEST_ANNOUNCE | Features::MQ | Features::CTRL_MAC_ADDR) && !bits.contains(Features::CTRL_VQ) {
        return false;
    }

    return true;
}

#[derive(Debug)]
pub struct VirtioNet {
    // TODO: Tmp
    pub device: VirtioDevice,
    net_config: NetConfiguration,
    common_features: Features,
}

impl VirtioNet {
    pub fn new(mut device: VirtioDevice) -> VirtioNet {
        let net_config = NetConfiguration {
            config: device.acquire_device_cfg()
        };
        VirtioNet {
            device, net_config, common_features: Features::empty()
        }
    }

    /// 5.1.5: Device Initialization
    pub fn init(&mut self) -> Result<(), Error> {
        // TODO: Is it OK to assume device is ack'd in VirtioNet::init?
        // 3.1.1 Driver Requirements: Device Initialization
        self.device.common_cfg.set_device_status(DeviceStatus::DRIVER);

        // Negociate features

        // Minimum features that we **should** negociate, as part of 5.1.4.2
        let wanted_features = Features::MAC | Features::MTU;

        // Additional features that would be nice to have
        let wanted_features = Features::CSUM | wanted_features;

        let common_features = self.device.negociate_features(wanted_features.bits(), 0, ensure_requirements_met)?;
        self.common_features = Features::from_bits_truncate(common_features);

        // 4.1.5.1: PCI-specific initialization
        // TODO: MSI-X Vector Configuration.
        // Virtqueue Configuration

        // 5.1.5: Device Initialization
        // Identify and initialize the receive and transmission virtqueues.
        // TODO: Support VIRTIO_NET_F_MQ
        info!("Setup virtqueues");
        for virtqueue_idx in 0..2 {
            self.device.setup_virtqueue(virtqueue_idx);
        }

        if self.common_features.contains(Features::CTRL_VQ) {
            // TODO: Setup ctrl_vq
        }

        info!("Push a ton of buffers");
        // Fill the receive queues buffer: See 5.1.6.3
        for queue in self.receive_queues() {
            for item in 0..queue.len() {
                //info!("Pushing buffer for item {}/{}", item, queue.len());
                //if item == 63 {
                //    info!("{:#?}", queue);
                //}
                queue.push_buffer_w(Vec::with_capacity(65560))
            }
        }

        // Even with VIRTIO_NET_F_MQ, only receiveq1, transmitq1 and controlq are
        // used by default. The driver would send the VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET
        // command specifying the number of the transmit and receive queues to use.

        // If the VIRTIO_NET_F_MAC feature bit is set, the configuration space mac
        // entry indicates the “physical” address of the network card, otherwise
        // the driver would typically generate a random local MAC address.
        info!("Get mac address");
        let mac = if self.common_features.contains(Features::MAC) {
            self.net_config.mac()
        } else {
            // TODO: Generate random mac
            [0, 1, 2, 3, 4, 5]
        };

        info!("We're good to go!");
        self.device.common_cfg.set_device_status(DeviceStatus::DRIVER_OK);

        Ok(())
    }

    fn receive_queues(&mut self) -> impl Iterator<Item = &mut VirtQueue> {
        let num_queues = if self.common_features.contains(Features::MQ) {
            self.net_config.max_virtqueue_pairs() as usize
        } else {
            1
        };
        self.device.queues.iter_mut().step_by(2).take(num_queues).filter_map(|v| v.as_mut())
    }

    fn transmit_queues(&mut self) -> impl Iterator<Item = &mut VirtQueue> {
        let num_queues = if self.common_features.contains(Features::MQ) {
            self.net_config.max_virtqueue_pairs() as usize
        } else {
            1
        };
        self.device.queues.iter_mut().skip(1).step_by(2).take(num_queues).filter_map(|v| v.as_mut())
    }

    fn control_queue(&mut self) -> Option<&mut VirtQueue> {
        if self.common_features.contains(Features::CTRL_VQ) {
            let num_queues = if self.common_features.contains(Features::MQ) {
                self.net_config.max_virtqueue_pairs() as usize
            } else {
                1
            };
            self.device.queues[num_queues * 2].as_mut()
        } else {
            None
        }
    }

    pub fn link_status(&self) -> bool {
        if self.common_features.contains(Features::STATUS) {
            self.net_config.status().get_bit(0)
        } else {
            true
        }
    }

    pub fn mac(&self) -> [u8; 6] {
        if self.common_features.contains(Features::MAC) {
            self.net_config.mac()
        } else {
            // TODO: Generate random mac
            [0, 1, 2, 3, 4, 5]
        }
    }
}

impl<'a> Device<'a> for VirtioNet {
    type RxToken = VirtioNetRxToken;
    type TxToken = VirtioNetTxToken<'a>;


    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let buf = self.receive_queues().nth(0).unwrap().pop_buffer_w()?;
        debug!("{:#?}", buf);
        let rx = VirtioNetRxToken(buf);
        let tx = VirtioNetTxToken(self);
        Some((rx, tx))
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(VirtioNetTxToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut device_caps = DeviceCapabilities::default();
        if self.common_features.contains(Features::MTU) {
            device_caps.max_transmission_unit = self.net_config.mtu() as usize;
        } else {
            device_caps.max_transmission_unit = 65535;
        }
        if self.common_features.contains(Features::CSUM) {
            device_caps.checksum.udp = Checksum::None;
            device_caps.checksum.tcp = Checksum::None;
        }
        device_caps
    }
}

pub struct VirtioNetRxToken(Vec<u8>);

impl RxToken for VirtioNetRxToken {
    fn consume<R, F>(self, timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&[u8]) -> smoltcp::Result<R>
    {
        debug!("Consuming the buffer");
        f(&self.0[core::mem::size_of::<NetHdr>()..])
    }
}

pub struct VirtioNetTxToken<'a>(&'a mut VirtioNet);

impl<'a> TxToken for VirtioNetTxToken<'a> {
    fn consume<R, F>(self, timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>
    {
        // TODO: Instead of allocating a new vec, use scatter-gather IO.

        let mut v = Vec::new();
        v.resize(len + core::mem::size_of::<NetHdr>(), 0);
        let res = f(&mut v[core::mem::size_of::<NetHdr>()..]);

        v[0] = 0;/*NetHdrFlags::NEEDS_CSUM.bits()*/;
        v[1] = 0;
        LE::write_u16(&mut v[2..], 0);
        LE::write_u16(&mut v[4..], 0);
        LE::write_u16(&mut v[6..], 0);
        LE::write_u16(&mut v[8..], 0);
        LE::write_u16(&mut v[10..], 0);

        self.0.transmit_queues().nth(0).unwrap().push_buffer_r(v);
        self.0.device.notify(1);
        res
    }
}

bitflags! {
    struct NetHdrFlags: u8 {
        const NEEDS_CSUM            = 1 << 0;
        const DATA_VALID            = 1 << 1;
        const RSC_INFO              = 1 << 2;
    }
}

bitflags! {
    struct GsoType: u8 {
        const None = 0;
        const TCPv4 = 1;
        const UDP = 3;
        const TCPv6 = 4;

        const ECN = 0x80;
    }
}

#[repr(C)]
struct NetHdr {
    flags: NetHdrFlags,
    gso_type: GsoType,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
    num_buffers: u16,
}

impl NetHdr {
    fn new_transmission(needs_csum: bool, csum_start: u16, csum_offset: u16) -> NetHdr {
        let mut flags = NetHdrFlags::empty();
        if needs_csum {
            flags |= NetHdrFlags::NEEDS_CSUM;
        }
        NetHdr {
            flags: flags,
            gso_type: GsoType::None,
            hdr_len: 0,
            gso_size: 0,
            csum_start: csum_start.to_le(),
            csum_offset: csum_offset.to_le(),
            num_buffers: 0
        }
    }
}
