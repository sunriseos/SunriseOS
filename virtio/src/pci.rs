use sunrise_libuser::pci::{BAR, MappedBAR};
use byteorder::{LE, NativeEndian, ByteOrder};
use bit_field::BitField;
use sunrise_libuser::error::KernelError;
use sunrise_libuser::pci::capabilities::RWCapability;
use crate::{DeviceStatus, Notification};

#[derive(Debug)]
pub enum Cap {
    /// Common Configuration.
    CommonCfg(CommonCfg),
    /// Notifications.
    NotifyCfg(NotificationCfg),
    /// ISR Status.
    IsrCfg(u8, u64, u64),
    /// Device-specific configuration.
    DeviceCfg(Config),
    /// PCI configuration access.
    PciCfg(u8, u64, u64),
}

impl Cap {
    pub fn read(bars: &[Option<BAR>; 6], data: &RWCapability) -> Result<Option<Cap>, KernelError> {
        let bar = data.read_u32(4).get_bits(0..8) as u8;
        if bar > 5 {
            return Ok(None)
        }

        let offset = data.read_u32(8) as u64;
        let length = data.read_u32(12) as u64;

        match data.read_u32(0).get_bits(24..32) {
            1 => Ok(Some(Cap::CommonCfg(CommonCfg { config: Config {
               bar: bars[bar as usize].unwrap().map()?,
               offset, length
            }}))),
            2 => Ok(Some(Cap::NotifyCfg(NotificationCfg { config: Config {
                bar: bars[bar as usize].unwrap().map()?,
                offset, length
            }, notify_off_multiplier: data.read_u32(16)}))),
            3 => Ok(Some(Cap::IsrCfg(bar, offset, length))),
            4 => Ok(Some(Cap::DeviceCfg(Config {
                bar: bars[bar as usize].unwrap().map()?,
                offset, length
            }))),
            5 => Ok(Some(Cap::PciCfg(bar, offset, length))),
            _ => Ok(None),
        }
    }
}

const DEVICE_FEATURES_SELECT_OFF: u64 = 0;
const DEVICE_FEATURES_OFF: u64 = 4;
const DRIVER_FEATURES_SELECT_OFF: u64 = 8;
const DRIVER_FEATURES_OFF: u64 = 12;
const MSIX_CONFIG_OFF: u64 = 16;
const NUM_QUEUES_OFF: u64 = 18;
const DEVICE_STATUS_OFF: u64 = 20;
const CONFIG_GENERATION_OFF: u64 = 21;
const QUEUE_SELECT_OFF: u64 = 22;
const QUEUE_SIZE_OFF: u64 = 24;
const QUEUE_MSIX_VECTOR_OFF: u64 = 26;
const QUEUE_ENABLE_OFF: u64 = 28;
const QUEUE_NOTIFY_OFF_OFF: u64 = 30;
const QUEUE_DESC_OFF: u64 = 32;
const QUEUE_DRIVER_OFF: u64 = 40;
const QUEUE_DEVICE_OFF: u64 = 48;

#[derive(Debug, Default)]
pub struct Queue {
    pub size: u16,
    pub msix_vector: u16,
    pub enable: bool,
    notify_off: u16,
    pub desc: u64,
    pub driver: u64,
    pub device: u64,
}

#[derive(Clone)]
pub struct QueueIter<'a>(&'a CommonCfg, u16);

impl<'a> Iterator for QueueIter<'a> {
    type Item = Queue;
    fn next(&mut self) -> Option<Queue> {
        if self.1 < self.0.num_queues() {
            let ret = Some(self.0.queue(self.1));
            self.1 += 1;
            ret
        } else {
            None
        }
    }
}

impl<'a> core::fmt::Debug for QueueIter<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_list().entries(self.clone()).finish()
    }
}

#[derive(Debug)]
pub struct Config {
    bar: MappedBAR,
    offset: u64,
    length: u64,
}

impl Config {
    pub fn read_u8(&self, additional_offset: u64) -> u8 {
        assert!(additional_offset < self.length, "OOB Read: {} < {}", additional_offset, self.length);
        self.bar.read_u8(self.offset + additional_offset)
    }

    pub fn write_u8(&self, additional_offset: u64, data: u8) {
        assert!(additional_offset < self.length, "OOB Write: {} < {}", additional_offset, self.length);
        self.bar.write_u8(self.offset + additional_offset, data);
    }
    pub fn read_u16<BO: ByteOrder>(&self, additional_offset: u64) -> u16 {
        assert!(additional_offset.saturating_add(1) < self.length, "OOB Read: {} + 1 < {}", additional_offset, self.length);
        self.bar.read_u16::<BO>(self.offset + additional_offset)
    }

    pub fn write_u16<BO: ByteOrder>(&self, additional_offset: u64, data: u16) {
        assert!(additional_offset.saturating_add(1) < self.length, "OOB Write: {} + 1 < {}", additional_offset, self.length);
        self.bar.write_u16::<BO>(self.offset + additional_offset, data);
    }

    pub fn read_u32<BO: ByteOrder>(&self, additional_offset: u64) -> u32 {
        assert!(additional_offset.saturating_add(3) < self.length, "OOB Read: {} + 3 < {}", additional_offset, self.length);
        self.bar.read_u32::<BO>(self.offset + additional_offset)
    }

    pub fn write_u32<BO: ByteOrder>(&self, additional_offset: u64, data: u32) {
        assert!(additional_offset.saturating_add(3) < self.length, "OOB Write: {} + 3 < {}", additional_offset, self.length);
        self.bar.write_u32::<BO>(self.offset + additional_offset, data);
    }

    pub fn read_u64<BO: ByteOrder>(&self, additional_offset: u64) -> u64 {
        assert!(additional_offset.saturating_add(7) < self.length, "OOB Read: {} + 7 < {}", additional_offset, self.length);
        let lo = self.bar.read_u32::<NativeEndian>(self.offset + additional_offset);
        let hi = self.bar.read_u32::<NativeEndian>(self.offset + additional_offset + 4);
        let mut bytes = [0u8; 8];
        NativeEndian::write_u32(&mut bytes, lo);
        NativeEndian::write_u32(&mut bytes[4..], hi);
        BO::read_u64(&bytes)
    }

    pub fn write_u64<BO: ByteOrder>(&self, additional_offset: u64, data: u64) {
        assert!(additional_offset.saturating_add(7) < self.length, "OOB Write: {} + 7 < {}", additional_offset, self.length);
        let mut bytes = [0; 8];
        BO::write_u64(&mut bytes, data);
        let lo = NativeEndian::read_u32(&bytes);
        let hi = NativeEndian::read_u32(&bytes[4..]);
        self.bar.write_u32::<NativeEndian>(self.offset + additional_offset, lo);
        self.bar.write_u32::<NativeEndian>(self.offset + additional_offset + 4, hi);
    }
}

pub struct CommonCfg {
    config: Config,
}

impl core::fmt::Debug for CommonCfg {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("CommonCfg")
            .field("device_feature_bits", &self.device_feature_bits())
            .field("driver_feature_bits", &self.driver_feature_bits())
            .field("msix_config", &self.msix_config())
            .field("device_status", &self.device_status())
            .field("config_generation", &self.config_generation())
            .field("queues", &self.queues())
            .finish()
    }
}

impl CommonCfg {
    pub fn device_feature_bits(&self) -> u64 {
        self.config.write_u32::<LE>(DEVICE_FEATURES_SELECT_OFF, 0);
        let datalo = self.config.read_u32::<LE>(DEVICE_FEATURES_OFF);
        self.config.write_u32::<LE>(DEVICE_FEATURES_SELECT_OFF, 1);
        let datahi = self.config.read_u32::<LE>(DEVICE_FEATURES_OFF);

        *0u64
            .set_bits(0..32, datalo as u64)
            .set_bits(32..64, datahi as u64)
    }

    pub fn driver_feature_bits(&self) -> u64 {
        self.config.write_u32::<LE>(DRIVER_FEATURES_SELECT_OFF, 0);
        let datalo = self.config.read_u32::<LE>(DRIVER_FEATURES_OFF);
        self.config.write_u32::<LE>(DRIVER_FEATURES_SELECT_OFF, 1);
        let datahi = self.config.read_u32::<LE>(DRIVER_FEATURES_OFF);

        *0u64
            .set_bits(0..32, datalo as u64)
            .set_bits(32..64, datahi as u64)
    }

    pub fn set_driver_features(&mut self, features: u64) {
        self.config.write_u32::<LE>(DRIVER_FEATURES_SELECT_OFF, 0);
        self.config.write_u32::<LE>(DRIVER_FEATURES_OFF, features.get_bits(0..32) as u32);
        self.config.write_u32::<LE>(DRIVER_FEATURES_SELECT_OFF, 1);
        self.config.write_u32::<LE>(DRIVER_FEATURES_OFF, features.get_bits(32..64) as u32);
    }

    pub fn msix_config(&self) -> u16 {
        self.config.read_u16::<LE>(MSIX_CONFIG_OFF)
    }

    pub fn set_msix_config(&mut self, config: u16) {
        self.config.write_u16::<LE>(MSIX_CONFIG_OFF, config);
    }

    pub fn num_queues(&self) -> u16 {
        self.config.read_u16::<LE>(NUM_QUEUES_OFF)
    }

    pub fn device_status(&self) -> DeviceStatus {
        // Maybe use from_bits_truncate? The device isn't supposed to change that field though, so
        // this should never fail. On the other hand... do I want to trust the device? Maybe I should
        // return None, and let the driver put the device in FAILED status.
        DeviceStatus::from_bits(self.config.read_u8(DEVICE_STATUS_OFF)).unwrap()
    }

    /// Sets the new device status bits. The old bits are or'd with the new ones (unless 0 is sent,
    /// which is used to reset the device).
    pub fn set_device_status(&mut self, newflags: DeviceStatus) {
        if newflags.is_empty() {
            self.config.write_u8(DEVICE_STATUS_OFF, 0);
        }
        let oldflags = self.device_status();
        self.config.write_u8(DEVICE_STATUS_OFF, (oldflags | newflags).bits());
    }

    pub fn config_generation(&self) -> u8 {
        self.config.read_u8(CONFIG_GENERATION_OFF)
    }

    fn queues(&self) -> impl Iterator<Item = Queue> + core::fmt::Debug + '_ {
        QueueIter(self, 0)
    }

    pub fn queue(&self, queue_idx: u16) -> Queue {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue_idx);
        Queue {
            size: self.config.read_u16::<LE>(QUEUE_SIZE_OFF),
            msix_vector: self.config.read_u16::<LE>(QUEUE_MSIX_VECTOR_OFF),
            enable: self.config.read_u16::<LE>(QUEUE_ENABLE_OFF) != 0,
            notify_off: self.config.read_u16::<LE>(QUEUE_NOTIFY_OFF_OFF),
            desc: self.config.read_u64::<LE>(QUEUE_DESC_OFF),
            driver: self.config.read_u64::<LE>(QUEUE_DRIVER_OFF),
            device: self.config.read_u64::<LE>(QUEUE_DEVICE_OFF)
        }
    }

    pub fn queue_size(&self, queue: u16) -> u16 {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.read_u16::<LE>(QUEUE_SIZE_OFF)
    }

    pub fn set_queue_size(&self, queue: u16, size: u16) {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.write_u16::<LE>(QUEUE_SIZE_OFF, size);
    }

    pub fn queue_msix_vector(&self, queue: u16) -> u16 {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.read_u16::<LE>(QUEUE_MSIX_VECTOR_OFF)
    }

    pub fn set_queue_msix_vector(&mut self, queue: u16, vector: u16) {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.write_u16::<LE>(QUEUE_MSIX_VECTOR_OFF, vector);
    }

    pub fn queue_enabled(&self, queue: u16) -> bool {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.read_u16::<LE>(QUEUE_ENABLE_OFF) != 0
    }

    pub fn set_queue_enabled(&mut self, queue: u16, enabled: bool) {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.write_u16::<LE>(QUEUE_ENABLE_OFF, enabled as u16);
    }

    pub fn queue_notify_off(&self, queue: u16) -> u16 {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.read_u16::<LE>(QUEUE_NOTIFY_OFF_OFF)
    }

    pub fn queue_desc(&self, queue: u16) -> u64 {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.read_u64::<LE>(QUEUE_DESC_OFF)
    }
    pub fn set_queue_desc(&mut self, queue: u16, off: u64) {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.write_u64::<LE>(QUEUE_DESC_OFF, off);

    }
    pub fn queue_driver(&self, queue: u16) -> u64 {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.read_u64::<LE>(QUEUE_DRIVER_OFF)
    }
    pub fn set_queue_driver(&mut self, queue: u16, off: u64) {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.write_u64::<LE>(QUEUE_DRIVER_OFF, off);

    }
    pub fn queue_device(&self, queue: u16) -> u64 {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.read_u64::<LE>(QUEUE_DEVICE_OFF)
    }
    pub fn set_queue_device(&mut self, queue: u16, off: u64) {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue);
        self.config.write_u64::<LE>(QUEUE_DEVICE_OFF, off);
    }

    pub fn set_queue(&mut self, queue_idx: u16, queue: &Queue) {
        self.config.write_u16::<LE>(QUEUE_SELECT_OFF, queue_idx);
        self.config.write_u16::<LE>(QUEUE_SIZE_OFF, queue.size);
        self.config.write_u16::<LE>(QUEUE_MSIX_VECTOR_OFF, queue.msix_vector);
        self.config.write_u64::<LE>(QUEUE_DESC_OFF, queue.desc);
        self.config.write_u64::<LE>(QUEUE_DRIVER_OFF, queue.driver);
        self.config.write_u64::<LE>(QUEUE_DEVICE_OFF, queue.device);
        // Write enable last.
        self.config.write_u16::<LE>(QUEUE_ENABLE_OFF, queue.enable as u16);
    }
}

#[derive(Debug)]
pub struct NotificationCfg {
    config: Config,
    notify_off_multiplier: u32
}

impl NotificationCfg {
    pub fn notify_with_notification(&self, queue_notify_off: usize, notification: Notification) {
        self.config.write_u32::<LE>(queue_notify_off as u64 * self.notify_off_multiplier as u64, notification.0.to_le())
    }
    pub fn notify_with_virtqueue(&self, queue_notify_off: usize, virtqueue_idx: u16) {
        log::info!("Notifying at {:#010x}, {:#010x?}", queue_notify_off as u64 * self.notify_off_multiplier as u64 + self.config.offset, self.config.bar);
        self.config.write_u16::<LE>(queue_notify_off as u64 * self.notify_off_multiplier as u64, virtqueue_idx.to_le())
    }
}
