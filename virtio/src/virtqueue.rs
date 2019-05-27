use bitflags::bitflags;
use static_assertions::assert_eq_size;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{fence, Ordering};
use core::fmt;
use sunrise_libuser::mem::virt_to_phys;
use log::info;

#[repr(C)]
struct Ptr {
    ptr: usize,
    len: usize,
}

pub struct VirtQueue {
    free_head: usize,
    last_used: u16,
    /// An array of queue_size descriptors
    descriptor_area: Box<[Descriptor]>,
    /// An array matching descriptor_area, which contains the Virtual Address of
    /// the associated descriptor.
    virt_area: Box<[usize]>,
    /// Contains an array of queue_size
    driver_area: Box<Avail>,
    /// Contains an array of queue_size
    device_area: Box<Used>,
}

impl fmt::Debug for VirtQueue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {

        struct DriverRingIterator<'a>(&'a [u16], &'a [Descriptor], u16);
        impl<'a> fmt::Debug for DriverRingIterator<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_list().entries(self.0.iter().map(|v| {
                    (v, self.1.get(*v as usize))
                }).take(self.2 as usize)).finish()
            }
        }

        struct DeviceRingIterator<'a>(&'a [UsedElem], &'a [Descriptor], u16, u16);
        impl<'a> fmt::Debug for DeviceRingIterator<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_list().entries(self.0.iter().map(|v| {
                    (v.id, v.len, self.1.get(v.id as usize))
                }).skip(self.2 as usize).take(self.3 as usize)).finish()
            }
        }

        f.debug_struct("VirtQueue")
            .field("free_head", &self.free_head)
            .field("last_used", &self.last_used)
            .field("driver_area", &self.driver_area)
            .field("driver_area_ring", &DriverRingIterator(self.driver_area.ring(), &*self.descriptor_area, self.driver_area.idx()))
            .field("device_area", &self.device_area)
            .field("device_area_ring", &DeviceRingIterator(self.device_area.ring(), &*self.descriptor_area, self.last_used, self.device_area.idx()))
            .finish()
    }
}

impl VirtQueue {
    pub fn new(queue_size: u16) -> VirtQueue {
        let mut descriptor_area = vec![Descriptor {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }; queue_size as usize].into_boxed_slice();

        for (idx, item) in descriptor_area.iter_mut().enumerate() {
            item.next = (idx as u16 + 1).to_le();
        }

        let driver_area = Avail::new(queue_size);
        let device_area = Used::new(queue_size);

        VirtQueue {
            free_head: 0,
            last_used: 0,
            virt_area: vec![0; queue_size as usize].into_boxed_slice(),
            descriptor_area,
            driver_area,
            device_area
        }
    }

    pub fn len(&self) -> u16 {
        self.descriptor_area.len() as u16
    }

    pub fn descriptor_area_dma_addr(&self) -> u64 {
        let vaddr = &*self.descriptor_area as *const _ as *const u8;
        let paddr = virt_to_phys(vaddr) as u64;
        info!("Getting descriptor DMA ADDR for {:p} => {:#010x}", vaddr, paddr);
        paddr
    }

    pub fn device_area_dma_addr(&self) -> u64 {
        let vaddr = &*self.device_area as *const _ as *const u8;
        let paddr = virt_to_phys(vaddr) as u64;
        info!("Getting device DMA ADDR for {:p} => {:#010x}", vaddr, paddr);
        paddr
    }

    pub fn driver_area_dma_addr(&self) -> u64 {
        let vaddr = &*self.driver_area as *const _ as *const u8;
        let paddr = virt_to_phys(vaddr) as u64;
        info!("Getting driver DMA ADDR for {:p} => {:#010x}", vaddr, paddr);
        paddr
    }

    /// 2.6.13: Supplying Buffers to The Device
    pub fn push_buffer_r(&mut self, mut buf: Vec<u8>) {
        assert!(buf.len() != 0);

        // TODO: Blow up if cur_free_head == EOL marker.
        let cur_free_head = self.free_head;
        self.free_head = u16::from_le(self.descriptor_area[cur_free_head].next) as usize;

        self.descriptor_area[cur_free_head].addr = (virt_to_phys(buf.as_mut_ptr()) as u64).to_le();
        self.virt_area[cur_free_head] = buf.as_ptr() as usize;
        self.descriptor_area[cur_free_head].len = (buf.len() as u32).to_le();
        self.descriptor_area[cur_free_head].flags = DescriptorFlags::empty().bits().to_le();
        self.descriptor_area[cur_free_head].next = 0;
        core::mem::forget(buf);

        self.driver_area.push_buffer(cur_free_head as u16);
    }

    /// 2.6.13: Supplying Buffers to The Device
    pub fn push_buffer_w(&mut self, mut buf: Vec<u8>) {
        assert!(buf.capacity() != 0);

        // TODO: Blow up if cur_free_head == EOL marker.
        let cur_free_head = self.free_head;
        self.free_head = u16::from_le(self.descriptor_area[cur_free_head].next) as usize;

        self.descriptor_area[cur_free_head].addr = (virt_to_phys(buf.as_mut_ptr()) as u64).to_le();
        self.virt_area[cur_free_head] = buf.as_ptr() as usize;
        self.descriptor_area[cur_free_head].len = (buf.capacity() as u32).to_le();
        self.descriptor_area[cur_free_head].flags = DescriptorFlags::WRITE.bits().to_le();
        self.descriptor_area[cur_free_head].next = 0;
        core::mem::forget(buf);

        self.driver_area.push_buffer(self.free_head as u16);
    }

    pub fn pop_buffer_w(&mut self) -> Option<Vec<u8>> {
        if self.last_used != self.device_area.idx() {
            let ring_len = self.device_area.ring().len();
            let used_elem = self.device_area.ring()[self.last_used as usize % ring_len];
            let used_elem_id = used_elem.id as usize;
            assert!(!DescriptorFlags::from_bits_truncate(self.descriptor_area[used_elem_id].flags).contains(DescriptorFlags::NEXT));
            let addr = self.virt_area[used_elem_id];
            let capacity = self.descriptor_area[used_elem_id].len as usize;
            let len = used_elem.len as usize;

            let ret = unsafe {
                Vec::from_raw_parts(addr as *mut u8, len, capacity)
            };

            self.last_used += 1;

            Some(ret)
        } else {
            None
        }
    }

    pub fn get_available_idx(&self) -> u16 {
        self.driver_area.idx()
    }

    pub fn device_notif_suppressed(&self) -> bool {
        self.device_area.flags().contains(UsedFlags::NO_NOTIFY)
    }

    /*pub fn push_buffer_ro(&mut self, buf: &[u8]) -> CompletionToken {
        
    }*/
}

bitflags! {
    struct DescriptorFlags: u16 {
        /// This marks a buffer as continuing via the next field.
        const NEXT = 1;
        /// This marks a buffer as write-only (otherwise read-only).
        const WRITE = 2;
        /// This means the buffer contains a list of buffer descriptors.
        const INDIRECT = 4;
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Descriptor {
    /// Address (guest-physical)
    addr: u64,
    /// Length
    len: u32,
    /// The flags as indicated above
    flags: u16,
    /// We chain unused descriptors via this, too
    next: u16
}

impl fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Descriptor")
            .field("addr", &self.addr())
            .field("len", &self.len())
            .field("flags", &self.flags())
            .field("next", &self.next())
            .finish()
    }
}

impl Descriptor {
    fn addr(&self) -> u64 {
        u64::from_le(self.addr)
    }
    fn len(&self) -> u32 {
        u32::from_le(self.len)
    }
    fn flags(&self) -> DescriptorFlags {
        DescriptorFlags::from_bits_truncate(u16::from_le(self.flags))
    }
    fn next(&self) -> u16 {
        u16::from_le(self.next)
    }
}

assert_eq_size!(Descriptor, [u8; 16]);

bitflags! {
    struct AvailFlags: u16 {
        /// The driver uses this to advise the device: don't kick me when you
        /// add a buffer. It's unreliable, so it's simply an optimization.
        const NO_INTERRUPT = 1;
    }
}

#[repr(C)]
pub struct Avail {
    flags: u16,
    idx: u16,
    // Array of queue_size elements. The last element is reserved for used_event!
    ring_and_used_event: [u16],
}

impl fmt::Debug for Avail {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Avail")
            .field("flags", &self.flags())
            .field("idx", &self.idx())
            //.field("ring", &self.ring())
            .field("used_event", &self.used_event())
            .finish()
    }
}

impl Avail {
    fn new(queue_size: u16) -> Box<Avail> {
        let vec = vec![0u16; queue_size as usize + 3];
        let b = Box::leak(vec.into_boxed_slice());
        unsafe {
            Box::from_raw(core::mem::transmute(Ptr {
                ptr: b as *mut _ as *mut u8 as usize,
                // Ignore flags and idx. Keep used_event in.
                len: b.len() - 2,
            }))
        }
    }

    fn flags(&self) -> AvailFlags {
        AvailFlags::from_bits_truncate(u16::from_le(self.flags))
    }

    fn set_flags(&mut self, flags: AvailFlags) {
        self.flags = flags.bits().to_le();
    }

    fn idx(&self) -> u16 {
        u16::from_le(self.idx)
    }

    fn set_idx(&mut self, idx: u16) {
        fence(Ordering::SeqCst);
        self.idx = idx.to_le();
    }

    fn ring(&self) -> &[u16] {
        &self.ring_and_used_event[..self.ring_and_used_event.len() - 1]
    }

    fn ring_mut(&mut self) -> &mut [u16] {
        let len = self.ring_and_used_event.len();
        &mut self.ring_and_used_event[..len - 1]
    }

    fn used_event(&self) -> u16 {
        u16::from_le(*self.ring_and_used_event.last().unwrap())
    }

    fn push_buffer(&mut self, desc_idx: u16) {
        let len = self.ring_mut().len();
        let idx = self.idx() as usize % len;
        self.ring_mut()[idx] = desc_idx.to_le();
        self.set_idx(self.idx().wrapping_add(1));
    }
}

bitflags! {
    struct UsedFlags: u16 {
        /// The device uses this to advise the driver: don't kick me when you
        /// add a buffer. It's unreliable, so it's simply an optimization.
        const NO_NOTIFY = 1;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem {
    /// Index of start of used descriptor chain.
    id: u32,
    /// Total length of the descriptor chain which was written to.
    len: u32
}

impl UsedElem {
    fn id(&self) -> u32 {
        u32::from_le(self.id)
    }

    fn len(&self) -> u32 {
        u32::from_le(self.len)
    }
}

impl fmt::Debug for UsedElem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Used")
            .field("id", &self.id())
            .field("len", &self.len())
            .finish()
    }
}

union UsedElemOrAvailEvent {
    elem: UsedElem,
    avail_event: u16
}

#[repr(C)]
pub struct Used {
    flags: u16,
    idx: u16,
    // Array of UsedElem. The last element is reserved for avail_event.
    ring_and_avail_event: [UsedElemOrAvailEvent],
}

impl fmt::Debug for Used {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Used")
            .field("flags", &self.flags())
            .field("idx", &self.idx())
            //.field("ring", &self.ring()) // Wrong endianness
            .field("avail_event", &self.avail_event())
            .finish()
    }
}

impl Used {
    fn new(queue_size: u16) -> Box<Used> {
        let vec = vec![0u32; queue_size as usize * 2 + 2];
        let b = Box::leak(vec.into_boxed_slice());
        unsafe {
            Box::from_raw(core::mem::transmute(Ptr {
                ptr: b as *mut _ as *mut u8 as usize,
                // Ignore flags and idx. Keep used_event in.
                len: (b.len() - 1) / 2,
            }))
        }
    }

    fn flags(&self) -> UsedFlags {
        UsedFlags::from_bits_truncate(u16::from_le(self.flags))
    }

    fn idx(&self) -> u16 {
        u16::from_le(self.idx)
    }

    fn ring(&self) -> &[UsedElem] {
        unsafe {
            // Safety:
            let ring = &self.ring_and_avail_event[..self.ring_and_avail_event.len() - 1];
            core::mem::transmute(ring)
        }
    }

    fn avail_event(&self) -> u16 {
        unsafe {
            u16::from_le(self.ring_and_avail_event.last().unwrap().avail_event)
        }
    }
}
