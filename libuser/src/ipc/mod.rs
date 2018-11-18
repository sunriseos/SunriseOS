use core::marker::PhantomData;
use core::mem;
use byteorder::{ByteOrder, LE};
use arrayvec::{ArrayVec, Array};
use utils::{self, align_up, CursorWrite, CursorRead};
use types::{Handle, HandleRef};
use bit_field::BitField;

#[macro_use]
pub mod macros;
pub mod server;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pid(pub u64);

bitfield! {
    /// Represenens the header of an HIPC command.
    ///
    /// The kernel uses this header to figure out how to send the IPC message.
    #[repr(transparent)]
    pub struct MsgPackedHdr(u64);
    impl Debug;
    u16, ty, set_ty: 15, 0;
    u8, num_x_descriptors, set_num_x_descriptors: 19, 16;
    u8, num_a_descriptors, set_num_a_descriptors: 23, 20;
    u8, num_b_descriptors, set_num_b_descriptors: 27, 24;
    u8, num_w_descriptors, set_num_w_descriptors: 31, 28;
    u16, raw_section_size, set_raw_section_size: 41, 32;
    u8, c_descriptor_flags, set_c_descriptor_flags: 45, 42;
    enable_handle_descriptor, set_enable_handle_descriptor: 63;
}

bitfield! {
    #[repr(transparent)]
    pub struct HandleDescriptorHeader(u32);
    impl Debug;
    send_pid, set_send_pid: 0;
    u8, num_copy_handles, set_num_copy_handles: 4, 1;
    u8, num_move_handles, set_num_move_handles: 8, 5;
}

#[derive(Debug, Clone, Copy)]
pub enum IPCBufferType {
    A { flags: u8 },
    B { flags: u8 },
    X { counter: u8 },
    C { has_u16_size: bool },
}

#[derive(Debug, Clone)]
pub struct IPCBuffer<'a> {
    // Address to the value
    addr: usize,
    // Size of the value
    size: usize,
    // Buffer type
    ty: IPCBufferType,
    // Tie the buffer's lifetime to the value's !
    // This is very very very important, for the safety of this interface. It ensures that, as long as
    // this IPCBuffer exist, the value it references cannot be dropped.
    phantom: PhantomData<&'a ()>
}

impl<'a> IPCBuffer<'a> {
    pub fn from_mut_ref<T>(val: &'a mut T, ty: IPCBufferType) -> IPCBuffer {
        // TODO: Verify type and val mutability
        IPCBuffer {
            addr: val as *mut T as usize,
            size: mem::size_of::<T>(),
            ty,
            phantom: PhantomData
        }
    }
    pub fn from_ref<T>(val: &'a T, ty: IPCBufferType) -> IPCBuffer {
        // TODO: Verify type and val mutability
        IPCBuffer {
            addr: val as *const T as usize,
            size: mem::size_of::<T>(),
            ty,
            phantom: PhantomData
        }
    }
    pub fn from_slice<T>(val: &'a [T], ty: IPCBufferType) -> IPCBuffer {
        // TODO: Verify type and val mutability
        IPCBuffer {
            addr: if val.len() == 0 { 0 } else { val.as_ptr() as usize },
            size: mem::size_of::<T>() * val.len(),
            ty,
            phantom: PhantomData
        }
    }
    pub fn from_mut_slice<T>(val: &'a mut [T], ty: IPCBufferType) -> IPCBuffer {
        // TODO: Verify type and val mutability
        IPCBuffer {
            addr: if val.len() == 0 { 0 } else { val.as_ptr() as usize },
            size: mem::size_of::<T>() * val.len(),
            ty,
            phantom: PhantomData
        }
    }

    pub unsafe fn from_ptr_len<T>(val: *const T, len: usize, ty: IPCBufferType) -> IPCBuffer<'static> {
        IPCBuffer {
            addr: val as usize,
            size: mem::size_of::<T>() * len,
            ty,
            phantom: PhantomData
        }
    }

    pub unsafe fn from_mut_ptr_len<T>(val: *mut T, len: usize, ty: IPCBufferType) -> IPCBuffer<'static> {
        IPCBuffer {
            addr: val as usize,
            size: mem::size_of::<T>() * len,
            ty,
            phantom: PhantomData
        }
    }

    // Based on http://switchbrew.org/index.php?title=IPC_Marshalling#Official_marshalling_code
    fn buftype(&self) -> IPCBufferType {
        self.ty
    }
}

pub struct Message<'a, RAW, BUFF = [IPCBuffer<'a>; 0], COPY = [u32; 0], MOVE = [u32; 0]>
where
    BUFF: Array<Item=IPCBuffer<'a>>,
    COPY: Array<Item=u32>,
    MOVE: Array<Item=u32>,
    RAW: Copy + Default,
{
    ty: u16,
    pid: Option<u64>,
    buffers: ArrayVec<BUFF>,
    copy_handles: ArrayVec<COPY>,
    move_handles: ArrayVec<MOVE>,
    is_request: bool,
    cmdid_error: u32,
    token: Option<u32>,
    raw: RAW
}

impl<'a, RAW, BUFF, COPY, MOVE> Message<'a, RAW, BUFF, COPY, MOVE>
where
    BUFF: Array<Item=IPCBuffer<'a>>,
    COPY: Array<Item=u32>,
    MOVE: Array<Item=u32>,
    RAW: Copy + Default
{
    pub fn new_request(token: Option<u32>, cmdid: u32) -> Message<'a, RAW, BUFF, COPY, MOVE> {
        Message {
            ty: 4,
            pid: None,
            buffers: ArrayVec::new(),
            copy_handles: ArrayVec::new(),
            move_handles: ArrayVec::new(),
            is_request: true,
            cmdid_error: cmdid,
            token: token,
            raw: RAW::default()
        }
    }

    pub fn new_response(token: Option<u32>) -> Message<'a, RAW, BUFF, COPY, MOVE> {
        Message {
            ty: 4,
            pid: None,
            buffers: ArrayVec::new(),
            copy_handles: ArrayVec::new(),
            move_handles: ArrayVec::new(),
            is_request: false,
            cmdid_error: 0,
            token: token,
            raw: RAW::default()
        }
    }

    pub fn set_error(&mut self, err: u32) -> &mut Self {
        self.cmdid_error = err;
        self
    }

    pub fn push_raw(&mut self, raw: RAW) -> &mut Self {
        self.raw = raw;
        self
    }

    pub fn raw(&self) -> RAW {
        self.raw
    }

    pub fn token(&self) -> Option<u32> {
        self.token
    }

    pub fn push_handle_move(&mut self, handle: Handle) -> &mut Self {
        self.move_handles.push(handle.0.get());
        mem::forget(handle);
        self
    }

    pub fn push_handle_copy(&mut self, handle: HandleRef) -> &mut Self {
        self.copy_handles.push(handle.inner.get());
        self
    }

    // TODO: Figure out a better API for buffers. This sucks.
    /*fn pop_in_buffer<T>(&mut self) -> InBuffer<T> {
    }*/
    pub fn pop_handle_move(&mut self) -> Handle {
        // TODO: avoid panic, return an error instead.
        Handle::new(self.move_handles.remove(0))
    }

    pub fn pop_handle_copy(&mut self) -> Handle {
        // TODO: avoid panic, return an error instead.
        Handle::new(self.move_handles.remove(0))
    }

    pub fn pop_pid(&mut self) -> Pid {
        Pid(self.pid.take().unwrap())
    }


    pub fn pack(self, data: &mut [u8]) {
        let (
            mut descriptor_count_x,
            mut descriptor_count_a,
            mut descriptor_count_b,
            mut descriptor_count_c) = (/* X */0, /* A */0, /* B */0, /* C */0);

        for bufty in self.buffers.iter().map(|b| b.buftype()) {
            match bufty {
                IPCBufferType::X {counter: _} => descriptor_count_x += 1,
                IPCBufferType::A {flags: _} => descriptor_count_a += 1,
                IPCBufferType::B {flags: _} => descriptor_count_b += 1,
                IPCBufferType::C {has_u16_size: _} => descriptor_count_c += 1,
            }
        }

        // TODO: Memset data first
        let mut cursor = CursorWrite::new(data);

        // Get the header.
        {
            let mut hdr = MsgPackedHdr(0);
            hdr.set_ty(self.ty);
            hdr.set_num_x_descriptors(descriptor_count_x);
            hdr.set_num_a_descriptors(descriptor_count_a);
            hdr.set_num_b_descriptors(descriptor_count_b);
            hdr.set_num_w_descriptors(0);
            if descriptor_count_c == 0 {
                hdr.set_c_descriptor_flags(0);
            } else if descriptor_count_c == 1 {
                hdr.set_c_descriptor_flags(2);
            } else {
                hdr.set_c_descriptor_flags(2 + descriptor_count_c as u8);
            }

            // 0x10 = padding, 8 = sfci, 8 = cmdid, data = T
            let raw_section_size =
                0x10 + 8 + 8 + mem::size_of::<RAW>() +
                //domain_id.map(|v| 0x10).unwrap_or(0) +
                (self.buffers.iter().filter(|v| if let IPCBufferType::C { has_u16_size: true } = v.ty { true } else { false }).count() * 2);

            /*if domain_id.is_some() {
                // Domain Header.
                // TODO: Input ObjectIDs
                raw_section_size += 0x10;
        }*/

            // C descriptor u16 sizes

            hdr.set_raw_section_size(utils::div_ceil(raw_section_size, 4) as u16);
            let enable_handle_descriptor = self.copy_handles.len() > 0 ||
                self.move_handles.len() > 0 || self.pid.is_some();
            hdr.set_enable_handle_descriptor(enable_handle_descriptor);

            let hdr = cursor.write_u64::<LE>(hdr.0);
        }

        // First, write the handle descriptor
        if self.copy_handles.len() > 0 || self.move_handles.len() > 0 || self.pid.is_some() {
            // Handle Descriptor Header
            {
                let mut descriptor_hdr = HandleDescriptorHeader(0);

                // Write the header
                descriptor_hdr.set_num_copy_handles(self.copy_handles.len() as u8);
                descriptor_hdr.set_num_move_handles(self.move_handles.len() as u8);
                descriptor_hdr.set_send_pid(self.pid.is_some());
                cursor.write_u32::<LE>(descriptor_hdr.0);
            }

            // Seek 8 if we have to send pid. We don't actually write the pid.
            if let Some(pid) = self.pid {
                cursor.write_u64::<LE>(pid);
            }

            // Write copy and move handles
            for hnd in self.copy_handles {
                cursor.write_u32::<LE>(hnd);
            }

            for hnd in self.move_handles {
                cursor.write_u32::<LE>(hnd);
            }
        }

        // X descriptors
        {
            for buf in self.buffers.iter() {
                let (addr, size, counter) = match buf.buftype() {
                    IPCBufferType::X { counter } => (buf.addr, buf.size, counter),
                    _ => continue
                };

                assert!(addr >> 39 == 0, "Invalid buffer address");
                assert!(size >> 16 == 0, "Invalid buffer size");
                assert!(counter & !0b1111 == 0, "Invalid counter");
                let num = *(counter.get_bits(0..4) as u32)
                    .set_bits(6..9, addr.get_bits(36..39) as u32)
                    .set_bits(12..16, addr.get_bits(32..36) as u32)
                    .set_bits(16..32, size as u32);
                cursor.write_u32::<LE>(num);
                cursor.write_u32::<LE>((addr & 0xFFFFFFFF) as u32);
            }
        }

        // A descriptors
        for buf in self.buffers.iter() {
            let (addr, size, flags) = match buf.buftype() {
                IPCBufferType::A {flags} => (buf.addr, buf.size, flags),
                _ => continue
            };

            assert!(addr >> 39 == 0, "Invalid buffer address");
            assert!(size >> 35 == 0, "Invalid buffer size");

            cursor.write_u32::<LE>((size & 0xFFFFFFFF) as u32);
            cursor.write_u32::<LE>((addr & 0xFFFFFFFF) as u32);

            let num = flags as usize
                | ((addr >> 36) & 0b111) << 2
                | ((size >> 32) & 0b1111) << 24
                | ((addr >> 32) & 0b1111) << 28;
            cursor.write_u32::<LE>(num as u32);
        }

        // B descriptors
        for buf in self.buffers.iter() {
            let (addr, size, flags) = match buf.buftype() {
                IPCBufferType::B {flags} => (buf.addr, buf.size, flags),
                _ => continue
            };
            assert!(addr >> 39 == 0, "Invalid buffer address");
            assert!(size >> 35 == 0, "Invalid buffer size");

            cursor.write_u32::<LE>((size & 0xFFFFFFFF) as u32);
            cursor.write_u32::<LE>((addr & 0xFFFFFFFF) as u32);

            let num = flags as usize
                | ((addr >> 36) & 0b111) << 2
                | ((size >> 32) & 0b1111) << 24
                | ((addr >> 32) & 0b1111) << 28;
            cursor.write_u32::<LE>(num as u32);
        }

        // TODO: W descriptors would go there.

        // Align to 16-byte boundary
        let before_pad = align_up(cursor.pos(), 16) - cursor.pos();
        cursor.skip_write(before_pad);

        // TODO: Domains
        /*if let Some(obj) = domain_id {
            {
                let hdr = cursor.skip_write(mem::size_of::<DomainMessageHeader>());
                let hdr = unsafe {
                    (hdr.as_mut_ptr() as *mut DomainMessageHeader).as_mut().unwrap()
                };
                hdr.set_command(1);
                hdr.set_input_object_count(0);
                hdr.set_data_len(mem::size_of::<RAW>() as u16 + 0x10);
            }
            cursor.write_u32::<LE>(obj);
            // Apparently this is some padding. :shrug:
            cursor.write_u64::<LE>(0);
    }*/
        if self.is_request {
            cursor.write(b"SFCI");
        } else {
            cursor.write(b"SFCO");
        }
        // If we have a token, use command version 1. Otherwise, send version 0.
        cursor.write_u32::<LE>(self.token.map(|v| 1).unwrap_or(0));

        cursor.write_u32::<LE>(self.cmdid_error);

        // Send the token if we have one, or zero.
        cursor.write_u32::<LE>(self.token.unwrap_or(0));

        cursor.write_raw(self.raw);

        // Write input object IDs. For now: none.

        // Total padding should be 0x10
        cursor.skip_write(0x10 - before_pad);


        // C descriptor u16 length list
        let mut i = 0;
        for buf in self.buffers.iter() {
            let buf = match buf.buftype() {
                IPCBufferType::C { has_u16_size: true } => buf,
                _ => continue
            };

            if buf.size >> 16 != 0 {
                panic!("Invalid buffer size {:x}", buf.size);
            }

            cursor.write_u16::<LE>((buf.size) as u16);
            i += 1;
        }

        // Align to u32
        if i % 2 == 1 {
            cursor.skip_write(2);
        }

        for buf in self.buffers.iter() {
            let buf = match buf.buftype() {
                IPCBufferType::C { has_u16_size: _ } => buf,
                _ => continue
            };

            assert_eq!(buf.addr >> 48, 0, "Invalid address {:x}", buf.addr);
            assert_eq!(buf.size >> 16, 0, "Invalid size {:x}", buf.size);

            cursor.write_u32::<LE>(buf.addr as u32);
            cursor.write_u32::<LE>((buf.addr >> 32) as u32 | (buf.size as u32) << 16);
        }
    }

    pub fn unpack(data: &[u8]) -> Message<'a, RAW, BUFF, COPY, MOVE> {

        let cursor = CursorRead::new(data);

        let hdr = MsgPackedHdr(cursor.read_u64::<LE>());

        let ty = hdr.ty();
        let mut pid = None;
        let mut copy_handles = ArrayVec::new();
        let mut move_handles = ArrayVec::new();
        let mut buffers = ArrayVec::new();

        // First, read the handle descriptor
        if hdr.enable_handle_descriptor() {
            let descriptor_hdr = HandleDescriptorHeader(cursor.read_u32::<LE>());

            if descriptor_hdr.send_pid() {
                pid = Some(cursor.read_u64::<LE>());
            }
            for _ in 0..descriptor_hdr.num_copy_handles() {
                copy_handles.push(cursor.read_u32::<LE>());
            }
            for _ in 0..descriptor_hdr.num_move_handles() {
                move_handles.push(cursor.read_u32::<LE>());
            }
        }

        // Then take care of the buffers
        for _ in 0..hdr.num_x_descriptors() {
            // skip 2 words
            let stuffed = cursor.read_u32::<LE>();
            let laddr = cursor.read_u32::<LE>();
            let addr = *(laddr as u64)
                .set_bits(32..36, stuffed.get_bits(12..16) as u64)
                .set_bits(36..39, stuffed.get_bits(6..9) as u64) as usize;
            let size = stuffed.get_bits(16..32) as usize;
            let counter = stuffed.get_bits(0..4) as u8;
            buffers.push(IPCBuffer { addr, size, ty: IPCBufferType::X { counter }, phantom: PhantomData });
        }
        for i in 0..hdr.num_a_descriptors() + hdr.num_b_descriptors() + hdr.num_w_descriptors() {
            // Skip 3 words
            let lsize = cursor.read_u32::<LE>();
            let laddr = cursor.read_u32::<LE>();
            let stuff = cursor.read_u32::<LE>();
            let addr = *(laddr as u64)
                .set_bits(32..36, stuff.get_bits(28..32) as u64)
                .set_bits(36..39, stuff.get_bits(2..5) as u64) as usize;
            let size = *(lsize as u64)
                .set_bits(32..36, stuff.get_bits(24..28) as u64) as usize;
            let flags = stuff.get_bits(0..2) as u8;

            let ty = if i < hdr.num_a_descriptors() {
                IPCBufferType::A { flags }
            } else if i < hdr.num_a_descriptors() + hdr.num_b_descriptors() {
                IPCBufferType::B { flags }
            } else {
                panic!("Unsupported W descriptor");
                //IPCBufferType::W { flags }
            };

            buffers.push(IPCBuffer { addr, size, ty, phantom: PhantomData });
        }

        // Finally, read the raw section
        // TODO: Domain
        // Align to 16-byte boundary
        let before_pad = align_up(cursor.pos(), 16) - cursor.pos();
        cursor.skip_read(before_pad);

        /*let input_objects = if this.domain_obj.is_some() {
            // Response have a "weird" domain header, at least in mephisto.
            //assert_eq!(domain_hdr.get_data_len() as usize, mem::size_of::<T>() + 8 + 8);
            // raw section size = Padding + domain header + SFCO/errcode + data size
            let input_objects = cursor.read_u32::<LE>() as usize;
            assert_eq!(hdr.get_raw_section_size() as u64, div_ceil((0x10 + 0x10 + 0x10 + mem::size_of::<T>() as usize + input_objects * 4) as u64, 4), "Invalid raw data size for domain");
            let _domain_id = cursor.read_u32::<LE>();
            cursor.skip_read(8);
            Some(input_objects)
        } else { None };*/

        // Find SFCO
        let is_request = match cursor.skip_read(4) {
            b"SFCI" => true,
            b"SFCO" => false,
            _ => panic!("Invalid request magic!")
        };
        let version = cursor.read_u32::<LE>();
        assert!(version <= 1, "Unsupported version");

        let cmdid_error = cursor.read_u32::<LE>();
        // Unused in version == 0 and domain messages in official code. Doesn't hurt to keep it anyways.
        let tokenval = cursor.read_u32::<LE>();
        let token = if version == 1 {
            Some(tokenval)
        } else {
            None
        };

        /*if this.domain_obj.is_none() {
        assert_eq!(hdr.get_raw_section_size() as usize, (mem::size_of::<T>() + 8 + 8 + 0x10) / 4);
    }*/
        let raw = cursor.read_raw::<RAW>();

        /*if let Some(input_objects) = input_objects {
            for _ in 0..input_objects {
                this.objects.push(cursor.read_u32::<LE>());
            }
        }*/
        // Total padding should be 0x10
        cursor.skip_read(0x10 - before_pad);

        // TODO: Read the end

        Message {
            ty,
            pid,
            buffers,
            copy_handles,
            move_handles,
            is_request,
            cmdid_error,
            token,
            raw
        }
    }
}

fn find_ty_cmdid(buf: &[u8]) -> (u16, u32) {
    let hdr = LE::read_u64(&buf[0..8]);
    let ty = hdr.get_bits(0..16) as u16;
    let x_descs = hdr.get_bits(16..20) as usize;
    let a_descs = hdr.get_bits(20..24) as usize;
    let b_descs = hdr.get_bits(24..28) as usize;
    let w_descs = hdr.get_bits(28..32) as usize;
    let (pid, copyhandles, movehandles) = if hdr.get_bit(63) {
        let dsc = LE::read_u32(&buf[8..12]);
        (dsc.get_bit(0) as usize, dsc.get_bits(1..5) as usize, dsc.get_bits(5..9) as usize)
    } else {
        (0, 0, 0)
    };
    let raw = 8 + (hdr.get_bit(63) as usize) * 4 + pid * 8 + (copyhandles + movehandles) * 4 + (x_descs * 8 + (a_descs + b_descs + w_descs) * 12);
    let raw = align_up(raw, 16) + 8;
    let cmdid = LE::read_u32(&buf[raw..raw + 4]);
    (ty, cmdid)
}

