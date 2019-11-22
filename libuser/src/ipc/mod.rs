//! # Core IPC Routines
//!
//! Horizon/OS is a microkernel. And what would be a microkernel without an
//! appropriately overengineered IPC layer? The IPC layer of Horizon/NX is split
//! in two parts: Cmif and Hipc. Cmif is the low-level IPC layer implemented by
//! the kernel. Its job is to move handles from the sender to the receiver, move
//! buffers using the appropriate method, and copy the data section over.
//!
//! The Hipc layer is responsible for the format of the Raw data section. It
//! expects the SFCI/SFCO header, the cmdid at a certain location, and handles
//! domains.
//!
//! In libuser, we don't make a proper distinction between Cmif and Hipc. Both
//! are implemented in the same layer, which is backed by the Message structure.

use core::convert::TryInto;
use core::marker::PhantomData;
use core::mem;
use core::convert::TryFrom;
use byteorder::LE;
use arrayvec::{ArrayVec, Array};
use crate::utils::{self, align_up, CursorWrite, CursorRead};
use crate::types::{Handle, HandleRef, Pid};
use bit_field::BitField;
use crate::error::{Error, LibuserError};

pub mod server;

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
    /// Part of an HIPC command. Sent only when
    /// `MsgPackedHdr::enable_handle_descriptor` is true.
    #[repr(transparent)]
    pub struct HandleDescriptorHeader(u32);
    impl Debug;
    send_pid, set_send_pid: 0;
    u8, num_copy_handles, set_num_copy_handles: 4, 1;
    u8, num_move_handles, set_num_move_handles: 8, 5;
}

/// Type of an IPC Buffer. Depending on the type, the kernel will either map it
/// in the remote process, or memcpy its content.
#[derive(Debug, Clone, Copy)]
pub enum IPCBufferType {
    /// Send Buffer.
    A {
        // TODO: Type-safe IPCBufferType flags.
        // BODY: Currently, IPCBufferType flags are encoded on an u8. However, it
        // BODY: can only have one of three values: 0, 1 and 3. We should
        // BODY: represent it as an enum or enum_with_val instead.
        /// Determines what MemoryState to use with the mapped memory in the
        /// sysmodule. Used to enforce whether or not device mapping is allowed
        /// for src and dst buffers respectively.
        ///
        /// - 0: Device mapping *not* allowed for src or dst.
        /// - 1: Device mapping allowed for src and dst.
        /// - 3: Device mapping allowed for src but not for dst.
        flags: u8
    },
    /// Receive Buffer.
    B {
        /// Determines what MemoryState to use with the mapped memory in the
        /// sysmodule. Used to enforce whether or not device mapping is allowed
        /// for src and dst buffers respectively.
        ///
        /// - 0: Device mapping *not* allowed for src or dst.
        /// - 1: Device mapping allowed for src and dst.
        /// - 3: Device mapping allowed for src but not for dst.
        flags: u8
    },
    /// SendReceive Buffer.
    W {
        /// Determines what MemoryState to use with the mapped memory in the
        /// sysmodule. Used to enforce whether or not device mapping is allowed
        /// for src and dst buffers respectively.
        ///
        /// - 0: Device mapping *not* allowed for src or dst.
        /// - 1: Device mapping allowed for src and dst.
        /// - 3: Device mapping allowed for src but not for dst.
        flags: u8
    },
    /// Pointer.
    X {
        /// The index of the C buffer to copy this pointer into.
        counter: u8
    },
    /// Receive List.
    C {
        /// If true, the size of the receive list should be written in the
        /// request raw data.
        has_u16_size: bool
    },
}

impl IPCBufferType {
    /// Checks if this buffer is a Send Buffer.
    fn is_type_a(self) -> bool {
        if let IPCBufferType::A { .. } = self {
            true
        } else {
            false
        }
    }

    /// Checks if this buffer is a Receive Buffer.
    fn is_type_b(self) -> bool {
        if let IPCBufferType::B { .. } = self {
            true
        } else {
            false
        }
    }

    /// Checks if this buffer is a SendReceive Buffer.
    fn is_type_w(self) -> bool {
        if let IPCBufferType::W { .. } = self {
            true
        } else {
            false
        }
    }

    /// Checks if this buffer is a Pointer Buffer.
    fn is_type_x(self) -> bool {
        if let IPCBufferType::X { .. } = self {
            true
        } else {
            false
        }
    }
}

/// An IPC Buffer represents a section of memory to send to the other side of the
/// pipe. It is usually used for sending big chunks of data that would not send
/// in the comparatively small argument area (which is usually around 200 bytes).
///
/// There exists 5 types of IPC Buffers: Send(A), Receive(B), SendReceive(W),
/// Pointer(X) and ReceiveList(C).
///
/// Send/Receive/SendReceive buffers work by remapping the memory from the
/// sender's process into the receiver's process. This means that they need to
/// have a page-aligned address and size.
///
/// In contrast, Pointer/ReceiveList buffers work by memcpying the sender's
/// Pointer buffer into the receiver's ReceiveList buffer. This allows greater
/// flexibility on the address and size. In general, those are prefered.
#[derive(Debug, Clone)]
pub struct IPCBuffer<'a> {
    /// Address to the value
    addr: u64,
    /// Size of the value
    size: u64,
    /// Buffer type
    ty: IPCBufferType,
    /// Tie the buffer's lifetime to the value's !
    /// This is very very very important, for the safety of this interface. It ensures that, as long as
    /// this IPCBuffer exist, the value it references cannot be dropped.
    phantom: PhantomData<&'a ()>
}

/// Util used for IPC buffer sizing.
pub trait SizedIPCBuffer {
    /// Return the size of the type.
    fn size(&self) -> usize;

    /// Check if the address and size are correct.
    fn is_cool(addr: usize, size: usize) -> bool;

    /// Create a reference to a ipc buffer from an address and a byte size. [see](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html)
    unsafe fn from_raw_parts<'a>(addr: usize, size: usize) -> &'a Self;

    /// Create a mutable reference to a ipc buffer from an address and a byte size. [see](https://doc.rust-lang.org/std/slice/fn.from_raw_parts_mut.html)
    unsafe fn from_raw_parts_mut<'a>(addr: usize, size: usize) -> &'a mut Self;
}

impl<T> SizedIPCBuffer for T {
    fn size(&self) -> usize {
        core::mem::size_of::<T>()
    }

    fn is_cool(addr: usize, size: usize) -> bool {
        size == core::mem::size_of::<T>() &&
            (addr % core::mem::align_of::<T>()) == 0
    }

    unsafe fn from_raw_parts<'a>(addr: usize, _size: usize) -> &'a Self {
        (addr as *const T).as_ref().unwrap()
    }

    unsafe fn from_raw_parts_mut<'a>(addr: usize, _size: usize) -> &'a mut Self {
        (addr as *mut T).as_mut().unwrap()
    }
}

impl<T> SizedIPCBuffer for [T] {
    fn size(&self) -> usize {
        core::mem::size_of::<T>() * self.len()
    }

    fn is_cool(addr: usize, size: usize) -> bool {
        size % core::mem::size_of::<T>() == 0 &&
           (addr % core::mem::align_of::<T>()) == 0
    }

    unsafe fn from_raw_parts<'a>(addr: usize, size: usize) -> &'a Self {
        core::slice::from_raw_parts(addr as *const T, size / core::mem::size_of::<T>())
    }

    unsafe fn from_raw_parts_mut<'a>(addr: usize, size: usize) -> &'a mut Self {
        core::slice::from_raw_parts_mut(addr as *mut T, size / core::mem::size_of::<T>())
    }
}

impl<'a> IPCBuffer<'a> {
    /// Creates a Type-A IPCBuffer from the given reference.
    fn out_buffer<T: SizedIPCBuffer + ?Sized>(data: &T, flags: u8) -> IPCBuffer {
        IPCBuffer {
            addr: data as *const T as *const u8 as usize as u64,
            // The dereference is necessary because &T implements SizedIPCBuffer too...
            size: (*data).size() as u64,
            ty: IPCBufferType::A {
                flags
            },
            phantom: PhantomData
        }
    }

    /// Creates a Type-B IPCBuffer from the given reference.
    fn in_buffer<T: SizedIPCBuffer + ?Sized>(data: &mut T, flags: u8) -> IPCBuffer {
        IPCBuffer {
            addr: data as *mut T as *const u8 as usize as u64,
            // The dereference is necessary because &T implements SizedIPCBuffer too...
            size: (*data).size() as u64,
            ty: IPCBufferType::B {
                flags
            },
            phantom: PhantomData
        }
    }

    /// Creates a Type-C IPCBuffer from the given reference.
    ///
    /// If has_u16_size is true, the size of the pointer will be written after
    /// the raw data. This is only used when sending client-sized arrays.
    fn in_pointer<T: SizedIPCBuffer + ?Sized>(data: &mut T, has_u16_size: bool) -> IPCBuffer {
        IPCBuffer {
            addr: data as *mut T as *const u8 as usize as u64,
            // The dereference is necessary because &T implements SizedIPCBuffer too...
            size: (*data).size() as u64,
            ty: IPCBufferType::C {
                has_u16_size
            },
            phantom: PhantomData
        }
    }

    /// Creates a Type-X IPCBuffer from the given reference.
    ///
    /// The counter defines which type-C buffer this should be copied into.
    fn out_pointer<T: SizedIPCBuffer + ?Sized>(data: &T, counter: u8) -> IPCBuffer {
        IPCBuffer {
            addr: data as *const T as *const u8 as usize as u64,
            // The dereference is necessary because &T implements SizedIPCBuffer too...
            size: (*data).size() as u64,
            ty: IPCBufferType::X {
                counter
            },
            phantom: PhantomData
        }
    }

    // Based on http://switchbrew.org/index.php?title=IPC_Marshalling#Official_marshalling_code
    /// Gets the [IPCBufferType] of this buffer. The buffer type determines how
    /// the buffer is passed to the other process and if it's an argument or a
    /// return value.
    fn buftype(&self) -> IPCBufferType {
        self.ty
    }
}

/// Type of an IPC message.
#[derive(Debug)]
pub enum MessageTy {
    /// Requests the other end to close the handle and any resource associated
    /// with it. Normally called when dropping the ClientSession.
    Close,
    /// A normal request.
    Request,
    /// A request handled by the server handler. See [switchbrew] for information
    /// on which functions can be called.
    ///
    /// [switchbrew]: https://switchbrew.org/w/index.php?title=IPC_Marshalling#Control
    Control,
}

/// A generic IPC message, representing either an IPC Request or an IPC Response.
///
/// In order to ensure performance, the request lives entirely on the stack, no
/// heap allocation is done. However, if we allowed the maximum sizes for
/// everything, this structure would be over-sized, spanning a page. In order to
/// avoid this, we allow the user to set the size of the various parameters they
/// need.
///
/// When sending a request that needs to send a COPY handle, the user is expected
/// to create a message specifying the COPY count through the type argument,
/// e.g.
///
/// ```
/// use sunrise_libuser::ipc::Message;
/// let msg = Message::<(), [_; 0], [_; 1], [_; 0]>::new_request(None, 1);
/// ```
///
/// The ugly syntax, while unfortunate, is a necessary evil until const generics
/// happen.
#[derive(Debug)]
pub struct Message<'a, RAW, BUFF = [IPCBuffer<'a>; 0], COPY = [u32; 0], MOVE = [u32; 0]>
where
    BUFF: Array<Item=IPCBuffer<'a>>,
    COPY: Array<Item=u32>,
    MOVE: Array<Item=u32>,
    RAW: Copy,
{
    /// Type of the message. This is derived from [MessageTy] and
    /// [Message::token].
    ty: u16,
    /// Optional PID included in the message. For outgoing messages, the actual
    /// value is not relevant, as the kernel will replace it with the sender's
    /// pid.
    pid: Option<u64>,
    /// Array of IPC Buffers included in the message.
    ///
    /// The user may configure the size of this array in the type, allowing
    /// precise control over the size of the Message type.
    buffers: ArrayVec<BUFF>,
    /// Array of copy handles included in the message. Copy handles are copied
    /// from the sender's process into the receiver's process. The sender and
    /// receiver may both use their respective handles.
    ///
    /// The user may configure the size of this array in the type, allowing
    /// precise control over the size of the Message type.
    copy_handles: ArrayVec<COPY>,
    /// Array of move handles included in the message. Move handles are moved
    /// from the sender's process into the receiver's process. The sender loses
    /// control over the handle, as if it had been closed.
    ///
    /// The user may configure the size of this array in the type, allowing
    /// precise control over the size of the Message type.
    move_handles: ArrayVec<MOVE>,
    /// Whether this message contains an IPC request or an IPC response.
    is_request: bool,
    /// Contains either the cmdid (if this message is a request) or an error
    /// number (if this message is a response).
    cmdid_error: u32,
    /// Optional tracking token. This is used to track the origin of each IPC
    /// call. Generally, the creating application will chose a random token when
    /// doing its request. Services will then use that token when they need to
    /// make their own requests.
    token: Option<u32>,
    /// The raw arguments included in this message.
    raw: Option<RAW>
}

impl<'a, RAW, BUFF, COPY, MOVE> Message<'a, RAW, BUFF, COPY, MOVE>
where
    BUFF: Array<Item=IPCBuffer<'a>>,
    COPY: Array<Item=u32>,
    MOVE: Array<Item=u32>,
    RAW: Copy
{
    /// Create a new request for the given cmdid. If a token is passed, the new
    /// IPC version will be used. The tokens allow for tracking an IPC request
    /// chain. The raw data will contain the default value, and all arrays will
    /// be empty.
    pub fn new_request(token: Option<u32>, cmdid: u32) -> Message<'a, RAW, BUFF, COPY, MOVE> {
        Message {
            ty: token.map(|_| 6).unwrap_or(4),
            pid: None,
            buffers: ArrayVec::new(),
            copy_handles: ArrayVec::new(),
            move_handles: ArrayVec::new(),
            is_request: true,
            cmdid_error: cmdid,
            token: token,
            raw: None
        }
    }

    /// Create a new empty reply. If the request this reply is created for had a
    /// token, it should be passed here. The raw data will contain the default
    /// value, and all arrays will be empty.
    pub fn new_response(token: Option<u32>) -> Message<'a, RAW, BUFF, COPY, MOVE> {
        Message {
            ty: token.map(|_| 6).unwrap_or(4),
            pid: None,
            buffers: ArrayVec::new(),
            copy_handles: ArrayVec::new(),
            move_handles: ArrayVec::new(),
            is_request: false,
            cmdid_error: 0,
            token: token,
            raw: None
        }
    }

    /// Sets the message type.
    pub fn set_ty(&mut self, ty: MessageTy) -> &mut Self {
        match (ty, self.token) {
            (MessageTy::Close, _) => self.ty = 2,
            (MessageTy::Request, Some(_)) => self.ty = 4,
            (MessageTy::Request, None) => self.ty = 6,
            (MessageTy::Control, Some(_)) => self.ty = 5,
            (MessageTy::Control, None) => self.ty = 7,
        }
        self
    }

    /// Set the error code from a reply.
    ///
    /// # Panics
    ///
    /// Panics if the message is a request.
    pub fn set_error(&mut self, err: u32) -> &mut Self {
        assert!(!self.is_request, "Attempted to set the error of a request. This operation is only valid for replies.");
        self.cmdid_error = err;
        self
    }

    /// Get the error code from a reply.
    ///
    /// # Panics
    ///
    /// Panics if the message is a request.
    pub fn error(&self) -> Result<(), Error> {
        assert!(!self.is_request, "Attempted to get the error of a request. This operation is only valid for replies.");
        if self.cmdid_error == 0 {
            Ok(())
        } else {
            Err(Error::from_code(self.cmdid_error))
        }
    }

    /// Sets the raw data of the message.
    pub fn push_raw(&mut self, raw: RAW) -> &mut Self {
        self.raw = Some(raw);
        self
    }

    /// Gets the raw data of the message.
    pub fn raw(&self) -> RAW {
        self.raw.unwrap()
    }

    /// Gets the token of a message. This token is used to track IPC call chains.
    /// Only present on newer IPC request types.
    pub fn token(&self) -> Option<u32> {
        self.token
    }

    // TODO: IPC Message::push_move_handle might cause handle leak
    // BODY: The push_move_handle function immediately downcasts the handle to
    // BODY: a mere int, and forgets the (droppable) handle. This might cause a
    // BODY: leak if the underlying IPC message is not sent. It'd be better to
    // BODY: keep the handle around as long as possible. In fact, closing the
    // BODY: handle after it's been moved might not be such a bad idea. After
    // BODY: all, handles are guaranteed not to get reused.
    /// Move a handle over IPC. Once the message is sent, the handle will not
    /// exist in the current process anymore.
    ///
    /// # Note
    ///
    /// The handle is forgotten as soon as this function is called. If the
    /// message is never sent, then the handle will never be closed, causing a
    /// handle leak! Furthermore, IPC errors might cause similar problems.
    ///
    /// # Panics
    ///
    /// Panics if attempting to push more handles than there is space for in this
    /// message.
    pub fn push_handle_move(&mut self, handle: Handle) -> &mut Self {
        self.move_handles.push(handle.0.get());
        mem::forget(handle);
        self
    }

    /// Copy a handle over IPC. The remote process will have a handle that points
    /// to the same object.
    ///
    /// # Panics
    ///
    /// Panics if attempting to push more handles than there is space for in this
    /// message.
    pub fn push_handle_copy(&mut self, handle: HandleRef<'_>) -> &mut Self {
        self.copy_handles.push(handle.inner.get());
        self
    }

    /// Retrieve a moved handle from this IPC message. Those are popped in the
    /// order they were inserted.
    ///
    /// # Errors
    ///
    /// Returns an InvalidMoveHandleCount if attempting to pop more handles than
    /// this message has.
    pub fn pop_handle_move(&mut self) -> Result<Handle, Error> {
        self.move_handles.pop_at(0)
            .map(Handle::new)
            .ok_or_else(|| LibuserError::InvalidMoveHandleCount.into())
    }

    /// Retrieve a copied handle from this IPC message. Those are popped in the
    /// order they were inserted.
    ///
    /// # Errors
    ///
    /// Returns an InvalidCopyHandleCount if attempting to pop more handles than
    /// this message has.
    pub fn pop_handle_copy(&mut self) -> Result<Handle, Error> {
        self.copy_handles.pop_at(0)
            .map(Handle::new)
            .ok_or_else(|| LibuserError::InvalidCopyHandleCount.into())
    }

    /// Retrieve the PID of the remote process (if sent at all). This message
    /// should only be called once.
    ///
    /// # Errors
    ///
    /// Returns a PidMissing if attempting to pop a Pid from a message that has
    /// none, or if attempting to pop a Pid twice.
    pub fn pop_pid(&mut self) -> Result<Pid, Error> {
        self.pid.take()
            .map(Pid)
            .ok_or_else(|| LibuserError::PidMissing.into())
    }

    /// Retreive the next InBuffer (type-A buffer) in the message.
    ///
    /// # Errors
    ///
    /// Returns an InvalidIpcBufferCount if not enough buffers are present
    ///
    /// Returns an InvalidIpcBuffer if the next buffer was not of the appropriate
    /// size.
    ///
    /// # Safety
    ///
    /// This method is unsafe as it allows creating references to arbitrary
    /// memory, and of arbitrary type.
    pub unsafe fn pop_in_buffer<'b, T: SizedIPCBuffer + ?Sized>(&mut self) -> Result<&'b T, Error> {
        let buffer = self.buffers.iter().position(|buf| buf.buftype().is_type_a())
            .and_then(|pos| self.buffers.pop_at(pos))
            .ok_or_else(|| LibuserError::InvalidIpcBufferCount)?;

        let addr = usize::try_from(buffer.addr).map_err(|_| LibuserError::InvalidIpcBuffer)?;
        let size = usize::try_from(buffer.size).map_err(|_| LibuserError::InvalidIpcBuffer)?;

        if T::is_cool(addr, size) {
            Ok(T::from_raw_parts(addr, size))
        } else {
            Err(LibuserError::InvalidIpcBuffer.into())
        }
    }

    /// Retreive the next OutBuffer (type-B buffer) in the message.
    ///
    /// # Errors
    ///
    /// Returns an InvalidIpcBufferCount if not enough buffers are present
    ///
    /// Returns an InvalidIpcBuffer if the next buffer was not of the appropriate
    /// size.
    ///
    /// # Safety
    ///
    /// This method is unsafe as it allows creating references to arbitrary
    /// memory, and of arbitrary type.
    pub unsafe fn pop_out_buffer<'b, T: SizedIPCBuffer + ?Sized>(&mut self) -> Result<&'b mut T, Error> {
        let buffer = self.buffers.iter().position(|buf| buf.buftype().is_type_b())
            .and_then(|pos| self.buffers.pop_at(pos))
            .ok_or_else(|| LibuserError::InvalidIpcBufferCount)?;

        let addr = usize::try_from(buffer.addr).map_err(|_| LibuserError::InvalidIpcBuffer)?;
        let size = usize::try_from(buffer.size).map_err(|_| LibuserError::InvalidIpcBuffer)?;

        if T::is_cool(addr, size) {
            Ok(T::from_raw_parts_mut(addr, size))
        } else {
            Err(LibuserError::InvalidIpcBuffer.into())
        }
    }

    /// Push an OutBuffer (type-A buffer) backed by the specified data.
    pub fn push_out_buffer<T: SizedIPCBuffer + ?Sized>(&mut self, data: &'a T) -> &mut Self {
        self.buffers.push(IPCBuffer::out_buffer(data, 0));
        self
    }

    /// Push an InBuffer (type-B buffer) backed by the specified data.
    pub fn push_in_buffer<T: SizedIPCBuffer + ?Sized>(&mut self, data: &'a mut T) -> &mut Self {
        self.buffers.push(IPCBuffer::in_buffer(data, 0));
        self
    }

    /// Push an InPointer (type-C buffer) backed by the specified data.
    ///
    /// If `has_u16_count` is true, the size of the X buffer will be appended
    /// to the Raw Data. See Buffer 0xA on the IPC Marshalling page of
    /// switchbrew.
    pub fn push_in_pointer<T: SizedIPCBuffer + ?Sized>(&mut self, data: &'a mut T, has_u16_count: bool) -> &mut Self {
        self.buffers.push(IPCBuffer::in_pointer(data, has_u16_count));
        self
    }

    /// Push an OutPointer (type-X buffer) backed by the specified data.
    ///
    /// If `has_u16_count` is true, the size of the X buffer will be appended
    /// to the Raw Data. See Buffer 0xA on the IPC Marshalling page of
    /// switchbrew.
    pub fn push_out_pointer<T: SizedIPCBuffer + ?Sized>(&mut self, data: &'a T) -> &mut Self {
        let index = self.buffers.iter().filter(|buf| buf.buftype().is_type_x()).count();
        self.buffers.push(IPCBuffer::out_pointer(data, index as u8));
        self
    }

    /// Send a Pid with this IPC request.
    ///
    /// If `pid` is None, sends the current process' Pid. If it's Some, then it
    /// will attempt to send that process Pid. Note however that this requires a
    /// kernel patch to work properly.
    pub fn send_pid(&mut self, pid: Option<Pid>) -> &mut Self {
        self.pid = Some(pid.map(|v| v.0).unwrap_or(0));
        self
    }

    /// Retreive the next InPointer (type-X buffer) in the message.
    ///
    /// # Errors
    ///
    /// Returns an InvalidIpcBufferCount if not enough buffers are present
    ///
    /// Returns an InvalidIpcBuffer if the next buffer was not of the appropriate
    /// size.
    ///
    /// # Safety
    ///
    /// This method is unsafe as it allows creating references to arbitrary
    /// memory, and of arbitrary type.
    pub unsafe fn pop_in_pointer<'b, T: SizedIPCBuffer + ?Sized>(&mut self) -> Result<&'b T, Error> {
        let buffer = self.buffers.iter().position(|buf| buf.buftype().is_type_x())
            .and_then(|pos| self.buffers.pop_at(pos))
            .ok_or_else(|| LibuserError::InvalidIpcBufferCount)?;

        let addr = usize::try_from(buffer.addr).map_err(|_| LibuserError::InvalidIpcBuffer)?;
        let size = usize::try_from(buffer.size).map_err(|_| LibuserError::InvalidIpcBuffer)?;

        if T::is_cool(addr, size) {
            Ok(T::from_raw_parts(addr, size))
        } else {
            Err(LibuserError::InvalidIpcBuffer.into())
        }
    }

    // TODO: Move pack to a non-generic function
    // BODY: Right now the pack and unpack functions are duplicated for every
    // BODY: instanciation of Message. This probably has a huge penalty on
    // BODY: codesize. We should make a function taking everything as slices
    // BODY: instead
    /// Packs this IPC Message to an IPC buffer.
    pub fn pack(self, data: &mut [u8]) {
        let (
            mut descriptor_count_x,
            mut descriptor_count_a,
            mut descriptor_count_b,
            mut descriptor_count_w,
            mut descriptor_count_c) = (/* X */0, /* A */0, /* B */0, /* W */0, /* C */0);

        for bufty in self.buffers.iter().map(|b| b.buftype()) {
            match bufty {
                IPCBufferType::X { .. } => descriptor_count_x += 1u8,
                IPCBufferType::A { .. } => descriptor_count_a += 1u8,
                IPCBufferType::B { .. } => descriptor_count_b += 1u8,
                IPCBufferType::W { .. } => descriptor_count_w += 1u8,
                IPCBufferType::C { .. } => descriptor_count_c += 1u8,
            }
        }

        let mut cursor = CursorWrite::new(data);

        // Get the header.
        {
            let mut hdr = MsgPackedHdr(0);
            hdr.set_ty(self.ty);
            hdr.set_num_x_descriptors(descriptor_count_x);
            hdr.set_num_a_descriptors(descriptor_count_a);
            hdr.set_num_b_descriptors(descriptor_count_b);
            hdr.set_num_w_descriptors(descriptor_count_w);
            if descriptor_count_c == 0 {
                hdr.set_c_descriptor_flags(0);
            } else if descriptor_count_c == 1 {
                hdr.set_c_descriptor_flags(2);
            } else {
                hdr.set_c_descriptor_flags(2 + descriptor_count_c);
            }

            // 0x10 = padding, 8 = sfci, 8 = cmdid, data = T
            let raw_section_size =
                0x10 + 8 + 8 + mem::size_of::<RAW>() +
                //domain_id.map(|v| 0x10).unwrap_or(0) +
                (self.buffers.iter().filter(|v| if let IPCBufferType::C { has_u16_size: true } = v.ty { true } else { false }).count() * 2);

            // TODO: IPC Domain Support
            // BODY: IPC Domains would be nice to include back. MegatonHammer has
            // BODY: the IPC request side of things, but I'm not too sure how to
            // BODY: implement the server side.
            /*if domain_id.is_some() {
                // Domain Header.
                raw_section_size += 0x10;
        }*/

            // C descriptor u16 sizes

            hdr.set_raw_section_size(utils::div_ceil(raw_section_size, 4) as u16);
            let enable_handle_descriptor = self.copy_handles.len() > 0 ||
                self.move_handles.len() > 0 || self.pid.is_some();
            hdr.set_enable_handle_descriptor(enable_handle_descriptor);

            cursor.write_u64::<LE>(hdr.0);
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

            // Seek 8 if we have to send pid. Write the PID, useful if we want
            // to pretend to be another process (requires a kernel patch).
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
                let num = *u32::from(counter.get_bits(0..4))
                    .set_bits(6..9, addr.get_bits(36..39) as u32)
                    .set_bits(12..16, addr.get_bits(32..36) as u32)
                    .set_bits(16..32, size as u32);
                cursor.write_u32::<LE>(num);
                cursor.write_u32::<LE>((addr & 0xFFFFFFFF) as u32);
            }
        }

        /// Pack a list of A, B or W descriptor in the buffer at the position of
        /// the cursor.
        fn pack_abw_descriptors<'a, I: Iterator<Item = &'a IPCBuffer<'a>>>(cursor: &mut CursorWrite, buffers: I) {
            for buf in buffers {
                let (addr, size, flags) = match buf.buftype() {
                    IPCBufferType::A {flags} => (buf.addr, buf.size, flags),
                    IPCBufferType::B {flags} => (buf.addr, buf.size, flags),
                    _ => unreachable!()
                };

                assert!(addr >> 39 == 0, "Invalid buffer address");
                assert!(size >> 35 == 0, "Invalid buffer size");

                cursor.write_u32::<LE>((size & 0xFFFFFFFF) as u32);
                cursor.write_u32::<LE>((addr & 0xFFFFFFFF) as u32);

                let num = u64::from(flags)
                    | ((addr >> 36) & 0b111) << 2
                    | ((size >> 32) & 0b1111) << 24
                    | ((addr >> 32) & 0b1111) << 28;
                cursor.write_u32::<LE>(num as u32);
            }
        }

        // A descriptors
        pack_abw_descriptors(&mut cursor, self.buffers.iter().filter(|buf| buf.buftype().is_type_a()));

        // B descriptors
        pack_abw_descriptors(&mut cursor, self.buffers.iter().filter(|buf| buf.buftype().is_type_b()));

        // W descriptors
        // Those are read-write descriptors. Technically speaking, a B descriptor is supposed
        // to be write-only. But Nintendo sucks.
        pack_abw_descriptors(&mut cursor, self.buffers.iter().filter(|buf| buf.buftype().is_type_w()));

        // Align to 16-byte boundary
        let before_pad = align_up(cursor.pos(), 16) - cursor.pos();
        cursor.skip_write(before_pad);

        // Domains
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
        cursor.write_u32::<LE>(self.token.map(|_| 1).unwrap_or(0));

        cursor.write_u32::<LE>(self.cmdid_error);

        // Send the token if we have one, or zero.
        cursor.write_u32::<LE>(self.token.unwrap_or(0));

        if let Some(raw) = self.raw {
            cursor.write_raw(raw);
        }

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
                IPCBufferType::C { .. } => buf,
                _ => continue
            };

            assert_eq!(buf.addr >> 48, 0, "Invalid address {:x}", buf.addr);
            assert_eq!(buf.size >> 16, 0, "Invalid size {:x}", buf.size);

            cursor.write_u32::<LE>(buf.addr as u32);
            cursor.write_u32::<LE>((buf.addr >> 32) as u32 | (buf.size as u32) << 16);
        }
    }

    // TODO: Don't panic here! Unpacking happens in the server, we should return an
    // error if the unpacking failed.
    /// Parse the passed buffer into an IPC Message.
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
            let addr = *u64::from(laddr)
                .set_bits(32..36, u64::from(stuffed.get_bits(12..16)))
                .set_bits(36..39, u64::from(stuffed.get_bits(6..9)));
            let size = u64::from(stuffed.get_bits(16..32));
            let counter = stuffed.get_bits(0..4) as u8;
            buffers.push(IPCBuffer { addr, size, ty: IPCBufferType::X { counter }, phantom: PhantomData });
        }
        for i in 0..hdr.num_a_descriptors() + hdr.num_b_descriptors() + hdr.num_w_descriptors() {
            // Skip 3 words
            let lsize = cursor.read_u32::<LE>();
            let laddr = cursor.read_u32::<LE>();
            let stuff = cursor.read_u32::<LE>();
            let addr = *u64::from(laddr)
                .set_bits(32..36, u64::from(stuff.get_bits(28..32)))
                .set_bits(36..39, u64::from(stuff.get_bits(2..5)));
            let size = *u64::from(lsize)
                .set_bits(32..36, u64::from(stuff.get_bits(24..28)));
            let flags = stuff.get_bits(0..2) as u8;

            let ty = if i < hdr.num_a_descriptors() {
                IPCBufferType::A { flags }
            } else if i < hdr.num_a_descriptors() + hdr.num_b_descriptors() {
                IPCBufferType::B { flags }
            } else {
                IPCBufferType::W { flags }
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
        let raw = Some(cursor.read_raw::<RAW>());

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

/// Quickly find the type and cmdid of an IPC message for the server dispatcher.
///
/// Doesn't do any validation that the message is valid.
fn find_ty_cmdid(buf: &[u8]) -> Option<(u16, u32)> {
    if buf.len() < 8 {
        return None
    }
    let hdr = u64::from_le_bytes(buf[0..8].try_into().expect("cmd header is invalid"));
    let ty = hdr.get_bits(0..16) as u16;
    let x_descs = hdr.get_bits(16..20) as usize;
    let a_descs = hdr.get_bits(20..24) as usize;
    let b_descs = hdr.get_bits(24..28) as usize;
    let w_descs = hdr.get_bits(28..32) as usize;
    let (pid, copyhandles, movehandles) = if hdr.get_bit(63) {
        if buf.len() < 12 {
            return None
        }
        let dsc = u32::from_le_bytes(buf[8..12].try_into().expect("cmd description is invalid"));
        (dsc.get_bit(0) as usize, dsc.get_bits(1..5) as usize, dsc.get_bits(5..9) as usize)
    } else {
        (0, 0, 0)
    };
    let raw = 8 + (hdr.get_bit(63) as usize) * 4 + pid * 8 + (copyhandles + movehandles) * 4 + (x_descs * 8 + (a_descs + b_descs + w_descs) * 12);
    let raw = align_up(raw, 16) + 8;
    if buf.len() < raw + 4 {
        return None
    }
    let cmdid = u32::from_le_bytes(buf[raw..raw + 4].try_into().expect("command id is invalid"));
    Some((ty, cmdid))
}

