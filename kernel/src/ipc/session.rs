//! IPC Sessions
//!
//! A Session represents an established connection. It implements a rendez-vous
//! style Remote Procedure Call interface. The ClientSession has a `send_request`
//! operation, which will wait for the counterpart ServerSession's `reply`. A
//! ServerSession can also `receive` the pending requests.
//!
//! Note that a single Session can only process a single request at a time - it
//! is an inherently sequential construct. If multiple threads attempt receiving
//! on the same handle, they will have to wait for the current request to be
//! replied to before being able to receive the next request in line.
//!
//! ```rust
//! use kernel::ipc::session;
//! let (server, client) = session::new();
//! ```
//!
//! The requests are encoded in a byte buffer under a specific format. For
//! documentation on the format, [switchbrew] is your friend.
//!
//! [switchbrew]: https://switchbrew.org/w/index.php?title=IPC_Marshalling

use crate::scheduler;
use alloc::vec::Vec;
use alloc::sync::{Arc, Weak};
use crate::sync::SpinLock;
use crate::error::UserspaceError;
use crate::event::Waitable;
use crate::process::ThreadStruct;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::slice;
use byteorder::{LE, ByteOrder};
use crate::paging::{MappingAccessRights, process_memory::ProcessMemory};
use crate::mem::{UserSpacePtr, UserSpacePtrMut, VirtualAddress};
use bit_field::BitField;
use crate::error::KernelError;
use crate::checks::check_lower_than_usize;

/// Wrapper around the currently active session and the incoming request list.
/// They are kept together so they are locked together.
#[derive(Debug)]
struct SessionRequests {
    /// The request currently being serviced. Sessions are sequential: they can
    /// only service a single request at a time.
    active_request: Option<Request>,
    /// Pending Requests.
    incoming_requests: Vec<Request>,
}

/// Shared part of a Session.
#[derive(Debug)]
struct Session {
    /// Pending requests and currently active request are there.
    internal: SpinLock<SessionRequests>,
    /// List of threads waiting for a request.
    accepters: SpinLock<Vec<Weak<ThreadStruct>>>,
    /// Count of live ServerSessions. Once it drops to 0, all attempts to call
    /// [ClientSession::send_request] will fail with
    /// [UserspaceError::PortRemoteDead].
    servercount: AtomicUsize,
}

/// The client side of a Session.
#[derive(Debug, Clone)]
pub struct ClientSession(Arc<Session>);

/// The server side of a Session.
#[derive(Debug)]
pub struct ServerSession(Arc<Session>);

impl Clone for ServerSession {
    fn clone(&self) -> Self {
        assert!(self.0.servercount.fetch_add(1, Ordering::SeqCst) != usize::max_value(), "Overflow when incrementing servercount");
        ServerSession(self.0.clone())
    }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        let count = self.0.servercount.fetch_sub(1, Ordering::SeqCst);
        assert!(count != 0, "Overflow when decrementing servercount");
        if count == 1 {
            info!("Last ServerSession dropped");
            // We're dead jim.
            let mut internal = self.0.internal.lock();

            if let Some(request) = internal.active_request.take() {
                *request.answered.lock() = Some(Err(UserspaceError::PortRemoteDead));
                scheduler::add_to_schedule_queue(request.sender.clone());
            }

            for request in internal.incoming_requests.drain(..) {
                *request.answered.lock() = Some(Err(UserspaceError::PortRemoteDead));
                scheduler::add_to_schedule_queue(request.sender.clone());
            }
        }
    }
}

bitfield! {
    /// Represenens the header of an HIPC command.
    ///
    /// The kernel uses this header to figure out how to send the IPC message.
    pub struct MsgPackedHdr(u64);
    impl Debug;
    u16, ty, _: 15, 0;
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
    pub struct HandleDescriptorHeader(u32);
    impl Debug;
    send_pid, set_send_pid: 0;
    u8, num_copy_handles, set_num_copy_handles: 4, 1;
    u8, num_move_handles, set_num_move_handles: 8, 5;
}

impl Session {
    /// Returns a ClientPort from this Port.
    fn client(this: Arc<Self>) -> ClientSession {
        ClientSession(this)
    }

    /// Returns a ServerSession from this Port.
    fn server(this: Arc<Self>) -> ServerSession {
        this.servercount.fetch_add(1, Ordering::SeqCst);
        ServerSession(this)
    }
}

/// Create a new Session pair. Those sessions are linked to each-other: The
/// server will receive requests sent through the client.
pub fn new() -> (ServerSession, ClientSession) {
    let sess = Arc::new(Session {
        internal: SpinLock::new(SessionRequests {
            incoming_requests: Vec::new(),
            active_request: None
        }),
        accepters: SpinLock::new(Vec::new()),
        servercount: AtomicUsize::new(0)
    });

    (Session::server(sess.clone()), Session::client(sess))
}

impl Waitable for ServerSession {
    fn is_signaled(&self) -> bool {
        let mut internal = self.0.internal.lock();
        if internal.active_request.is_none() {
            if let Some(s) = internal.incoming_requests.pop() {
                internal.active_request = Some(s);
                true
            } else {
                false
            }
        } else {
            true
        }
    }

    fn register(&self) {
        let mut accepters = self.0.accepters.lock();
        let curproc = scheduler::get_current_thread();

        if !accepters.iter().filter_map(|v| v.upgrade()).any(|v| Arc::ptr_eq(&curproc, &v)) {
            accepters.push(Arc::downgrade(&curproc));
        }
    }
}

/// An incoming IPC request.
#[derive(Debug)]
struct Request {
    /// Address of the mirror-mapped (in-kernel) IPC buffer. Guaranteed to be
    /// at least sender_bufsize in size.
    sender_buf: VirtualAddress,
    /// Size of the IPC buffer.
    sender_bufsize: usize,
    /// Thread that sent this request. It should be woken up when the request
    /// is answered.
    sender: Arc<ThreadStruct>,
    /// A really really broken excuse for a condvar. The thread replying should
    /// insert a result (potentially an error) in this option before waking up
    /// the sender.
    answered: Arc<SpinLock<Option<Result<(), UserspaceError>>>>,
}

/// Send an IPC Buffer from the sender into the receiver.
///
/// There are two "families" of IPC buffers:
///
/// - Buffers, also known as IPC type A, B and W, are going to remap the Page
///   from the sender's address space to the receiver's. As a result, those
///   buffers are required to be page-aligned.
/// - Pointers, also known as IPC type X and C, involve the kernel copying the
///   data from the type X Pointer to the associated type C pointer. This results
///   in much more flexibility for the userspace, at the cost of a bit of
///   performance.
///
/// In practice, the performance lost by memcpying the data can be made up by not
/// requiring to flush the page table cache, so care must be taken when chosing
/// between Buffer or Pointer family of IPC.
#[allow(unused)]
fn buf_map(from_buf: &[u8], to_buf: &mut [u8], curoff: &mut usize, from_mem: &mut ProcessMemory, to_mem: &mut ProcessMemory, flags: MappingAccessRights) -> Result<(), UserspaceError> {
    let lowersize = LE::read_u32(&from_buf[*curoff..*curoff + 4]);
    let loweraddr = LE::read_u32(&from_buf[*curoff + 4..*curoff + 8]);
    let rest = LE::read_u32(&from_buf[*curoff + 8..*curoff + 12]);

    let bufflags = rest.get_bits(0..2);

    let addr = *(u64::from(loweraddr))
        .set_bits(32..36, u64::from(rest.get_bits(28..32)))
        .set_bits(36..39, u64::from(rest.get_bits(2..5)));

    let size = *(u64::from(loweraddr))
        .set_bits(32..36, u64::from(rest.get_bits(24..28)));

    // 64-bit address on a 32-bit kernel!
    check_lower_than_usize(addr, UserspaceError::InvalidAddress)?;
    check_lower_than_usize(size, UserspaceError::InvalidSize)?;
    check_lower_than_usize(addr.saturating_add(size), UserspaceError::InvalidSize)?;

    let addr = addr as usize;
    let size = size as usize;

    // TODO: handle NULL addr case -> no need to map anything, just create an equivalent null entry.

    // Map the descriptor in the other process.
    let mapping = from_mem.share_existing_mapping(VirtualAddress(addr), size)?;
    let to_addr = to_mem.find_available_space(size)?;
    to_mem.map_shared_mapping(mapping, to_addr, MappingAccessRights::u_rw())?;

    let loweraddr = to_addr.addr() as u32;
    let rest = *0u32
        .set_bits(0..2, bufflags)
        .set_bits(2..5, (to_addr.addr() as u64).get_bits(36..39) as u32)
        .set_bits(24..28, (size as u64).get_bits(32..36) as u32)
        .set_bits(28..32, (to_addr.addr() as u64).get_bits(32..36) as u32);

    LE::write_u32(&mut to_buf[*curoff + 0..*curoff + 4], lowersize);
    LE::write_u32(&mut to_buf[*curoff + 4..*curoff + 8], loweraddr);
    LE::write_u32(&mut to_buf[*curoff + 8..*curoff + 12], rest);

    *curoff += 12;
    Ok(())
}

impl ClientSession {
    /// Send an IPC request through the client pipe. Takes a userspace buffer
    /// containing the packed IPC request. When returning, the buffer will
    /// contain the IPC answer (unless an error occured).
    ///
    /// This function is blocking - it will wait until the server receives and
    /// replies to the request before returning.
    ///
    /// Note that the buffer needs to live until send_request returns, which may
    /// take an arbitrary long time. We do not eagerly read the buffer - it will
    /// be read from when the server asks to receive a request.
    pub fn send_request(&self, buf: UserSpacePtrMut<[u8]>) -> Result<(), UserspaceError> {
        let answered = Arc::new(SpinLock::new(None));

        {
            // Be thread-safe: First we lock the internal mutex. Then check whether there's
            // a server left or not, in which case fail-fast. Otherwise, add the incoming
            // request.
            let mut internal = self.0.internal.lock();

            if self.0.servercount.load(Ordering::SeqCst) == 0 {
                return Err(UserspaceError::PortRemoteDead);
            }

            internal.incoming_requests.push(Request {
                sender_buf: VirtualAddress(buf.as_ptr() as usize),
                sender_bufsize: buf.len(),
                answered: answered.clone(),
                sender: scheduler::get_current_thread(),
            })
        }

        let mut guard = answered.lock();

        while let None = *guard {
            while let Some(item) = self.0.accepters.lock().pop() {
                if let Some(process) = item.upgrade() {
                    scheduler::add_to_schedule_queue(process);
                    break;
                }
            }

            guard = scheduler::unschedule(&*answered, guard)?;
        }

        (*guard).unwrap()
    }
}

/// Efficiently finds C Descriptor in a message.
fn find_c_descriptors(buf: &mut [u8]) -> Result<CBufBehavior, KernelError> {
    let mut curoff = 0;

    let hdr = MsgPackedHdr(LE::read_u64(&buf[curoff..curoff + 8]));
    curoff += 8;

    let cflag = hdr.c_descriptor_flags();

    match cflag {
        0 => return Ok(CBufBehavior::Disabled),
        1 => return Ok(CBufBehavior::Inlined),
        _ => ()
    }

    // Go grab C descriptors

    if hdr.enable_handle_descriptor() {
        let descriptor = HandleDescriptorHeader(LE::read_u32(&buf[curoff..curoff + 4]));
        curoff += 4;
        if descriptor.send_pid() {
            curoff += 8;
        }
        curoff += 4 * usize::from(descriptor.num_copy_handles() + descriptor.num_move_handles());
    }

    curoff += 8 * usize::from(hdr.num_x_descriptors());
    curoff += 12 * usize::from(hdr.num_a_descriptors() + hdr.num_b_descriptors() + hdr.num_w_descriptors());
    curoff += 4 * usize::from(hdr.raw_section_size());


    match hdr.c_descriptor_flags() {
        0 | 1 => unreachable!(),
        2 => {
            let word1 = LE::read_u32(&buf[curoff..curoff + 4]);
            let word2 = LE::read_u32(&buf[curoff + 4..curoff + 8]);
            let addr = *u64::from(word1).set_bits(32..48, u64::from(word2.get_bits(0..16)));
            let size = u64::from(word2.get_bits(16..32));
            Ok(CBufBehavior::Single(addr, size))
        },
        x => {
            let mut bufs = [(0, 0); 13];
            for i in 0..x - 2 {
                let word1 = LE::read_u32(&buf[curoff..curoff + 4]);
                let word2 = LE::read_u32(&buf[curoff + 4..curoff + 8]);
                let addr = *u64::from(word1).set_bits(32..48, u64::from(word2.get_bits(0..16)));
                let size = u64::from(word2.get_bits(16..32));
                bufs[i as usize] = (addr, size);
            }
            Ok(CBufBehavior::Numbered(bufs, (x - 2) as usize))
        }
    }
}

impl ServerSession {
    /// Receive an IPC request through the server pipe. Takes a userspace buffer
    /// containing an empty IPC message. The request may optionally contain a
    /// C descriptor in order to receive X descriptors. The buffer will be filled
    /// with an IPC request.
    ///
    /// This function does **not** wait. It assumes an active_request has already
    /// been set by a prior call to wait.
    pub fn receive(&self, mut buf: UserSpacePtrMut<[u8]>, has_c_descriptors: bool) -> Result<(), UserspaceError> {
        // Read active session
        let internal = self.0.internal.lock();

        // TODO: In case of a race, we might want to check that receive is only called once.
        // Can races even happen ?
        let active = internal.active_request.as_ref().unwrap();

        let sender = active.sender.process.clone();
        let memlock = sender.pmemory.lock();

        let mapping = memlock.mirror_mapping(active.sender_buf, active.sender_bufsize)?;
        let sender_buf = unsafe {
            slice::from_raw_parts_mut(mapping.addr().addr() as *mut u8, mapping.len())
        };

        let c_bufs = if has_c_descriptors {
            find_c_descriptors(&mut *buf)?
        } else {
            CBufBehavior::Disabled
        };

        pass_message(sender_buf, active.sender.clone(), &mut *buf, scheduler::get_current_thread(), false, &*memlock, c_bufs)?;

        Ok(())
    }

    /// Replies to the currently active IPC request on the server pipe. Takes a
    /// userspace buffer containing the IPC reply. The kernel will copy the reply
    /// to the sender's IPC buffer, before waking the sender so it may return to
    /// userspace.
    ///
    /// # Panics
    ///
    /// Panics if there is no currently active request on the pipe.
    // TODO: Don't panic in Session::reply if active_request is not set.
    // BODY: Session::reply currently asserts that an active session is set. This
    // BODY: assertion can be trivially triggered by userspace, by calling
    // BODY: the reply_and_receive syscall with reply_target set to a Session
    // BODY: that hasn't received any request.
    pub fn reply(&self, buf: UserSpacePtr<[u8]>) -> Result<(), UserspaceError> {
        // TODO: This probably has an errcode.
        assert!(self.0.internal.lock().active_request.is_some(), "Called reply without an active session");

        let active = self.0.internal.lock().active_request.take().unwrap();

        let sender = active.sender.process.clone();

        let memlock = sender.pmemory.lock();

        let mapping = memlock.mirror_mapping(active.sender_buf, active.sender_bufsize)?;
        let sender_buf = unsafe {
            slice::from_raw_parts_mut(mapping.addr().addr() as *mut u8, mapping.len())
        };

        pass_message(&*buf, scheduler::get_current_thread(), sender_buf, active.sender.clone(), true, &*memlock, CBufBehavior::Disabled)?;

        *active.answered.lock() = Some(Ok(()));

        scheduler::add_to_schedule_queue(active.sender.clone());

        Ok(())
    }
}

/// Defines how to handle X Buffer descriptors based on the C Buffer flags.
#[allow(clippy::large_enum_variant)] // Expected.
enum CBufBehavior {
    /// No C Buffers are available. Presence of X Buffers should cause an error.
    Disabled,
    /// X Buffers should be copied after the Raw Data.
    Inlined,
    /// X Buffers should be copied sequentially to the C Buffer represented by
    /// the given address/size pair.
    Single(u64, u64),
    /// X Buffers should be copied to the appropriate C Buffer represented y
    /// the given address/size pair, based on the counter.
    Numbered([(u64, u64); 13], usize)
}

/// Send a message from the sender to the receiver. This is more or less a
/// memcpy, with some special case done to satisfy the various commands of the
/// CMIF structure:
///
/// - If send_pid is enabled, write the pid of the sender in the spot reserved
///   for this,
/// - Copy/Move handles are added to the receiver's Handle Table, and removed
///   from the sender's Handle Table when appropriate. The handle numbers are
///   rewritten to the receiver's.
/// - Buffers are appropriately mapped through the [buf_map] function, and the
///   address are rewritten to in the receiver's address space.
///
/// This function should always be called from the context of the receiver/
/// server.
#[allow(unused)]
fn pass_message(from_buf: &[u8], from_proc: Arc<ThreadStruct>, to_buf: &mut [u8], to_proc: Arc<ThreadStruct>, is_reply: bool, other_memlock: &ProcessMemory, c_bufs: CBufBehavior) -> Result<(), UserspaceError> {
    // TODO: pass_message deadlocks when sending message to the same process.
    // BODY: If from_proc and to_proc are the same process, pass_message will
    // BODY: deadlock trying to acquire the locks to the handle table or the
    // BODY: page tables.

    let mut curoff = 0;
    let hdr = MsgPackedHdr(LE::read_u64(&from_buf[curoff..curoff + 8]));
    LE::write_u64(&mut to_buf[curoff..curoff + 8], hdr.0);

    curoff += 8;

    let descriptor = if hdr.enable_handle_descriptor() {
        let descriptor = HandleDescriptorHeader(LE::read_u32(&from_buf[curoff..curoff + 4]));
        LE::write_u32(&mut to_buf[curoff..curoff + 4], descriptor.0);
        curoff += 4;
        descriptor
    } else {
        HandleDescriptorHeader(0)
    };

    if descriptor.send_pid() {
        // TODO: Atmosphere patch for fs_mitm.
        LE::write_u64(&mut to_buf[curoff..curoff + 8], from_proc.process.pid as u64);
        curoff += 8;
    }

    if descriptor.num_copy_handles() != 0 || descriptor.num_move_handles() != 0 {
        let mut from_handle_table = from_proc.process.phandles.lock();
        let mut to_handle_table = to_proc.process.phandles.lock();

        for i in 0..descriptor.num_copy_handles() {
            let handle = LE::read_u32(&from_buf[curoff..curoff + 4]);
            let handle = from_handle_table.get_handle(handle)?;
            let handle = to_handle_table.add_handle(handle);
            LE::write_u32(&mut to_buf[curoff..curoff + 4], handle);
            curoff += 4;
        }
        for i in 0..descriptor.num_move_handles() {
            let handle = LE::read_u32(&from_buf[curoff..curoff + 4]);
            let handle = from_handle_table.delete_handle(handle)?;
            let handle = to_handle_table.add_handle(handle);
            LE::write_u32(&mut to_buf[curoff..curoff + 4], handle);
            curoff += 4;
        }
    }

    {
        let mut coff = 0;
        for i in 0..hdr.num_x_descriptors() {
            let word1 = LE::read_u32(&from_buf[curoff..curoff + 4]);
            let counter = word1.get_bits(0..6); // Counter can't go higher anyways.

            let from_addr = *u64::from(LE::read_u32(&from_buf[curoff + 4..curoff + 8]))
                .set_bits(32..36, u64::from(word1.get_bits(12..16)))
                .set_bits(36..39, u64::from(word1.get_bits(6..9)));
            let from_size = u64::from(word1.get_bits(16..32));

            let (to_addr, to_size) = match c_bufs {
                CBufBehavior::Disabled => return Err(UserspaceError::PortRemoteDead),
                CBufBehavior::Inlined => unimplemented!(),
                CBufBehavior::Single(addr, size) => {
                    (addr + coff, size - coff)
                },
                CBufBehavior::Numbered(bufs, count) => {
                    // TODO: IPC Type-X: Prevent multiple writes to a C-buffer?
                    // BODY: Do I need to prevent multiple writes to the same
                    // BODY: buffer ID? In theory, I could use coff as a bitmap
                    // BODY: of used buffers, and prevent reuse this way, but I'm
                    // BODY: unsure of how the nintendo switch behaves here.
                    let (addr, size) = bufs[..count][counter as usize];
                    (addr, size)
                }
            };

            // Check addresses fit in 32-bit kernel.
            check_lower_than_usize(from_addr, UserspaceError::InvalidAddress)?;
            check_lower_than_usize(from_size, UserspaceError::InvalidAddress)?;
            check_lower_than_usize(from_addr.saturating_add(from_size), UserspaceError::InvalidAddress)?;
            check_lower_than_usize(to_addr, UserspaceError::InvalidAddress)?;
            check_lower_than_usize(to_size, UserspaceError::InvalidAddress)?;
            check_lower_than_usize(to_addr.saturating_add(to_size), UserspaceError::InvalidAddress)?;

            let (mapping, mut uspaceptr) = if !is_reply {
                // We're receiving: C Buffers are in our address space, X buffers
                // are in the other address space
                let mapping = other_memlock.mirror_mapping(VirtualAddress(from_addr as usize), from_size as usize)?;
                let uspaceptr = UserSpacePtrMut::from_raw_parts_mut(to_addr as *mut u8, to_size as usize);
                (mapping, uspaceptr)
            } else {
                // We're receiving: C Buffers are in our address space, X buffers
                // are in the other address space
                let mapping = other_memlock.mirror_mapping(VirtualAddress(to_addr as usize), to_size as usize)?;
                let uspaceptr = UserSpacePtrMut::from_raw_parts_mut(from_addr as *mut u8, from_size as usize);
                (mapping, uspaceptr)
            };

            let (from, to) = {
                let ref_mapping = unsafe {
                    slice::from_raw_parts_mut(mapping.addr().addr() as *mut u8, mapping.len())
                };
                let ref_uspace = &mut *uspaceptr;
                if !is_reply {
                    (ref_mapping, ref_uspace)
                } else {
                    (ref_uspace, ref_mapping)
                }
            };

            to[..from.len()].copy_from_slice(from);
            coff += from.len() as u64;

            let mut counter = counter;
            LE::write_u32(&mut to_buf[curoff..curoff + 4], *counter
                .set_bits(6..9, to_addr.get_bits(36..39) as u32)
                .set_bits(12..16, to_addr.get_bits(32..36) as u32)
                .set_bits(16..32, from_size as u32));
            LE::write_u32(&mut to_buf[curoff + 4..curoff + 8], to_addr as u32);

            curoff += 8;
        }
    }

    if hdr.num_a_descriptors() != 0 || hdr.num_b_descriptors() != 0 {
        let mut from_mem = from_proc.process.pmemory.lock();
        let mut to_mem = to_proc.process.pmemory.lock();

        for i in 0..hdr.num_a_descriptors() {
            buf_map(from_buf, to_buf, &mut curoff, &mut *from_mem, &mut *to_mem, MappingAccessRights::empty())?;
        }

        for i in 0..hdr.num_b_descriptors() {
            buf_map(from_buf, to_buf, &mut curoff, &mut *from_mem, &mut *to_mem, MappingAccessRights::WRITABLE)?;
        }

        for i in 0..hdr.num_w_descriptors() {
            buf_map(from_buf, to_buf, &mut curoff, &mut *from_mem, &mut *to_mem, MappingAccessRights::WRITABLE)?;
        }
    }

    (&mut to_buf[curoff..curoff + (hdr.raw_section_size() as usize) * 4])
        .copy_from_slice(&from_buf[curoff..curoff + (hdr.raw_section_size() as usize) * 4]);

    if hdr.c_descriptor_flags() == 1 {
        unimplemented!("Inline C Descriptor");
    } else if hdr.c_descriptor_flags() == 2 {
        unimplemented!("Single C Descriptor");
    } else if hdr.c_descriptor_flags() != 0 {
        unimplemented!("Multi C Descriptor");
        for i in 0..hdr.c_descriptor_flags() - 2 {
        }
    }

    Ok(())
}
