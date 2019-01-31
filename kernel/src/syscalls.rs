//! Syscall implementations

use crate::mem::{VirtualAddress, PhysicalAddress};
use crate::mem::{UserSpacePtr, UserSpacePtrMut};
use crate::paging::{MappingAccessRights, mapping::MappingType};
use crate::frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait};
use crate::process::{Handle, ThreadStruct, ProcessStruct};
use crate::event::{self, Waitable};
use crate::scheduler::{self, get_current_thread, get_current_process};
use crate::devices::pit;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::ipc;
use crate::utils::check_thread_killed;
use crate::error::UserspaceError;
use kfs_libkern::{nr, SYSCALL_NAMES, MemoryInfo, MemoryAttributes, MemoryPermissions};
use bit_field::BitArray;

/// Resize the heap of a process, just like a brk.
/// It can both expand, and shrink the heap.
///
/// If `new_size` == 0, the heap space is entirely de-allocated.
///
/// # Return
///
/// The address of the start of the heap.
///
/// # Error
///
/// * `new_size` must be [PAGE_SIZE] aligned.
///
/// [PAGE_SIZE]: crate::paging::PAGE_SIZE
fn set_heap_size(new_size: usize) -> Result<usize, UserspaceError> {
    let p = get_current_process();
    let mut pmemory = p.pmemory.lock();
    let heap_addr = pmemory.resize_heap(new_size)?;
    Ok(heap_addr.addr())
}

/// Maps the vga frame buffer mmio in userspace memory
#[cfg(target_arch = "x86")] // Temporary.
fn map_framebuffer() -> Result<(usize, usize, usize, usize), UserspaceError> {
    use crate::arch::i386;
    let tag = i386::multiboot::get_boot_information().framebuffer_info_tag()
        .expect("Framebuffer to be provided");
    let framebuffer_size = tag.framebuffer_bpp() as usize
                                * tag.framebuffer_dimensions().0 as usize
                                * tag.framebuffer_dimensions().1 as usize / 8;
    let frame_buffer_phys_region = unsafe {
        PhysicalMemRegion::on_fixed_mmio(PhysicalAddress(tag.framebuffer_addr()), framebuffer_size)
    };

    let process = get_current_process();
    let mut memory = process.pmemory.lock();
    //let framebuffer_vaddr = memory.find_virtual_space::<UserLand>(frame_buffer_phys_region.size())?;
    // todo make user provide the address
    let framebuffer_vaddr = VirtualAddress(0x40000000);
    memory.map_phys_region_to(frame_buffer_phys_region, framebuffer_vaddr, MappingAccessRights::u_rw())?;

    let addr = framebuffer_vaddr.0;
    let width = tag.framebuffer_dimensions().0 as usize;
    let height = tag.framebuffer_dimensions().1 as usize;
    let bpp = tag.framebuffer_bpp() as usize;
    Ok((addr, width, height, bpp))
}

/// Create an event handle for the given IRQ number. Waiting on this handle will
/// wait until the IRQ is triggered. The flags argument configures the
/// triggering. If it is false, the IRQ is active HIGH level sensitive, if it is
/// true it is rising-edge sensitive.
///
/// # Return
///
/// A handle to the readable event associated with the IRQ.
///
/// # Error
///
/// NoSuchEntry: IRQ above 0x3FF or outside the IRQ access mask was given.
fn create_interrupt_event(irq_num: usize, _flag: u32) -> Result<usize, UserspaceError> {
    // TODO: Properly handle flags in create_interrupt_event.
    // BODY: The flags in create_interrupt_event configure the triggering of the
    // BODY: event. If it is false, the IRQ is active HIGH level sensitive. If it
    // BODY: is true, it is rising-edge sensitive.
    // TODO: Fully correct error handling in create_interrupt_event.
    // BODY: https://switchbrew.org/w/index.php?title=SVC#svcCreateInterruptEvent
    // BODY: contains complete error code information. Notably, we're missing the
    // BODY: IRQ already registered error, since our implementation allows
    // BODY: multiple InterruptEvent on the same IRQ.
    let curproc = scheduler::get_current_process();
    if !curproc.capabilities.irq_access_mask.get_bit(irq_num) {
        if cfg!(feature = "no-security-check") {
            error!("Process {} attempted to create unauthorized IRQEvent for irq {}", curproc.name, irq_num);
        } else {
            return Err(UserspaceError::NoSuchEntry);
        }
    }
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ReadableEvent(Box::new(event::wait_event(irq_num)))));
    Ok(hnd as _)
}

/// Waits for one of the handles to signal an event.
///
/// When zero handles are passed, this will wait forever until either timeout or cancellation occurs.
///
/// Does not accept 0xFFFF8001 or 0xFFFF8000 as handles.
///
/// # Result
///
/// Index of the handle that was signaled in the handles table.
///
/// # Error
///
/// - Timeout: the timeout was reached without a signal occuring on the given handles.
/// - InvalidHandle: A handle in the handle table does not exist.
fn wait_synchronization(handles_ptr: UserSpacePtr<[u32]>, timeout_ns: usize) -> Result<usize, UserspaceError> {
    // A list of underlying handles to wait for...
    let mut handle_arr = Vec::new();
    let proc = scheduler::get_current_process();
    {
        // Make sure we drop proclock before waiting.
        let handleslock = proc.phandles.lock();
        for handle in handles_ptr.iter() {
            let hnd = handleslock.get_handle(*handle)?;
            let _ = hnd.as_waitable()?;
            handle_arr.push(hnd);
        }
    }

    // Add a waitable for the timeout.
    let timeout_waitable = if timeout_ns != usize::max_value() {
        Some(pit::wait_ms(timeout_ns / 1_000_000))
    } else {
        None
    };

    // Turn the handle array and the waitable timeout into an iterator of Waitables...
    let waitables = handle_arr.iter()
        .map(|v| v.as_waitable().unwrap())
        .chain(timeout_waitable.iter().map(|v| v as &dyn Waitable));

    // And now, wait!
    let val = event::wait(waitables.clone())?;

    // Figure out which waitable got triggered.
    for (idx, handle) in waitables.enumerate() {
        if handle as *const _ == val as *const _ {
            if idx == handle_arr.len() {
                return Err(UserspaceError::Timeout);
            } else {
                return Ok(idx);
            }
        }
    }
    // That's not supposed to happen. I heard that *sometimes*, dyn pointers will not turn up equal...
    unreachable!("No waitable triggered??!?");
}

/// Print the passed string to the serial port.
fn output_debug_string(s: UserSpacePtr<[u8]>) -> Result<(), UserspaceError> {
    info!("{}", String::from_utf8_lossy(&*s));
    Ok(())
}

/// Kills our own process.
fn exit_process() -> Result<(), UserspaceError> {
    ProcessStruct::kill_process(get_current_process());
    Ok(())
}

/// Connects to the given ClientPort.
///
/// # Returns
///
/// Returns a ClientSession handle.
///
/// # Error
///
/// - InvalidHandle: The passed handle does not exist, or is not a ClientPort.
/// - PortRemoteDead: All associated ServerPort handles are closed
fn connect_to_port(handle: u32) -> Result<usize, UserspaceError> {
    let curproc = scheduler::get_current_process();
    let clientport = curproc.phandles.lock().get_handle(handle)?.as_client_port()?;
    let clientsess = clientport.connect()?;
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(clientsess)));
    Ok(hnd as _)
}

/// Kills our own thread.
fn exit_thread() -> Result<(), UserspaceError> {
    ThreadStruct::kill(get_current_thread());
    Ok(())
}

/// Creates a thread in the current process.
/// The thread can then be started with the svcStartThread.
///
/// # Params
///
/// * `ip` the entry point of the thread,
/// * `arg` the initial argument of the thread (passed in eax),
/// * `sp` the top of the stack,
/// * `priority` ignored,
/// * `processor_id` ignored,
///
/// # Returns
///
/// A thread_handle to the created thread.
fn create_thread(ip: usize, arg: usize, sp: usize, _priority: u32, _processor_id: u32) -> Result<usize, UserspaceError> {
    let cur_proc = get_current_process();
    let thread = ThreadStruct::new(&cur_proc, VirtualAddress(ip), VirtualAddress(sp), arg)?;
    let handle = Handle::Thread(thread);
    let mut handles_table = cur_proc.phandles.lock();
    Ok(handles_table.add_handle(Arc::new(handle)) as usize)
}

/// Starts a previously created thread.
///
/// # Error
///
/// * `InvalidHandle` if the handle is not a thread_handle,
/// * `ProcessAlreadyStarted` if the thread has already started,
#[allow(clippy::unit_arg)]
fn start_thread(thread_handle: u32) -> Result<(), UserspaceError> {
    let cur_proc = get_current_process();
    let handles_table = cur_proc.phandles.lock();
    let thread = handles_table.get_handle(thread_handle)?.as_thread_handle()?;
    Ok(ThreadStruct::start(thread)?)
}

/// Connects to the given named port. The name should be a 12-byte array
/// containing a null-terminated string.
///
/// # Returns
///
/// Returns a ClientSession handle.
///
/// # Error
///
/// - ExceedingMaximum: Name is bigger than 12 character, or is missing a \0.
/// - NoSuchEntry: No named port were registered with this name.
/// - PortRemoteDead: All associated ServerPort handles are closed.
fn connect_to_named_port(name: UserSpacePtr<[u8; 12]>) -> Result<usize, UserspaceError> {
    let session = ipc::connect_to_named_port(*name)?;
    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(session)));
    Ok(hnd as _)
}

/// Creates a new ServerPort for the given named port. The name should be a
/// 12-byte array containing a null-terminated string. This ServerPort can be
/// connected to with `connect_to_named_port`.
///
/// # Returns
///
/// Returns a ServerSession handle.
///
/// # Error
///
/// - ExceedingMaximum: Name is bigger than 12 character, or is missing a \0.
fn manage_named_port(name_ptr: UserSpacePtr<[u8; 12]>, max_sessions: u32) -> Result<usize, UserspaceError> {
    let server = ipc::create_named_port(*name_ptr, max_sessions)?;
    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerPort(server)));
    Ok(hnd as _)
}

/// Waits for an incoming connection on the given ServerPort handle, and create
/// a new ServerSession for it.
///
/// # Returns
///
/// Returns a ServerSession handle.
///
/// # Error
///
/// - InvalidHandle: Handles does not exist or is not a ServerPort.
fn accept_session(porthandle: u32) -> Result<usize, UserspaceError> {
    let curproc = scheduler::get_current_process();
    let handle = curproc.phandles.lock().get_handle(porthandle)?;
    let port = match *handle {
        Handle::ServerPort(ref port) => port,
        _ => return Err(UserspaceError::InvalidHandle),
    };

    let server_session = port.accept()?;
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerSession(server_session)));
    Ok(hnd as _)
}

/// Send an IPC request through the ClientSession, and blocks until a response is
/// received. This variant takes a userspace buffer and size. Those must be
/// page-aligned.
///
/// # Error
///
/// - PortRemoteDead: All ServerSession associated with this handle are closed.
fn send_sync_request_with_user_buffer(buf: UserSpacePtrMut<[u8]>, handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    let sess = proc.phandles.lock().get_handle(handle)?.as_client_session()?;
    sess.send_request(buf)
}

/// If ReplyTarget is not zero, a reply from the given buffer will be sent to
/// that session. Then it will wait until either of the passed sessions has an
/// incoming message, is closed, a passed port has an incoming connection, or
/// the timeout expires. If there is an incoming message, it is copied to the
/// TLS.
///
/// If ReplyTarget is zero, the buffer should contain a blank message. If this
/// message has a C descriptor, the buffer it points to will be used as the
/// pointer buffer. See IPC_Marshalling#IPC_buffers. Note that a pointer buffer
/// cannot be specified if ReplyTarget is not zero.
///
/// After being validated, passed handles will be enumerated in order; even if a
/// session has been closed, if one that appears earlier in the list has an
/// incoming message, it will take priority and a result code of 0x0 will be
/// returned.
fn reply_and_receive_with_user_buffer(buf: UserSpacePtrMut<[u8]>, handles: UserSpacePtr<[u32]>, reply_target: u32, timeout: usize) -> Result<usize, UserspaceError> {
    let proc = scheduler::get_current_process();
    if reply_target != 0 {
        // get session
        let sess = proc.phandles.lock().get_handle(reply_target)?;
        sess.as_server_session()?.reply(UserSpacePtr(buf.0))?;
    }

    // TODO: Ensure all handles are ClientSessions
    let idx = wait_synchronization(handles, timeout)?;

    let servsess = proc.phandles.lock().get_handle(handles[idx])?.as_server_session()?;
    servsess.receive(buf)?;
    Ok(idx)
}

/// Closed the passed handle.
///
/// Does not accept 0xFFFF8001 or 0xFFFF8000 as handles.
fn close_handle(handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    proc.phandles.lock().delete_handle(handle)?;
    Ok(())
}

/// Sleep for a specified amount of time, or yield thread.
///
/// Setting nanoseconds to 0, -1, or -2 indicates a yielding type:
///
/// - 0 Yielding without core migration
/// - -1 Yielding with core migration
/// - -2 Yielding to any other thread
fn sleep_thread(nanos: usize) -> Result<(), UserspaceError> {
    if nanos == 0 {
        scheduler::schedule();
        Ok(())
    } else {
        event::wait(Some(&pit::wait_ms(nanos / 1_000_000) as &dyn Waitable)).map(|_| ())
    }
}

/// Create a new Port pair. Those ports are linked to each-other: The server will
/// receive connections from the client.
fn create_port(max_sessions: u32, _is_light: bool, _name_ptr: UserSpacePtr<[u8; 12]>) -> Result<(usize, usize), UserspaceError>{
    let (server, client) = ipc::port::new(max_sessions);
    let curproc = scheduler::get_current_process();
    let serverhnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerPort(server)));
    let clienthnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientPort(client)));
    Ok((clienthnd as _, serverhnd as _))
}

/// Allocate a new SharedMemory region. This is a memory region backed by
/// DRAM allocated from the current process' pool partition, that can be mapped
/// in different processes.
///
/// Other perm can be used to enforce permission 1, 3, or 0x10000000 if don't
/// care.
fn create_shared_memory(size: u32, _myperm: u32, _otherperm: u32) -> Result<usize, UserspaceError> {
    let frames = FrameAllocator::allocate_frames_fragmented(size as usize)?;
    let handle = Arc::new(Handle::SharedMemory(Arc::new(frames)));
    let curproc = get_current_process();
    let hnd = curproc.phandles.lock().add_handle(handle);
    Ok(hnd as _)
}

/// Maps the block supplied by the handle. The required permissions are different
/// for the process that created the handle and all other processes.
///
/// Increases reference count for the SharedMemory object. Thus in order to
/// release the memory associated with the object, all handles to it must be
/// closed and all mappings must be unmapped.
fn map_shared_memory(handle: u32, addr: usize, size: usize, perm: u32) -> Result<(), UserspaceError> {
    let perm = MemoryPermissions::from_bits(perm).ok_or(UserspaceError::InvalidMemPerms)?;
    let curproc = get_current_process();
    let mem = curproc.phandles.lock().get_handle(handle)?.as_shared_memory()?;
    // TODO: RE the switch: can we map a subsection of a shared memory?
    if size != mem.iter().map(|v| v.size()).sum() {
        return Err(UserspaceError::InvalidSize)
    }
    curproc.pmemory.lock().map_shared_mapping(mem, VirtualAddress(addr), perm.into())?;
    Ok(())
}

/// Unmaps this shared memory region. This cannot be used to partially unmap a
/// region: the address **must** be the start of the shared mapping, and the size
/// **must** be the full size of the mapping.
///
/// # Error
///
/// - InvalidAddress: address is not the start of a shared mapping
/// - InvalidSize: Size is not the same as the mapping size.
fn unmap_shared_memory(handle: u32, addr: usize, size: usize) -> Result<(), UserspaceError> {
    let curproc = get_current_process();
    let hmem = curproc.phandles.lock().get_handle(handle)?.as_shared_memory()?;
    let addr = VirtualAddress(addr);
    let mut memlock = curproc.pmemory.lock();
    {
        let qmem = memlock.query_memory(addr)?;
        let mapping = qmem.mapping();

        // Check that the given addr/size covers the full mapping.
        // TODO: Can we unmap a subsection of a shared memory?
        // BODY: I am unsure if it is allowed to unmap a subsection of a shared memory mapping.
        // This will require some reverse engineering work.
        if mapping.address() != addr {
            return Err(UserspaceError::InvalidAddress)
        }
        if mapping.length() != size {
            return Err(UserspaceError::InvalidSize)
        }

        // Check that we have the correct shared mapping.
        match mapping.mtype_ref() {
            MappingType::Shared(ref cmem) if Arc::ptr_eq(&hmem, cmem) => (),
            _ => return Err(UserspaceError::InvalidAddress)
        }
    }
    // We know that mapping = addr + size, and we know that handle == mapping.
    // Let's unmap.
    memlock.unmap(addr, size)?;
    Ok(())
}


/// Query information about an address. Will always fetch the lowest page-aligned
/// mapping that contains the provided address. Writes the output to the
/// given userspace pointer to a MemoryInfo structure.
#[inline(never)]
fn query_memory(mut meminfo: UserSpacePtrMut<MemoryInfo>, _unk: usize, addr: usize) -> Result<usize, UserspaceError> {
    let curproc = scheduler::get_current_process();
    let memlock = curproc.pmemory.lock();
    let qmem = memlock.query_memory(VirtualAddress(addr))?;
    let mapping = qmem.mapping();
    *meminfo = MemoryInfo {
        baseaddr: mapping.address().addr(),
        size: mapping.length(),
        memtype: mapping.mtype_ref().into(),
        // TODO: Handle MemoryAttributes and refcounts in query_memory
        // BODY: QueryMemory gives userspace the ability to query if a memory
        // area is being used as an IPC buffer or a device address space. We
        // should implement this.
        memattr: MemoryAttributes::empty(),
        perms: mapping.flags().into(),
        ipc_ref_count: 0,
        device_ref_count: 0,
    };
    // TODO: PageInfo Handling
    // BODY: Properly return Page Information. The horizon/NX page-info stuff
    //       is not really documented yet, so this will require some RE work.
    Ok(0)
}

/// Create a new Session pair. Those sessions are linked to each-other: The
/// server will receive requests sent through the client.
///
/// # Returns
///
/// - A handle to a ServerSession
/// - A handle to a ClientSession
fn create_session(_is_light: bool, _unk: usize) -> Result<(usize, usize), UserspaceError> {
    let (server, client) = ipc::session::new();
    let curproc = scheduler::get_current_process();
    let serverhnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerSession(server)));
    let clienthnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(client)));
    Ok((serverhnd as _, clienthnd as _))
}

impl Registers {
    /// Update the Registers with the passed result.
    fn apply0(&mut self, ret: Result<(), UserspaceError>) {
        self.apply3(ret.map(|_| (0, 0, 0)))
    }

    /// Update the Registers with the passed result.
    fn apply1(&mut self, ret: Result<usize, UserspaceError>) {
        self.apply3(ret.map(|v| (v, 0, 0)))
    }

    /// Update the Registers with the passed result.
    fn apply2(&mut self, ret: Result<(usize, usize), UserspaceError>) {
        self.apply3(ret.map(|(v0, v1)| (v0, v1, 0)))
    }

    /// Update the Registers with the passed result.
    fn apply3(&mut self, ret: Result<(usize, usize, usize), UserspaceError>) {
        self.apply4(ret.map(|(v0, v1, v2)| (v0, v1, v2, 0)))
    }

    /// Update the Registers with the passed result.
    fn apply4(&mut self, ret: Result<(usize, usize, usize, usize), UserspaceError>) {
        match ret {
            Ok((v0, v1, v2, v3)) => {
                self.eax = 0;
                self.ebx = v0;
                self.ecx = v1;
                self.edx = v2;
                self.esi = v3;
                self.edi = 0;
                self.ebp = 0;
            },
            Err(err) => {
                self.eax = err.make_ret();
                self.ebx = 0;
                self.ecx = 0;
                self.edx = 0;
                self.esi = 0;
                self.edi = 0;
                self.ebp = 0;
            }
        }
    }
}

/// Represents a register backup. The syscall wrapper constructs this structure
/// before calling syscall_handler_inner, and then pops it before returning to
/// userspace, allowing precise control over register state.
#[repr(C)]
#[derive(Debug)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct Registers {
    eax: usize,
    ebx: usize,
    ecx: usize,
    edx: usize,
    esi: usize,
    edi: usize,
    ebp: usize,
}


// TODO: Missing argument slot for SVCs on i386 backend
// BODY: Our i386 SVC ABI is currently fairly different from the ABI used by
// BODY: Horizon/NX. This is for two reasons:
// BODY:
// BODY: 1. We are missing one argument slot compared to the official SVCs, so
// BODY:    we changed the ABI to work around it.
// BODY:
// BODY: 2. The Horizon ABI "skipping" over some register is an optimization for
// BODY:    ARM, but doesn't help on i386.
// BODY:
// BODY: That being said, there is a way for us to recover the missing SVC slot.
// BODY: We are currently "wasting" x0 for the syscall number. We could avoid
// BODY: this by instead using different IDT entries for the different syscalls.
// BODY: This is actually more in line with what the Horizon/NX kernel is doing
// BODY: anyways.
// BODY:
// BODY: Once we've regained this missing slot, we'll be able to make our ABI
// BODY: match the Horizon/NX 32-bit ABI. While the "skipping over" doesn't help
// BODY: our performances, it doesn't really hurt it either, and having a uniform
// BODY: ABI across platforms would make for lower maintenance.
/// Syscall dispatcher. Dispatches to the various syscall handling functions
/// based on registers.eax, and updates the registers struct with the correct
/// return values.
pub extern fn syscall_handler_inner(registers: &mut Registers) {

    let (syscall_nr, x0, x1, x2, x3, x4, x5) = (registers.eax, registers.ebx, registers.ecx, registers.edx, registers.esi, registers.edi, registers.ebp);
    let syscall_name = SYSCALL_NAMES.get(syscall_nr).unwrap_or(&"Unknown");

    debug!("Handling syscall {} - x0: {}, x1: {}, x2: {}, x3: {}, x4: {}, x5: {}",
          syscall_name, x0, x1, x2, x3, x4, x5);

    let allowed = get_current_process().capabilities.syscall_mask.get_bit(syscall_nr);

    if cfg!(feature = "no-security-check") && !allowed {
        let curproc = get_current_process();
        error!("Process {} attempted to use unauthorized syscall {} ({:#04x})",
               curproc.name, syscall_name, syscall_nr);
    }

    let allowed = cfg!(feature = "no-security-check") || allowed;

    match (allowed, syscall_nr) {
        // Horizon-inspired syscalls!
        (true, nr::SetHeapSize) => registers.apply1(set_heap_size(x0)),
        (true, nr::QueryMemory) => registers.apply1(query_memory(UserSpacePtrMut(x0 as _), x1, x2)),
        (true, nr::ExitProcess) => registers.apply0(exit_process()),
        (true, nr::CreateThread) => registers.apply1(create_thread(x0, x1, x2, x3 as _, x4 as _)),
        (true, nr::StartThread) => registers.apply0(start_thread(x0 as _)),
        (true, nr::ExitThread) => registers.apply0(exit_thread()),
        (true, nr::SleepThread) => registers.apply0(sleep_thread(x0)),
        (true, nr::MapSharedMemory) => registers.apply0(map_shared_memory(x0 as _, x1 as _, x2 as _, x3 as _)),
        (true, nr::UnmapSharedMemory) => registers.apply0(unmap_shared_memory(x0 as _, x1 as _, x2 as _)),
        (true, nr::CloseHandle) => registers.apply0(close_handle(x0 as _)),
        (true, nr::WaitSynchronization) => registers.apply1(wait_synchronization(UserSpacePtr::from_raw_parts(x0 as _, x1), x2)),
        (true, nr::ConnectToNamedPort) => registers.apply1(connect_to_named_port(UserSpacePtr(x0 as _))),
        (true, nr::SendSyncRequestWithUserBuffer) => registers.apply0(send_sync_request_with_user_buffer(UserSpacePtrMut::from_raw_parts_mut(x0 as _, x1), x2 as _)),
        (true, nr::OutputDebugString) => registers.apply0(output_debug_string(UserSpacePtr::from_raw_parts(x0 as _, x1))),
        (true, nr::CreateSession) => registers.apply2(create_session(x0 != 0, x1 as _)),
        (true, nr::AcceptSession) => registers.apply1(accept_session(x0 as _)),
        (true, nr::ReplyAndReceiveWithUserBuffer) => registers.apply1(reply_and_receive_with_user_buffer(UserSpacePtrMut::from_raw_parts_mut(x0 as _, x1), UserSpacePtr::from_raw_parts(x2 as _, x3), x4 as _, x5)),
        (true, nr::CreateSharedMemory) => registers.apply1(create_shared_memory(x0 as _, x1 as _, x2 as _)),
        (true, nr::CreateInterruptEvent) => registers.apply1(create_interrupt_event(x0, x1 as u32)),
        (true, nr::CreatePort) => registers.apply2(create_port(x0 as _, x1 != 0, UserSpacePtr(x2 as _))),
        (true, nr::ManageNamedPort) => registers.apply1(manage_named_port(UserSpacePtr(x0 as _), x1 as _)),
        (true, nr::ConnectToPort) => registers.apply1(connect_to_port(x0 as _)),

        // KFS extensions
        #[cfg(target_arch = "i386")]
        (true, nr::MapFramebuffer) => registers.apply4(map_framebuffer()),

        // Unknown/unauthorized syscall.
        (false, _) => {
            // Attempted to call unauthorized SVC. Horizon invokes usermode
            // exception handling in some cases. Let's just kill the process for
            // now.
            let curproc = get_current_process();
            error!("Process {} attempted to use unauthorized syscall {} ({:#04x}), killing",
                   curproc.name, syscall_name, syscall_nr);
            ProcessStruct::kill_process(curproc);
        },
        _ => {
            let curproc = get_current_process();
            error!("Process {} attempted to use unknown syscall {} ({:#04x}), killing",
                   curproc.name, syscall_name, syscall_nr);
            ProcessStruct::kill_process(curproc);
        }
    }

    // Effectively kill the thread at syscall boundary
    check_thread_killed();
}

