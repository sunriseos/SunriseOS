//! Syscall implementations

use i386;
use mem::{VirtualAddress, PhysicalAddress};
use mem::{UserSpacePtr, UserSpacePtrMut};
use paging::{MappingFlags, mapping::MappingType};
use frame_allocator::{PhysicalMemRegion, FrameAllocator, FrameAllocatorTrait};
use process::{Handle, ThreadStruct, ProcessStruct};
use event::{self, Waitable};
use scheduler::{self, get_current_thread, get_current_process};
use devices::pit;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use ipc;
use super::check_thread_killed;
use error::UserspaceError;
use kfs_libkern::{nr, SYSCALL_NAMES, MemoryInfo, MemoryAttributes, MemoryPermissions};

fn ignore_syscall(nr: usize) -> Result<(), UserspaceError> {
    // TODO: Trigger "unknown syscall" signal, for userspace signal handling.
    warn!("Unknown syscall {}", nr);
    Err(UserspaceError::NotImplemented)
}

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
fn set_heap_size(new_size: usize) -> Result<usize, UserspaceError> {
    let p = get_current_process();
    let mut pmemory = p.pmemory.lock();
    let heap_addr = pmemory.resize_heap(new_size)?;
    Ok(heap_addr.addr())
}

/// Maps the vga frame buffer mmio in userspace memory
fn map_framebuffer() -> Result<(usize, usize, usize, usize), UserspaceError> {
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
    memory.map_phys_region_to(frame_buffer_phys_region, framebuffer_vaddr, MappingFlags::u_rw())?;

    let addr = framebuffer_vaddr.0;
    let width = tag.framebuffer_dimensions().0 as usize;
    let height = tag.framebuffer_dimensions().1 as usize;
    let bpp = tag.framebuffer_bpp() as usize;
    Ok((addr, width, height, bpp))
}

fn create_interrupt_event(irq_num: usize, _flag: u32) -> Result<usize, UserspaceError> {
    // TODO: Flags?
    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ReadableEvent(Box::new(event::wait_event(irq_num)))));
    Ok(hnd as _)
}

// TODO: Timeout_ns should be an u64!
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

fn output_debug_string(s: UserSpacePtr<[u8]>) -> Result<(), UserspaceError> {
    info!("{}", String::from_utf8_lossy(&*s));
    Ok(())
}

/// Kills our own process.
fn exit_process() -> Result<(), UserspaceError> {
    ProcessStruct::kill_process(get_current_process());
    Ok(())
}
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
/// * `context` ignored,
/// * `sp` the top of the stack,
/// * `priority` ignored,
/// * `processor_id` ignored,
///
/// # Returns
///
/// A thread_handle to the created thread.
fn create_thread(ip: usize, _context: usize, sp: usize, _priority: u32, _processor_id: u32) -> Result<usize, UserspaceError> {
    let cur_proc = get_current_process();
    let thread = ThreadStruct::new( &cur_proc, VirtualAddress(ip), VirtualAddress(sp))?;
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
fn start_thread(thread_handle: u32) -> Result<(), UserspaceError> {
    let cur_proc = get_current_process();
    let handles_table = cur_proc.phandles.lock();
    let thread = handles_table.get_handle(thread_handle)?.as_thread_handle()?;
    Ok(ThreadStruct::start(thread)?)
}

fn connect_to_named_port(name: UserSpacePtr<[u8; 12]>) -> Result<usize, UserspaceError> {
    let session = ipc::connect_to_named_port(*name)?;
    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(session)));
    Ok(hnd as _)
}

fn manage_named_port(name_ptr: UserSpacePtr<[u8; 12]>, max_sessions: u32) -> Result<usize, UserspaceError> {
    let server = ipc::create_named_port(*name_ptr, max_sessions)?;
    let curproc = scheduler::get_current_process();
    let hnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerPort(server)));
    Ok(hnd as _)
}

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

fn send_sync_request_with_user_buffer(buf: UserSpacePtrMut<[u8]>, handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    let sess = proc.phandles.lock().get_handle(handle)?.as_client_session()?;
    sess.send_request(buf)
}

fn reply_and_receive_with_user_buffer(buf: UserSpacePtrMut<[u8]>, handles: UserSpacePtr<[u32]>, reply_target: u32, timeout: usize) -> Result<usize, UserspaceError> {
    let proc = scheduler::get_current_process();
    if reply_target != 0 {
        // get session
        let sess = proc.phandles.lock().get_handle(reply_target)?;
        sess.as_server_session()?.reply(UserSpacePtr(buf.0))?;
    }

    // TODO: Ensure all handles are ClientSessions
    let idx = wait_synchronization(handles.clone(), timeout)?;

    let servsess = proc.phandles.lock().get_handle(handles[idx])?.as_server_session()?;
    servsess.receive(buf)?;
    Ok(idx)
}

fn close_handle(handle: u32) -> Result<(), UserspaceError> {
    let proc = scheduler::get_current_process();
    proc.phandles.lock().delete_handle(handle)?;
    Ok(())
}

fn sleep_thread(nanos: usize) -> Result<(), UserspaceError> {
    if nanos == 0 {
        scheduler::schedule();
        Ok(())
    } else {
        event::wait(Some(&pit::wait_ms(nanos / 1_000_000) as &dyn Waitable)).map(|_| ())
    }
}

fn create_port(max_sessions: u32, _is_light: bool, _name_ptr: UserSpacePtr<[u8; 12]>) -> Result<(usize, usize), UserspaceError>{
    let (server, client) = ipc::port::new(max_sessions);
    let curproc = scheduler::get_current_process();
    let serverhnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerPort(server)));
    let clienthnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientPort(client)));
    Ok((clienthnd as _, serverhnd as _))
}

fn create_shared_memory(size: u32, _myperm: u32, _otherperm: u32) -> Result<usize, UserspaceError> {
    let frames = FrameAllocator::allocate_frames_fragmented(size as usize)?;
    let handle = Arc::new(Handle::SharedMemory(Arc::new(frames)));
    let curproc = get_current_process();
    let hnd = curproc.phandles.lock().add_handle(handle);
    Ok(hnd as _)
}

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

fn create_session(_is_light: bool, _unk: usize) -> Result<(usize, usize), UserspaceError> {
    let (server, client) = ipc::session::new();
    let curproc = scheduler::get_current_process();
    let serverhnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ServerSession(server)));
    let clienthnd = curproc.phandles.lock().add_handle(Arc::new(Handle::ClientSession(client)));
    Ok((serverhnd as _, clienthnd as _))
}

impl Registers {
    fn apply0(&mut self, ret: Result<(), UserspaceError>) {
        self.apply3(ret.map(|_| (0, 0, 0)))
    }

    fn apply1(&mut self, ret: Result<usize, UserspaceError>) {
        self.apply3(ret.map(|v| (v, 0, 0)))
    }

    fn apply2(&mut self, ret: Result<(usize, usize), UserspaceError>) {
        self.apply3(ret.map(|(v0, v1)| (v0, v1, 0)))
    }

    fn apply3(&mut self, ret: Result<(usize, usize, usize), UserspaceError>) {
        self.apply4(ret.map(|(v0, v1, v2)| (v0, v1, v2, 0)))
    }

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

#[repr(C)]
pub struct Registers {
    eax: usize,
    ebx: usize,
    ecx: usize,
    edx: usize,
    esi: usize,
    edi: usize,
    ebp: usize,
}

// TODO: Get a 6th argument in by putting the syscall_nr in the interrupt struct.
pub extern fn syscall_handler_inner(registers: &mut Registers) {

    let (syscall_nr, x0, x1, x2, x3, x4, x5) = (registers.eax, registers.ebx, registers.ecx, registers.edx, registers.esi, registers.edi, registers.ebp);

    debug!("Handling syscall {} - x0: {}, x1: {}, x2: {}, x3: {}, x4: {}, x5: {}",
          SYSCALL_NAMES[syscall_nr], x0, x1, x2, x3, x4, x5);

    match syscall_nr {
        // Horizon-inspired syscalls!
        nr::SetHeapSize => registers.apply1(set_heap_size(x0)),
        nr::QueryMemory => registers.apply1(query_memory(UserSpacePtrMut(x0 as _), x1, x2)),
        nr::ExitProcess => registers.apply0(exit_process()),
        nr::CreateThread => registers.apply1(create_thread(x0, x1, x2, x3 as _, x4 as _)),
        nr::StartThread => registers.apply0(start_thread(x0 as _)),
        nr::ExitThread => registers.apply0(exit_thread()),
        nr::SleepThread => registers.apply0(sleep_thread(x0)),
        nr::MapSharedMemory => registers.apply0(map_shared_memory(x0 as _, x1 as _, x2 as _, x3 as _)),
        nr::UnmapSharedMemory => registers.apply0(unmap_shared_memory(x0 as _, x1 as _, x2 as _)),
        nr::CloseHandle => registers.apply0(close_handle(x0 as _)),
        nr::WaitSynchronization => registers.apply1(wait_synchronization(UserSpacePtr::from_raw_parts(x0 as _, x1), x2)),
        nr::ConnectToNamedPort => registers.apply1(connect_to_named_port(UserSpacePtr(x0 as _))),
        nr::SendSyncRequestWithUserBuffer => registers.apply0(send_sync_request_with_user_buffer(UserSpacePtrMut::from_raw_parts_mut(x0 as _, x1), x2 as _)),
        nr::OutputDebugString => registers.apply0(output_debug_string(UserSpacePtr::from_raw_parts(x0 as _, x1))),
        nr::CreateSession => registers.apply2(create_session(x0 != 0, x1 as _)),
        nr::AcceptSession => registers.apply1(accept_session(x0 as _)),
        // TODO: We need one more register for the timeout. Sad panda.
        // The ARM64 spec allows x0-x7 as input arguments, so *ideally* we need 2
        // more registers.
        nr::ReplyAndReceiveWithUserBuffer => registers.apply1(reply_and_receive_with_user_buffer(UserSpacePtrMut::from_raw_parts_mut(x0 as _, x1), UserSpacePtr::from_raw_parts(x2 as _, x3), x4 as _, x5)),
        nr::CreateSharedMemory => registers.apply1(create_shared_memory(x0 as _, x1 as _, x2 as _)),
        nr::CreateInterruptEvent => registers.apply1(create_interrupt_event(x0, x1 as u32)),
        nr::CreatePort => registers.apply2(create_port(x0 as _, x1 != 0, UserSpacePtr(x2 as _))),
        nr::ManageNamedPort => registers.apply1(manage_named_port(UserSpacePtr(x0 as _), x1 as _)),
        nr::ConnectToPort => registers.apply1(connect_to_port(x0 as _)),

        // KFS extensions
        nr::MapFramebuffer => registers.apply4(map_framebuffer()),
        // Unknown syscall. Should probably crash.
        u => registers.apply0(ignore_syscall(u))
    }

    // Effectively kill the thread at syscall boundary
    check_thread_killed();
}

