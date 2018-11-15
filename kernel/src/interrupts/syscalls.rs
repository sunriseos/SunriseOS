//! Syscall implementations

use i386;
use mem::{VirtualAddress, PhysicalAddress};
use mem::{FatPtr, UserSpacePtr, UserSpacePtrMut};
use paging::{PAGE_SIZE, MappingFlags};
use paging::lands::{UserLand, KernelLand};
use frame_allocator::PhysicalMemRegion;
use process::{Handle, ProcessState, ProcessStruct};
use event::{self, Waitable};
use scheduler::{self, get_current_process};
use utils;
use devices::pit;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
use core::sync::atomic::Ordering;
use sync::SpinLockIRQ;
use ipc;
use error::{KernelError, UserspaceError};

extern fn ignore_syscall(nr: usize) -> Result<(), UserspaceError> {
    // TODO: Trigger "unknown syscall" signal, for userspace signal handling.
    info!("Unknown syscall {}", nr);
    Ok(())
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
    let framebuffer_vaddr = VirtualAddress(0x80000000);
    memory.map_phys_region_to(frame_buffer_phys_region, framebuffer_vaddr, MappingFlags::u_rw());

    let addr = framebuffer_vaddr.0;
    let width = tag.framebuffer_dimensions().0 as usize;
    let height = tag.framebuffer_dimensions().1 as usize;
    let bpp = tag.framebuffer_bpp() as usize;
    Ok((addr, width, height, bpp))
}

fn create_interrupt_event(irq_num: usize, flag: u32) -> Result<usize, UserspaceError> {
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
    let mut timeout_waitable = None;
    if timeout_ns != usize::max_value() {
        timeout_waitable = Some(pit::wait_ms(timeout_ns / 1_000_000));
    }

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

fn exit_process() -> Result<(), UserspaceError> {
    let proc = ProcessStruct::kill(scheduler::get_current_process());
    Ok(())
}

fn connect_to_named_port(name: UserSpacePtr<[u8; 12]>) -> Result<usize, UserspaceError> {
    let session = ipc::connect_to_named_port(*name)?;
    info!("Got session {:?}", session);
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
    let port = match &*handle {
        &Handle::ServerPort(ref port) => port,
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
        sess.as_server_session()?.reply(UserSpacePtr(buf.0));
    }

    // TODO: Ensure all handles are receive
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
    use logger::Logger;
    use devices::rs232::SerialLogger;

    let (syscall_nr, x0, x1, x2, x3, x4, x5) = (registers.eax, registers.ebx, registers.ecx, registers.edx, registers.esi, registers.edi, registers.ebp);

    info!("Handling syscall {} - x0: {}, x1: {}, x2: {}, x3: {}, x4: {}, x5: {}",
          syscall_nr, x0, x1, x2, x3, x4, x5);

    match syscall_nr {
        // Horizon-inspired syscalls!
        0x07 => registers.apply0(exit_process()),
        0x16 => registers.apply0(close_handle(x0 as _)),
        0x18 => registers.apply1(wait_synchronization(UserSpacePtr::from_raw_parts(x0 as _, x1), x2)),
        0x1F => registers.apply1(connect_to_named_port(UserSpacePtr(x0 as _))),
        0x22 => registers.apply0(send_sync_request_with_user_buffer(UserSpacePtrMut::from_raw_parts_mut(x0 as _, x1), x2 as _)),
        0x27 => registers.apply0(output_debug_string(UserSpacePtr::from_raw_parts(x0 as _, x1))),
        0x41 => registers.apply1(accept_session(x0 as _)),
        // TODO: We need one more register for the timeout. Sad panda.
        // The ARM64 spec allows x0-x7 as input arguments, so *ideally* we need 2
        // more registers.
        0x44 => registers.apply1(reply_and_receive_with_user_buffer(UserSpacePtrMut::from_raw_parts_mut(x0 as _, x1), UserSpacePtr::from_raw_parts(x2 as _, x3), x4 as _, 0)),
        0x53 => registers.apply1(create_interrupt_event(x0, x1 as u32)),
        0x71 => registers.apply1(manage_named_port(UserSpacePtr(x0 as _), x1 as _)),

        // KFS extensions
        0x80 => registers.apply4(map_framebuffer()),
        // Unknown syscall. Should probably crash.
        u => registers.apply0(ignore_syscall(u))
    }

    if scheduler::get_current_process().pstate.load(Ordering::SeqCst) == ProcessState::Killed {
        let lock = SpinLockIRQ::new(());
        scheduler::unschedule(&lock, lock.lock());
        //unreachable!();
    }
}
