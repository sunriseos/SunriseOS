//! Syscall implementations

use i386;
use i386::mem::PhysicalAddress;
use i386::mem::paging::{self, PageTablesSet};
use mem::{FatPtr, UserSpacePtr, UserSpacePtrMut};
use process::{Handle, ProcessState, ProcessStruct};
use event::{self, Waitable};
use scheduler;
use utils;
use devices::pit;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;
use core::sync::atomic::Ordering;
use sync::SpinLockIRQ;
use error::Error;

extern fn ignore_syscall(nr: usize) -> Result<(), Error> {
    // TODO: Trigger "unknown syscall" signal, for userspace signal handling.
    info!("Unknown syscall {}", nr);
    Ok(())
}

fn map_framebuffer(mut addr: UserSpacePtrMut<usize>, mut width: UserSpacePtrMut<usize>, mut height: UserSpacePtrMut<usize>, mut bpp: UserSpacePtrMut<usize>) -> Result<(), Error> {
    let boot_info = i386::multiboot::get_boot_information();
    let tag = boot_info.framebuffer_info_tag().expect("Framebuffer to be provided");
    let framebuffer_size = tag.framebuffer_bpp() as usize * tag.framebuffer_dimensions().0 as usize * tag.framebuffer_dimensions().1 as usize / 8;
    let framebuffer_size_pages = utils::align_up(framebuffer_size, paging::PAGE_SIZE) / paging::PAGE_SIZE;
    let mut page_tables = paging::ACTIVE_PAGE_TABLES.lock();

    let framebuffer_vaddr = page_tables.find_available_virtual_space::<paging::UserLand>(framebuffer_size_pages).expect("Hopefully there's some space");
    page_tables.map_range(PhysicalAddress(tag.framebuffer_addr()), framebuffer_vaddr, framebuffer_size_pages, paging::EntryFlags::WRITABLE);

    *addr = framebuffer_vaddr.0;
    *width = tag.framebuffer_dimensions().0 as usize;
    *height = tag.framebuffer_dimensions().1 as usize;
    *bpp = tag.framebuffer_bpp() as usize;
    Ok(())
}

fn create_interrupt_event(mut irqhandle: UserSpacePtrMut<u32>, irq_num: usize, flag: u32) -> Result<(), Error> {
    // TODO: Flags?
    let curproc = scheduler::get_current_process();
    *irqhandle = curproc.phandles.lock().add_handle(Arc::new(Handle::ReadableEvent(Box::new(event::wait_event(irq_num)))));
    Ok(())
}

// TODO: Timeout_ns should be an u64!
fn wait_synchronization(mut handle_idx: UserSpacePtrMut<usize>, handles_ptr: UserSpacePtr<[u32]>, timeout_ns: usize) -> Result<(), Error> {
    // A list of underlying handles to wait for...
    let mut handle_arr = Vec::new();
    let proc = scheduler::get_current_process();
    {
        // Make sure we drop proclock before waiting.
        let handleslock = proc.phandles.lock();
        for handle in handles_ptr.iter() {
            handle_arr.push(handleslock.get_handle(*handle));
        }
    }

    // Add a waitable for the timeout.
    let mut timeout_waitable = None;
    if timeout_ns != usize::max_value() {
        timeout_waitable = Some(pit::wait_ms(timeout_ns / 1_000_000));
    }

    // Turn the handle array and the waitable timeout into an iterator of Waitables...
    let waitables = handle_arr.iter().map(|v| match &**v {
        &Handle::ReadableEvent(ref waitable) => &**waitable
    }).chain(timeout_waitable.iter().map(|v| v as &dyn Waitable));

    // And now, wait!
    let val = match event::wait(waitables.clone()) {
        Some(v) => v,
        None => return Err(Error::Canceled)
    };

    // Figure out which waitable got triggered.
    for (idx, handle) in waitables.enumerate() {
        if handle as *const _ == val as *const _ {
            if idx == handle_arr.len() {
                return Err(Error::Timeout);
            } else {
                *handle_idx = idx;
                return Ok(());
            }
        }
    }
    // That's not supposed to happen. I heard that *sometimes*, dyn pointers will not turn up equal...
    unreachable!("No waitable triggered??!?");
}

fn output_debug_string(s: UserSpacePtr<[u8]>) -> Result<(), Error> {
    info!("{}", String::from_utf8_lossy(&*s));
    Ok(())
}

fn exit_process() -> Result<(), Error> {
    let proc = ProcessStruct::kill(scheduler::get_current_process());
    Ok(())
}
}

pub extern fn syscall_handler_inner(syscall_nr: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize, arg5: usize, arg6: usize) -> usize {
    use logger::Logger;
    use devices::rs232::SerialLogger;
    info!("Handling syscall {} - arg1: {}, arg2: {}, arg3: {}, arg4: {}, arg5: {}, arg6: {}",
          syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6);
    let ret = match syscall_nr {
        // Horizon-inspired syscalls!
        0x07 => exit_process(),
        0x18 => wait_synchronization(UserSpacePtrMut(arg1 as _), UserSpacePtr(unsafe {mem::transmute(FatPtr {
            data: arg2,
            len: arg3
        })}), arg4),
        0x27 => output_debug_string(UserSpacePtr(unsafe {mem::transmute(FatPtr {
            data: arg1,
            len: arg2
        })})),
        0x53 => create_interrupt_event(UserSpacePtrMut(arg1 as _), arg2, arg3 as u32),
        //0x79 => create_process(arg1, arg2),

        // KFS extensions
        0x80 => map_framebuffer(UserSpacePtrMut(arg1 as _), UserSpacePtrMut(arg2 as _), UserSpacePtrMut(arg3 as _), UserSpacePtrMut(arg4 as _)),

        // Unknown syscall. Should probably crash.
        u => ignore_syscall(u)
    };

    if scheduler::get_current_process().pstate.load(Ordering::SeqCst) == ProcessState::Killed {
        let lock = SpinLockIRQ::new(());
        scheduler::unschedule(&lock, lock.lock());
        //unreachable!();
    }
    match ret {
        Ok(()) => 0,
        Err(err) => err.make_ret()
    }
}
