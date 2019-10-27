#![feature(async_await)]
#![no_std]

extern crate alloc;

use core::cmp::min;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::sync::Arc;

use spin::Mutex;
use lazy_static::lazy_static;

use sunrise_libuser::{kip_header, capabilities};
use sunrise_libuser::error::{Error, PmError};
use sunrise_libuser::ipc;
use sunrise_libuser::ipc::server::{port_handler, new_session_wrapper};
use sunrise_libuser::futures::{WaitableManager, WorkQueue};
use sunrise_libuser::futures_rs::future::FutureObj;
use sunrise_libuser::syscalls;
use sunrise_libuser::twili::{ITwiliManagerService, ITwiliService, IPipeProxy, IPipeAsync};
use sunrise_libuser::types::{WritableEvent, ReadableEvent, Pid};

#[derive(Debug, Default, Clone)]
struct TwiliManIface;
impl ITwiliManagerService for TwiliManIface {
    fn register_pipes(
        &mut self,
        _manager: WorkQueue<'static>,
        pid: u64,
        stdin: IPipeProxy,
        stdout: IPipeProxy,
        stderr: IPipeProxy) -> Result<(), Error>
    {
        log::info!("Registering pipes for {}", pid);
        PIPES.lock().insert(pid, (stdin, stdout, stderr));
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct TwiliIface;
impl ITwiliService for TwiliIface {
    fn open_pipes(&mut self, _manager: WorkQueue<'static>, pid: Pid) -> Result<(IPipeProxy, IPipeProxy, IPipeProxy), Error> {
        log::info!("Opening pipes for {}", pid.0);
        PIPES.lock().remove(&pid.0)
            .ok_or(PmError::PidNotFound.into())
    }

    fn create_pipe(&mut self, manager: WorkQueue<'static>) -> Result<IPipeProxy, Error> {
        let pipe = DumbPipe(Arc::new(Mutex::new(VecDeque::new())));
        let (server, client) = syscalls::create_session(false, 0)?;
        let wrapper = new_session_wrapper(manager.clone(), server, pipe, DumbPipe::dispatch);
        manager.spawn(FutureObj::new(Box::new(wrapper)));
        Ok(IPipeProxy::from(client))
    }
}

lazy_static! {
    static ref PIPES: Mutex<BTreeMap<u64, (IPipeProxy, IPipeProxy, IPipeProxy)>> =
        Mutex::new(BTreeMap::new());
    static ref DATA_EVENT: (WritableEvent, ReadableEvent) = {
        sunrise_libuser::syscalls::create_event().unwrap()
    };
}

#[derive(Debug, Clone)]
struct DumbPipe(Arc<Mutex<VecDeque<u8>>>);
impl IPipeAsync for DumbPipe {
    fn read<'a>(&'a mut self, work_queue: WorkQueue<'static>, buf: &'a mut [u8]) -> FutureObj<'a, Result<u64, Error>> {
        FutureObj::new(Box::new(async move {
            DATA_EVENT.1.wait_async_cb(work_queue.clone(), || {
                self.0.lock().get(0).map(|_| ())
            }).await;
            let mut locked = self.0.lock();
            let count = min(buf.len(), locked.len());
            for (idx, item) in locked.drain(..count).enumerate() {
                buf[idx] = item;
            }
            Ok(count as u64)
        }))
    }

    fn write<'a>(&'a mut self, _manager: WorkQueue<'static>, buf: &'a [u8]) -> FutureObj<'a, Result<(), Error>> {
        FutureObj::new(Box::new(async move {
            self.0.lock().extend(buf);
            DATA_EVENT.0.signal().unwrap();
            Ok(())
        }))
    }
}

fn main() {
    let mut man = WaitableManager::new();

    let handler = port_handler(man.work_queue(), "twili", TwiliIface::dispatch).unwrap();
    man.work_queue().spawn(FutureObj::new(Box::new(handler)));
    let handler = port_handler(man.work_queue(), "twili:m", TwiliManIface::dispatch).unwrap();
    man.work_queue().spawn(FutureObj::new(Box::new(handler)));

    man.run();
}

kip_header!(HEADER = sunrise_libuser::caps::KipHeader {
    magic: *b"KIP1",
    name: *b"twili\0\0\0\0\0\0\0",
    title_id: 0x0200000000006480,
    process_category: sunrise_libuser::caps::ProcessCategory::KernelBuiltin,
    main_thread_priority: 0,
    default_cpu_core: 0,
    flags: 0,
    reserved: 0,
    stack_page_count: 16,
});

capabilities!(CAPABILITIES = Capabilities {
    svcs: [
        sunrise_libuser::syscalls::nr::SleepThread,
        sunrise_libuser::syscalls::nr::ExitProcess,
        sunrise_libuser::syscalls::nr::CloseHandle,
        sunrise_libuser::syscalls::nr::WaitSynchronization,
        sunrise_libuser::syscalls::nr::OutputDebugString,
        sunrise_libuser::syscalls::nr::SetThreadArea,

        sunrise_libuser::syscalls::nr::SetHeapSize,
        sunrise_libuser::syscalls::nr::QueryMemory,
        sunrise_libuser::syscalls::nr::ConnectToNamedPort,
        sunrise_libuser::syscalls::nr::SendSyncRequestWithUserBuffer,

        sunrise_libuser::syscalls::nr::ReplyAndReceiveWithUserBuffer,
        sunrise_libuser::syscalls::nr::AcceptSession,
    ],
    raw_caps: [sunrise_libuser::caps::ioport(0x60), sunrise_libuser::caps::ioport(0x64), sunrise_libuser::caps::irq_pair(1, 0x3FF)]
});