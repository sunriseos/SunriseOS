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
use sunrise_libuser::error::{Error, TwiliError, PmError};
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

    fn create_pipe(&mut self, manager: WorkQueue<'static>) -> Result<(IPipeProxy, IPipeProxy), Error> {
        let pipe = Arc::new(Mutex::new(DumbPipe::default()));

        // Read Side
        let read_side = DumbPipeRead { pipe: pipe.clone() };
        let (server, client1) = syscalls::create_session(false, 0)?;
        let wrapper = new_session_wrapper(manager.clone(), server, read_side, DumbPipeRead::dispatch);
        manager.spawn(FutureObj::new(Box::new(wrapper)));

        // Write Side
        let write_side = DumbPipeWrite { pipe: pipe.clone() };
        let (server, client2) = syscalls::create_session(false, 0)?;
        let wrapper = new_session_wrapper(manager.clone(), server, write_side, DumbPipeWrite::dispatch);
        manager.spawn(FutureObj::new(Box::new(wrapper)));

        Ok((IPipeProxy::from(client1), IPipeProxy::from(client2)))
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

    fn create_pipe(&mut self, manager: WorkQueue<'static>) -> Result<(IPipeProxy, IPipeProxy), Error> {
        let pipe = Arc::new(Mutex::new(DumbPipe::default()));

        // Read Side
        let read_side = DumbPipeRead { pipe: pipe.clone() };
        let (server, client1) = syscalls::create_session(false, 0)?;
        let wrapper = new_session_wrapper(manager.clone(), server, read_side, DumbPipeRead::dispatch);
        manager.spawn(FutureObj::new(Box::new(wrapper)));

        // Write Side
        let write_side = DumbPipeWrite { pipe: pipe.clone() };
        let (server, client2) = syscalls::create_session(false, 0)?;
        let wrapper = new_session_wrapper(manager.clone(), server, write_side, DumbPipeWrite::dispatch);
        manager.spawn(FutureObj::new(Box::new(wrapper)));

        Ok((IPipeProxy::from(client1), IPipeProxy::from(client2)))
    }
}

lazy_static! {
    static ref PIPES: Mutex<BTreeMap<u64, (IPipeProxy, IPipeProxy, IPipeProxy)>> =
        Mutex::new(BTreeMap::new());
    static ref DATA_EVENT: (WritableEvent, ReadableEvent) = {
        sunrise_libuser::syscalls::create_event().unwrap()
    };
}

#[derive(Debug, Default)]
struct DumbPipe {
    queue: VecDeque<u8>,
    is_done: bool,
}

#[derive(Debug, Clone)]
struct DumbPipeRead {
    pipe: Arc<Mutex<DumbPipe>>,
}

#[derive(Debug, Clone)]
struct DumbPipeWrite {
    pipe: Arc<Mutex<DumbPipe>>,
}


impl IPipeAsync for DumbPipeWrite {
    fn read<'a>(&'a mut self, _work_queue: WorkQueue<'static>, _buf: &'a mut [u8]) -> FutureObj<'a, Result<u64, Error>> {
        FutureObj::new(Box::new(async move {
            Err(TwiliError::OperationUnsupported.into())
        }))
    }

    fn write<'a>(&'a mut self, _manager: WorkQueue<'static>, buf: &'a [u8]) -> FutureObj<'a, Result<(), Error>> {
        FutureObj::new(Box::new(async move {
            self.pipe.lock().queue.extend(buf);
            DATA_EVENT.0.signal().unwrap();
            Ok(())
        }))
    }
}

impl IPipeAsync for DumbPipeRead {
    fn read<'a>(&'a mut self, work_queue: WorkQueue<'static>, buf: &'a mut [u8]) -> FutureObj<'a, Result<u64, Error>> {
        FutureObj::new(Box::new(async move {
            let mut locked = DATA_EVENT.1.wait_async_cb(work_queue.clone(), || {
                let locked = self.pipe.lock();
                if !locked.queue.is_empty() || locked.is_done {
                    Some(locked)
                } else {
                    None
                }
            }).await;

            let (s1, s2) = locked.queue.as_slices();

            let counts1 = min(s1.len(), buf.len());
            buf[..counts1].copy_from_slice(&s1[..counts1]);

            let counts2 = min(s2.len(), buf.len() - counts1);
            buf[counts1..counts1 + counts2].copy_from_slice(&s2[..counts2]);

            log::info!("Read {} bytes", counts1 + counts2);

            locked.queue.drain(..counts1 + counts2);
            Ok((counts1 + counts2) as u64)
        }))
    }

    fn write<'a>(&'a mut self, _manager: WorkQueue<'static>, _buf: &'a [u8]) -> FutureObj<'a, Result<(), Error>> {
        FutureObj::new(Box::new(async move {
            Err(TwiliError::OperationUnsupported.into())
        }))
    }
}

impl Drop for DumbPipeWrite {
    fn drop(&mut self) {
        log::info!("Write side of pipe deaded.");
        self.pipe.lock().is_done = true;
        DATA_EVENT.0.signal().unwrap();
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
        sunrise_libuser::syscalls::nr::CreateSession,

        sunrise_libuser::syscalls::nr::CreateEvent,
        sunrise_libuser::syscalls::nr::SignalEvent,
        sunrise_libuser::syscalls::nr::ClearEvent,
    ],
    raw_caps: [sunrise_libuser::caps::ioport(0x60), sunrise_libuser::caps::ioport(0x64), sunrise_libuser::caps::irq_pair(1, 0x3FF)]
});