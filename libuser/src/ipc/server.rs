use syscalls;
use types::{Handle, HandleRef, ServerPort, ServerSession};
use core::marker::PhantomData;
use alloc::prelude::*;
use spin::Mutex;
use core::ops::{Deref, DerefMut, Index};

pub trait IWaitable {
    fn get_handle<'a>(&'a self) -> HandleRef<'a>;
    fn into_handle(self) -> Handle;
    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<(), usize>;
}

pub struct WaitableManager {
    to_add_waitables: Mutex<Vec<Box<IWaitable>>>
}

impl WaitableManager {
    pub fn new() -> WaitableManager {
        WaitableManager {
            to_add_waitables: Mutex::new(Vec::new())
        }
    }

    pub fn run(&self) -> ! {
        let mut waitables = Vec::new();
        loop {
            {
                let mut guard = self.to_add_waitables.lock();
                for waitable in guard.drain(..) {
                    waitables.push(waitable);
                }
            }

            let idx = {
                let handles = waitables.iter().map(|v| v.get_handle()).collect::<Vec<HandleRef>>();
                // TODO: new_waitable_event
                syscalls::wait_synchronization(&*handles, None).unwrap()
            };

            match waitables[idx].handle_signaled(self) {
                Ok(()) => (),
                Err(err) => {
                    syscalls::output_debug_string(&format!("Error: {}", err));
                    waitables.remove(idx);
                }
            }
        }
    }

    pub fn add_waitable(&self, waitable: Box<IWaitable>) {
        self.to_add_waitables.lock().push(waitable);
    }
}

pub trait Object {
    fn dispatch(&mut self, manager: &WaitableManager, cmdid: u32, buf: &mut [u8]) -> Result<(), usize>;
}

#[repr(C, align(16))]
struct Align16<T>(T);
impl<T> Deref for Align16<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T> DerefMut for Align16<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T, Idx> Index<Idx> for Align16<T> where T: Index<Idx> {
    type Output = T::Output;

    fn index(&self, index: Idx) -> &T::Output {
        &self.0[index]
    }
}

struct SessionWrapper<T: Object> {
    handle: ServerSession,
    object: T,

    // Ensure 16 bytes of alignment so the raw data is properly aligned.
    buf: Align16<[u8; 0x100]>
}

impl<T: Object> SessionWrapper<T> {
    pub fn new(handle: ServerSession, object: T) -> SessionWrapper<T> {
        SessionWrapper {
            handle,
            object,
            buf: Align16([0; 0x100]),
        }
    }
}

impl<T: Object> IWaitable for SessionWrapper<T> {
    fn get_handle<'a>(&'a self) -> HandleRef<'a> {
        self.handle.0.as_ref()
    }

    fn into_handle(self) -> Handle {
        self.handle.0
    }

    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<(), usize> {
        self.handle.receive(&mut self.buf[..], Some(0))?;
        let (ty, cmdid) = super::find_ty_cmdid(&self.buf[..]);
        syscalls::output_debug_string(&format!("ty={}, cmdid={}", ty, cmdid));
        match ty {
            // TODO: Handle other types.
            4 | 6 => {
                self.object.dispatch(manager, cmdid, &mut self.buf[..])?;
                self.handle.reply(&mut self.buf[..])?;
            },
            _ => unimplemented!()
        }
        Ok(())
    }
}

pub struct PortHandler<T: Object + Default> {
    handle: ServerPort,
    phantom: PhantomData<T>
}

impl<T: Object + Default + 'static> IWaitable for PortHandler<T> {
    fn get_handle<'a>(&'a self) -> HandleRef<'a> {
        self.handle.0.as_ref()
    }

    fn into_handle(self) -> Handle {
        self.handle.0
    }

    fn handle_signaled(&mut self, manager: &WaitableManager) -> Result<(), usize> {
        let session = Box::new(SessionWrapper {
            object: T::default(),
            handle: self.handle.accept()?,
            buf: Align16([0; 0x100])
        });
        manager.add_waitable(session);
        Ok(())
    }
}

fn encode_bytes(s: &str) -> u64 {
    assert!(s.len() < 8);
    let s = s.as_bytes();
    0
        | (*s.get(0).unwrap_or(&0) as u64) << 00 | (*s.get(1).unwrap_or(&0) as u64) << 08
        | (*s.get(2).unwrap_or(&0) as u64) << 16 | (*s.get(3).unwrap_or(&0) as u64) << 24
        | (*s.get(4).unwrap_or(&0) as u64) << 32 | (*s.get(5).unwrap_or(&0) as u64) << 40
        | (*s.get(6).unwrap_or(&0) as u64) << 48 | (*s.get(7).unwrap_or(&0) as u64) << 56
}

impl<T: Object + Default> PortHandler<T> {
    pub fn new(server_name: &str) -> Result<PortHandler<T>, usize> {
        use sm::IUserInterface;
        let port = IUserInterface::raw_new()?.register_service(encode_bytes(server_name), false, 0)?;
        Ok(PortHandler {
            handle: port,
            phantom: PhantomData
        })
    }

    pub fn new_managed(server_name: &str) -> Result<PortHandler<T>, usize> {
        let port = syscalls::manage_named_port(server_name, 0)?;
        Ok(PortHandler {
            handle: port,
            phantom: PhantomData
        })
    }
}
