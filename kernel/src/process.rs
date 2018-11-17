//! Process

use stack::KernelStack;
use i386::process_switch::*;
use paging::process_memory::ProcessMemory;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use event::Waitable;
use sync::{RwLock, RwLockWriteGuard, SpinLockIRQ, SpinLock, Mutex, MutexGuard};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::fmt::{self, Debug};
use scheduler;
use error::{KernelError, UserspaceError};
use ipc::{ServerPort, ClientPort, ServerSession, ClientSession};
use mem::VirtualAddress;

/// The struct representing a process. There's one for every process.
///
/// It contains many information about the process :
///
/// - Its type (regular userspace process, or kworker)
/// - Its state (Running, Scheduled, Stopped)
/// - Its memory pages
/// - Its kernel stack, for syscalls and interrupts
/// - Its hardware context, to be restored on rescheduling
#[derive(Debug)]
pub struct ProcessStruct {
    /// The unique id of this process.
    pub pid:                  usize,
    /// A name for this process.
    pub name:                 String,
    /// The memory view of this process. Shared among the threads.
    pub pmemory:              Mutex<ProcessMemory>,
    /// The handles of this process. Shared among the threads.
    pub phandles:             SpinLockIRQ<HandleTable>,
    /// The threads of this process.
    /// A ProcessStruct with no thread left will eventually be dropped.
    // todo choose a better lock
    pub threads:              SpinLockIRQ<Vec<Weak<ThreadStruct>>>,

    /// A vector of readable IO ports.
    ///
    /// When task switching, the IOPB will be changed to take this into account.
    // TODO: This is i386-specific. Sucks, but it should *really* go somewhere else.
    // Maybe in ProcessMemory?
    pub ioports: Vec<u16>
}

static NEXT_PROCESS_ID: AtomicUsize = AtomicUsize::new(0);

/// The struct representing a thread. A process may own multiple threads.
#[derive(Debug)]
pub struct ThreadStruct {
    /// The state of this thread.
    pub state: ThreadStateAtomic,

    /// The kernel stack it uses for handling syscalls/irqs.
    pub kstack: KernelStack,

    /// The saved hardware context, for getting it running again on a process_switch.
    pub hwcontext: SpinLockIRQ<ThreadHardwareContext>,

    /// The process that this thread belongs to.
    ///
    /// # Description
    ///
    /// A process has a link to its threads, and every thread has a link back to its process.
    /// The thread owns a strong reference to the process it belongs to, and the process in turn
    /// has a vec of weak references to the threads it owns.
    /// This way dropping a process is done automatically when its last thread is dropped.
    ///
    /// The currently running process is indirectly kept alive by the `CURRENT_THREAD` global in scheduler.
    pub process: Arc<ProcessStruct>,

    /// Interrupt disable counter.
    ///
    /// # Description
    ///
    /// Allows recursively disabling interrupts while keeping a sane behavior.
    /// Should only be manipulated through sync::enable_interrupts and
    /// sync::disable_interrupts.
    ///
    /// Used by the SpinLockIRQ to implement recursive irqsave logic.
    pub int_disable_counter: AtomicUsize,
}

#[derive(Debug)]
pub enum Handle {
    ReadableEvent(Box<Waitable>),
    ServerPort(ServerPort),
    ClientPort(ClientPort),
    ServerSession(ServerSession),
    ClientSession(ClientSession),
}

impl Handle {
    pub fn as_waitable(&self) -> Result<&Waitable, UserspaceError> {
        match self {
            &Handle::ReadableEvent(ref waitable) => Ok(&**waitable),
            &Handle::ServerPort(ref serverport) => Ok(serverport),
            &Handle::ServerSession(ref serversession) => Ok(serversession),
            _ => Err(UserspaceError::InvalidHandle),
        }
    }

    pub fn as_server_session(&self) -> Result<ServerSession, UserspaceError> {
        if let &Handle::ServerSession(ref s) = self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    pub fn as_client_session(&self) -> Result<ClientSession, UserspaceError> {
        if let &Handle::ClientSession(ref s) = self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }
}

#[derive(Debug)]
pub struct HandleTable {
    table: BTreeMap<u32, Arc<Handle>>,
    counter: u32
}

impl HandleTable {
    pub fn new() -> HandleTable {
        HandleTable {
            table: BTreeMap::new(),
            counter: 1
        }
    }

    pub fn add_handle(&mut self, handle: Arc<Handle>) -> u32 {
        loop {
            let handlenum = self.counter;
            self.counter += 1;
            if !self.table.contains_key(&handlenum) {
                self.table.insert(handlenum, handle);
                break handlenum;
            }
        }
    }

    pub fn get_handle(&self, handle: u32) -> Result<Arc<Handle>, UserspaceError> {
        self.table.get(&handle).cloned().ok_or(UserspaceError::InvalidHandle)
    }

    pub fn delete_handle(&mut self, handle: u32) -> Result<Arc<Handle>, UserspaceError> {
        // TODO: Handle 0xFFFF8000 and 0xFFFF8001 ?
        self.table.remove(&handle).ok_or(UserspaceError::InvalidHandle)
    }
}

/// The state of a thread.
///
/// - Running: currently on the CPU
/// - Scheduled: scheduled to be running
/// - Stopped: not in the scheduled queue, waiting for an event
/// - Newborn: has never been ran, not in the schedule queue yet.
/// - Killed: dying, will be unscheduled and dropped at syscall boundary
///
/// Since SMP is not supported, there is only one Running thread.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ThreadState {
    Running = 0,
    Scheduled = 1,
    Stopped = 2,
    Newborn = 3,
    Killed = 4,
}

impl ThreadState {
    fn from_primitive(v: usize) -> ThreadState {
        match v {
            0 => ThreadState::Running,
            1 => ThreadState::Scheduled,
            2 => ThreadState::Stopped,
            3 => ThreadState::Newborn,
            4 => ThreadState::Killed,
            _ => panic!("Invalid thread state"),
        }
    }
}

pub struct ThreadStateAtomic(AtomicUsize);

impl Debug for ThreadStateAtomic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.load(Ordering::SeqCst), f)
    }
}

impl ThreadStateAtomic {
    pub fn new(state: ThreadState) -> ThreadStateAtomic {
        ThreadStateAtomic(AtomicUsize::new(state as usize))
    }

    pub fn into_inner(self) -> ThreadState {
        ThreadState::from_primitive(self.0.into_inner())
    }

    pub fn load(&self, order: Ordering) -> ThreadState {
        ThreadState::from_primitive(self.0.load(order))
    }

    pub fn store(&self, val: ThreadState, order: Ordering) {
        self.0.store(val as usize, order)
    }

    pub fn swap(&self, val: ThreadState, order: Ordering) -> ThreadState {
        ThreadState::from_primitive(self.0.swap(val as usize, order))
    }

    pub fn compare_and_swap(&self, current: ThreadState, new: ThreadState, order: Ordering) -> ThreadState {
        ThreadState::from_primitive(self.0.compare_and_swap(current as usize, new as usize, order))
    }

    pub fn compare_exchange(&self, current: ThreadState, new: ThreadState, success: Ordering, failure: Ordering) -> Result<ThreadState, ThreadState> {
        self.0.compare_exchange(current as usize, new as usize, success, failure)
            .map(ThreadState::from_primitive)
            .map_err(ThreadState::from_primitive)
    }

    pub fn compare_exchange_weak(&self, current: ThreadState, new: ThreadState, success: Ordering, failure: Ordering) -> Result<ThreadState, ThreadState> {
        self.0.compare_exchange_weak(current as usize, new as usize, success, failure)
            .map(ThreadState::from_primitive)
            .map_err(ThreadState::from_primitive)
    }

    pub fn fetch_update<F>(&self, mut f: F, fetch_order: Ordering, set_order: Ordering) -> Result<ThreadState, ThreadState>
    where
        F: FnMut(ThreadState) -> Option<ThreadState>
    {
        self.0.fetch_update(|v| f(ThreadState::from_primitive(v)).map(|v| v as usize),
                            fetch_order, set_order)
            .map(ThreadState::from_primitive)
            .map_err(ThreadState::from_primitive)
    }
}

impl ProcessStruct {
    /// Creates a new process.
    ///
    /// The created process will have no threads.
    ///
    /// # Panics
    ///
    /// Panics if max PID has been reached, which it shouldn't have since we're the first process.
    // todo: return an error instead of panicking
    pub fn new(name: String, ioports: Vec<u16>) -> Arc<ProcessStruct> {

        // allocate its memory space
        let pmemory = Mutex::new(ProcessMemory::new());

        // The PID.
        let pid = NEXT_PROCESS_ID.fetch_add(1, Ordering::SeqCst);
        if pid == usize::max_value() {
            panic!("Max PID reached!");
            // todo: return an error instead of panicking
        }

        let p = Arc::new(
            ProcessStruct {
                pid,
                name,
                pmemory,
                threads: SpinLockIRQ::new(Vec::new()),
                phandles: SpinLockIRQ::new(HandleTable::new()),
                ioports
            }
        );

        p
    }

    /// Creates the very first process at boot.
    /// Called internally by create_first_thread.
    ///
    /// The created process will have no threads.
    ///
    /// # Safety
    ///
    /// Use only for creating the very first process. Should never be used again after that.
    /// Must be using a valid KernelStack, a valid ActivePageTables.
    ///
    /// # Panics
    ///
    /// Panics if max PID has been reached, which it shouldn't have since we're the first process.
    unsafe fn create_first_process() -> Arc<ProcessStruct> {

        // the already currently active pages
        let pmemory = Mutex::new(ProcessMemory::from_active_page_tables());

        let pid = NEXT_PROCESS_ID.fetch_add(1, Ordering::SeqCst);
        if pid == usize::max_value() {
            panic!("Max PID reached!");
        }

        let p = Arc::new(
            ProcessStruct {
                pid,
                name: String::from("init"),
                pmemory,
                threads: SpinLockIRQ::new(Vec::new()),
                phandles: SpinLockIRQ::new(HandleTable::new()),
                ioports: Vec::new(),
            }
        );

        p
    }

    /// Kills a process by killing all of its threads.
    pub fn kill_process(this: Arc<Self>) {
        unimplemented!("killing a process is not yet implemented");
    }

}

impl Drop for ProcessStruct {
    fn drop(&mut self) {
        // todo this should be a debug !
        info!("Dropped a process : {:?}", self)
    }
}

impl ThreadStruct {
    /// Creates a new thread.
    ///
    /// Sets the entrypoint and userspace stack pointer.
    ///
    /// Adds itself to list of threads of the belonging process.
    ///
    /// The returned thread will be in `Newborn` state. It must be changed to `Stopped`
    /// before adding it to the schedule queue.
    ///
    /// # Safety
    ///
    /// The given entrypoint *must* point to a mapped address in that process's address space.
    /// The function makes no attempt at checking if it is kernel or userspace.
    pub unsafe fn new(belonging_process: &Arc<ProcessStruct>, ep: VirtualAddress, stack: VirtualAddress) -> Result<Arc<Self>, KernelError> {

        // allocate its kernel stack
        let kstack = KernelStack::allocate_stack()?;

        // hardware context will be computed later in this function, write a dummy value for now
        let empty_hwcontext = SpinLockIRQ::new(ThreadHardwareContext::new());

        // the state of the process, NotReady
        let state = ThreadStateAtomic::new((ThreadState::Newborn));

        let t = Arc::new(
            ThreadStruct {
                state,
                kstack,
                hwcontext : empty_hwcontext,
                int_disable_counter: AtomicUsize::new(0),
                process: Arc::clone(belonging_process),
            }
        );

        // prepare the thread's stack for its first schedule-in
        unsafe {
            // Safety: We just created the ThreadStruct, and own the only reference
            // to it, so we *know* it never has been scheduled, and cannot be.
            prepare_for_first_schedule(&t, ep.addr(), stack.addr());
        }

        // add it to the process' list of threads
        belonging_process.threads.lock().push(Arc::downgrade(&t));

        // todo: what if a process was killing all the threads, finished, dropped the lock,
        // and now we're pushing one again ?
        //
        // maybe we should cancel the operation if we can't get the lock ?
        // maybe the process struct should contain a "terminated" state that we check before pushing new threads ?
        // maybe we should poison the lock when killing a process ?
        // maybe we can use the special -empty vec- case as meaning "killed process" ?

        Ok(t)
    }

    /// Creates the very first process and thread at boot.
    ///
    /// 1: Creates a process struct that uses current page tables.
    /// 2: Creates a thread struct that uses the current KernelStack as its stack,
    ///    and points to the created process.
    /// 3: Adds itself to the created process.
    ///
    /// Thread will be in state Running.
    ///
    /// Returns the created thread.
    ///
    /// # Safety
    ///
    /// Use only for creating the very first process. Should never be used again after that.
    /// Must be using a valid KernelStack, a valid ActivePageTables.
    ///
    /// # Panics
    ///
    /// Panics if max PID has been reached, which it shouldn't have since we're the first process.
    pub unsafe fn create_first_thread() -> Arc<ThreadStruct> {

        // first create the process we will belong to
        let process = ProcessStruct::create_first_process();

        // the state of the process, currently running
        let state = ThreadStateAtomic::new(ThreadState::Running);

        // use the already allocated stack
        let kstack = KernelStack::get_current_stack();

        // the saved esp will be overwritten on schedule-out anyway
        let hwcontext = SpinLockIRQ::new(ThreadHardwareContext::new());

        let t = Arc::new(
            ThreadStruct {
                state,
                kstack,
                hwcontext,
                int_disable_counter: AtomicUsize::new(0),
                process: Arc::clone(&process),
            }
        );

        // first process now has one thread
        process.threads.lock().push(Arc::downgrade(&t));

        t
    }

    /// Sets the thread to the Killed state.
    ///
    /// We reschedule the thread (cancelling any waiting it was doing).
    /// In this state, the thread will die when attempting to return to userspace.
    pub fn kill(this: Arc<Self>) {
        this.state.store(ThreadState::Killed, Ordering::SeqCst);
        scheduler::add_to_schedule_queue(this);
    }
}

impl Drop for ThreadStruct {
    fn drop(&mut self) {
        // todo this should be a debug !
        info!("Dropped a thread : {:?}", self)
    }
}

