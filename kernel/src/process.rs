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
use sync::{SpinLockIRQ, SpinLock, Mutex};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::fmt::{self, Debug};
use scheduler;
use error::{KernelError, UserspaceError};
use ipc::{ServerPort, ClientPort, ServerSession, ClientSession};
use mem::VirtualAddress;
use failure::Backtrace;
use frame_allocator::PhysicalMemRegion;

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
    /// Marks when the process is dying.
    pub killed:               AtomicBool,

    /// A vector of readable IO ports.
    ///
    /// When task switching, the IOPB will be changed to take this into account.
    // TODO: This is i386-specific. Sucks, but it should *really* go somewhere else.
    // Maybe in ProcessMemory?
    pub ioports: Vec<u16>,

    /// An array of the created but not yet started threads.
    ///
    /// When we create a thread, we return a handle to userspace containing a weak reference to the thread,
    /// which has not been added to the schedule queue yet.
    /// To prevent it from being dropped, we must keep at least 1 strong reference somewhere.
    /// This is the job of the maternity. It holds references to threads that no one has for now.
    /// When a thread is started, its only strong reference is removed from the maternity, and put
    /// in the scheduler, which is now in charge of keeping it alive (or not).
    ///
    /// Note that we store in the process struct a strong reference to a thread, which itself
    /// has a strong reference to the same process struct. This creates a cycle, and we loose
    /// the behaviour of "a process is dropped when its last *living* thread is dropped".
    /// The non-started threads will keep the process struct alive. This makes it possible to
    /// pass a non-started thread handle to another process, and let it start it for us, even after
    /// our last living thread has died.
    ///
    /// However, because of this, if a thread creates other threads, does not share the handles,
    /// and dies before starting them, the process struct will be kept alive indefinitely
    /// by those non-started threads that no one can start, and the process will stay that way
    /// until it is explicitly killed from outside.
    // todo choose a better lock
    thread_maternity: SpinLock<Vec<Arc<ThreadStruct>>>,
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
    Thread(Weak<ThreadStruct>),
    SharedMemory(Arc<Vec<PhysicalMemRegion>>),
}

impl Handle {
    /// Gets the handle as a [Waitable], or return a `UserspaceError` if the handle cannot be waited on.
    pub fn as_waitable(&self) -> Result<&Waitable, UserspaceError> {
        match self {
            &Handle::ReadableEvent(ref waitable) => Ok(&**waitable),
            &Handle::ServerPort(ref serverport) => Ok(serverport),
            &Handle::ServerSession(ref serversession) => Ok(serversession),
            _ => Err(UserspaceError::InvalidHandle),
        }
    }

    /// Casts the handle as a [ClientPort], or returns a `UserspaceError`.
    pub fn as_client_port(&self) -> Result<ClientPort, UserspaceError> {
        if let &Handle::ClientPort(ref s) = self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    /// Casts the handle as a [ServerSession], or returns a `UserspaceError`.
    pub fn as_server_session(&self) -> Result<ServerSession, UserspaceError> {
        if let &Handle::ServerSession(ref s) = self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    /// Casts the handle as a [ClientSession], or returns a `UserspaceError`.
    pub fn as_client_session(&self) -> Result<ClientSession, UserspaceError> {
        if let &Handle::ClientSession(ref s) = self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    /// Casts the handle as a Weak<[ThreadStruct]>, or returns a `UserspaceError`.
    pub fn as_thread_handle(&self) -> Result<Weak<ThreadStruct>, UserspaceError> {
        if let &Handle::Thread(ref s) = self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    pub fn as_shared_memory(&self) -> Result<Arc<Vec<PhysicalMemRegion>>, UserspaceError> {
        if let &Handle::SharedMemory(ref s) = self {
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
/// - Killed: dying, will be unscheduled and dropped at syscall boundary
///
/// Since SMP is not supported, there is only one Running thread.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum ThreadState {
    /// Currently on the CPU.
    Running = 0,
    /// Scheduled to be running.
    Scheduled = 1,
    /// Not in the scheduled queue, waiting for an event.
    Stopped = 2,
    /// Dying, will be unscheduled and dropped at syscall boundary.
    Killed = 3,
}

impl ThreadState {
    fn from_primitive(v: usize) -> ThreadState {
        match v {
            0 => ThreadState::Running,
            1 => ThreadState::Scheduled,
            2 => ThreadState::Stopped,
            3 => ThreadState::Killed,
            _ => panic!("Invalid thread state"),
        }
    }
}

/// Stores a ThreadState atomically.
pub struct ThreadStateAtomic(AtomicUsize);

impl Debug for ThreadStateAtomic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.load(Ordering::SeqCst), f)
    }
}

#[allow(missing_docs)]
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
                killed: AtomicBool::new(false),
                thread_maternity: SpinLock::new(Vec::new()),
                ioports,
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
                killed: AtomicBool::new(false),
                thread_maternity: SpinLock::new(Vec::new()),
                ioports: Vec::new(),
            }
        );

        p
    }

    /// Kills a process by killing all of its threads.
    ///
    /// When a thread is about to return to userspace, it checks if its state is Killed.
    /// In this case it unschedules itself instead, and its ThreadStruct is dropped.
    ///
    /// When our last thread is dropped, our process struct is dropped with it.
    ///
    /// We also mark the process struct as killed to prevent race condition with
    /// another thread that would want to spawn a thread after we killed all ours.
    pub fn kill_process(this: Arc<Self>) {
        // mark the process as killed
        this.killed.store(true, Ordering::SeqCst);

        // kill our baby threads. Those threads have never run, we don't even bother
        // scheduling them so the can free their resources, just drop the hole maternity.
        this.thread_maternity.lock().clear();

        // kill all other regular threads
        for weak_thread in this.threads.lock().iter() {
            Weak::upgrade(weak_thread)
                .map(|t| ThreadStruct::kill(t));
        }
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
    /// The returned thread will be in `Stopped` state.
    ///
    /// The thread's only strong reference is stored in the process' maternity,
    /// and we return only a weak to it, that can directly be put in a thread_handle.
    pub fn new(belonging_process: &Arc<ProcessStruct>, ep: VirtualAddress, stack: VirtualAddress) -> Result<Weak<Self>, KernelError> {

        // allocate its kernel stack
        let kstack = KernelStack::allocate_stack()?;

        // hardware context will be computed later in this function, write a dummy value for now
        let empty_hwcontext = SpinLockIRQ::new(ThreadHardwareContext::new());

        // the state of the process, Stopped
        let state = ThreadStateAtomic::new(ThreadState::Stopped);

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

        // make a weak copy that we will return
        let ret = Arc::downgrade(&t);

        // add it to the process' list of threads, and to the maternity, simultaneously
        let mut maternity = belonging_process.thread_maternity.lock();
        let mut threads_vec = belonging_process.threads.lock();
        if belonging_process.killed.load(Ordering::SeqCst) {
            // process was killed while we were waiting for the lock.
            // do not add the process to the vec, cancel the thread creation.
            drop(t);
            return Err(KernelError::ProcessKilled { backtrace: Backtrace::new() })
        }
        // push a weak in the threads_vec
        threads_vec.push(Arc::downgrade(&t));
        // and put the only strong in the maternity
        maternity.push(t);

        Ok(ret)
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
    /// Does not check that the process struct is not marked killed.
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

    /// Takes a reference to a thread, removes it from the maternity, and adds it to the schedule queue.
    ///
    /// We take only a weak reference, to permit calling this function easily with a thread_handle.
    ///
    /// # Errors
    ///
    /// * `ThreadAlreadyStarted` if the weak resolution failed (the thread has already been killed).
    /// * `ThreadAlreadyStarted` if the thread was not found in the maternity.
    /// * `ProcessKilled` if the process struct was tagged `killed` before we had time to start it.
    pub fn start(this: Weak<Self>) -> Result<(), KernelError> {
        let thread = this.upgrade().ok_or(
            // the thread was dropped, meaning it has already been killed.
            KernelError::ThreadAlreadyStarted { backtrace: Backtrace::new() }
        )?;
        // remove it from the maternity
        let mut maternity = thread.process.thread_maternity.lock();
        if thread.process.killed.load(Ordering::SeqCst) {
            // process was killed while we were waiting for the lock.
            // do not start process to the vec, cancel the thread start.
            return Err(KernelError::ProcessKilled { backtrace: Backtrace::new() })
        }
        let cradle = maternity.iter().position(|baby| Arc::ptr_eq(baby, &thread));
        match cradle {
            None => {
                // the thread was not found in the maternity, meaning it had already started.
                return Err(KernelError::ThreadAlreadyStarted { backtrace: Backtrace::new() })
            },
            Some(pos) => {
                // remove it from maternity, and put it in the schedule queue
                scheduler::add_to_schedule_queue(maternity.remove(pos));
                Ok(())
            }
        }
    }

    /// Sets the thread to the `Killed` state.
    ///
    /// We reschedule the thread (cancelling any waiting it was doing).
    /// In this state, the thread will die when attempting to return to userspace.
    ///
    /// If the thread was already in the `Killed` state, this function is a no-op.
    pub fn kill(this: Arc<Self>) {
        let old_state = this.state.swap(ThreadState::Killed, Ordering::SeqCst);
        if old_state == ThreadState::Killed {
            // if the thread was already marked killed, don't do anything.
            return;
        }
        scheduler::add_to_schedule_queue(this);
    }
}

impl Drop for ThreadStruct {
    fn drop(&mut self) {
        // todo this should be a debug !
        info!("Dropped a thread : {:?}", self)
    }
}

