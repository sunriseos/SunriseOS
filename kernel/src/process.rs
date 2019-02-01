//! Process

use crate::arch::KernelStack;
use crate::arch::{ThreadHardwareContext, prepare_for_first_schedule};
use crate::paging::process_memory::ProcessMemory;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use crate::event::Waitable;
use crate::sync::{SpinLockIRQ, SpinLock, Mutex};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::fmt::{self, Debug};
use crate::scheduler;
use crate::error::{KernelError, UserspaceError};
use crate::ipc::{ServerPort, ClientPort, ServerSession, ClientSession};
use crate::mem::VirtualAddress;
use failure::Backtrace;
use crate::frame_allocator::PhysicalMemRegion;

mod capabilities;
pub use self::capabilities::ProcessCapabilities;

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

    /// Permissions of this process.
    pub capabilities:             ProcessCapabilities,

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
    // TODO: Use a better lock around thread_maternity.
    // BODY: Thread maternity currently uses a SpinLock. We should ideally use a
    // BODY: scheduling mutex there.
    thread_maternity: SpinLock<Vec<Arc<ThreadStruct>>>,
}

/// Next available PID.
///
/// PIDs are just allocated sequentially in ascending order, and reaching usize::max_value() causes a panic.
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

    /// Argument passed to the entrypoint on first schedule.
    pub arg: usize
}

/// A handle to a userspace-accessible resource.
///
/// # Description
///
/// When the userspace manipulates a kernel construct, it does so by operating
/// on Handles, which are analogious to File Descriptor in a Unix System. A
/// Handle represents all kinds of kernel structures, from IPC objects to
/// Threads and IRQ events.
///
/// A Handle may be shared across multiple processes, usually by passing it via
/// IPC. This can be used, for instance, to share a handle to a memory region,
/// allowing for the mapping of Shared Memory.
///
/// Most handles can be waited on via [crate::interrupts::syscalls::wait_synchronization], which
/// will have relevant behavior for all the different kind of handles.
#[derive(Debug)]
pub enum Handle {
    /// An event on which we can wait. Could be an IRQ, or a user-generated
    /// event.
    ReadableEvent(Box<dyn Waitable>),
    /// The server side of an IPC port. See [crate::ipc::port] for more information.
    ServerPort(ServerPort),
    /// The client side of an IPC port. See [crate::ipc::port] for more information.
    ClientPort(ClientPort),
    /// The server side of an IPC session. See [crate::ipc::session] for more
    /// information.
    ServerSession(ServerSession),
    /// The client side of an IPC session. See [crate::ipc::session] for more
    /// information.
    ClientSession(ClientSession),
    /// A thread.
    Thread(Weak<ThreadStruct>),
    /// A shared memory region. The handle holds on to the underlying physical
    /// memory, which means the memory will only get freed once all handles to
    /// it are dropped.
    SharedMemory(Arc<Vec<PhysicalMemRegion>>),
}

impl Handle {
    /// Gets the handle as a [Waitable], or return a `UserspaceError` if the handle cannot be waited on.
    pub fn as_waitable(&self) -> Result<&dyn Waitable, UserspaceError> {
        match *self {
            Handle::ReadableEvent(ref waitable) => Ok(&**waitable),
            Handle::ServerPort(ref serverport) => Ok(serverport),
            Handle::ServerSession(ref serversession) => Ok(serversession),
            _ => Err(UserspaceError::InvalidHandle),
        }
    }

    /// Casts the handle as a [ClientPort], or returns a `UserspaceError`.
    pub fn as_client_port(&self) -> Result<ClientPort, UserspaceError> {
        if let Handle::ClientPort(ref s) = *self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    /// Casts the handle as a [ServerSession], or returns a `UserspaceError`.
    pub fn as_server_session(&self) -> Result<ServerSession, UserspaceError> {
        if let Handle::ServerSession(ref s) = *self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    /// Casts the handle as a [ClientSession], or returns a `UserspaceError`.
    pub fn as_client_session(&self) -> Result<ClientSession, UserspaceError> {
        if let Handle::ClientSession(ref s) = *self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    /// Casts the handle as a Weak<[ThreadStruct]>, or returns a `UserspaceError`.
    pub fn as_thread_handle(&self) -> Result<Weak<ThreadStruct>, UserspaceError> {
        if let Handle::Thread(ref s) = *self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }

    /// Casts the handle as an Arc<Vec<[PhysicalMemRegion]>, or returns a
    /// `UserspaceError`.
    pub fn as_shared_memory(&self) -> Result<Arc<Vec<PhysicalMemRegion>>, UserspaceError> {
        if let Handle::SharedMemory(ref s) = *self {
            Ok((*s).clone())
        } else {
            Err(UserspaceError::InvalidHandle)
        }
    }
}

/// Holds the table associating userspace handle numbers to a kernel [Handle].
///
/// Each process holds a table associating a number to a kernel Handle. This
/// number is unique to that process, handles are not shared between processes.
///
/// Handle numbers hold two guarantees.
///
/// - It will not be reused ever. If a userspace attempts to use a handle after
///   closing it, it will be guaranteed to receive an InvalidHandle error.
/// - It will always be above 0, and under 0xFFFF0000.
///
/// Technically, a Horizon/NX handle is composed of two parts: The top 16 bits
/// are randomized, while the top 16 bits are an auto-incrementing counters.
/// Because of this, it is impossible to have more than 65535 handles.
///
/// In KFS, we do not yet have randomness, so the counter just goes from 1 and
/// goes up.
///
/// There exists two "meta-handles": 0xFFFF8000 and 0xFFFF8001, which always
/// point to the current process and thread, respectively. Those handles are not
/// *actually* stored in the handle table to avoid creating a reference cycle.
/// Instead, they are retrieved dynamically at runtime by the get_handle
/// function.
#[derive(Debug)]
pub struct HandleTable {
    /// Internal mapping from a handle number to a Kernel Object.
    table: BTreeMap<u32, Arc<Handle>>,
    /// The next handle's ID.
    counter: u32
}

impl Default for HandleTable {
    /// Creates an empty handle table. Note that an empty handle table still
    /// implicitly contains the meta-handles 0xFFFF8000 and 0xFFFF8001.
    fn default() -> Self {
        HandleTable {
            table: BTreeMap::new(),
            counter: 1
        }
    }
}

impl HandleTable {
    // TODO: HandleTable::add_handle should error if the table is full.
    // BODY: HandleTable::add_handle currently assumes that insertion will always
    // BODY: succeed. It does not implement any handle count limitations present
    // BODY: in Horizon/NX. Furthermore, if the handle table is completely filled
    // BODY: (e.g. there are 2^32 handles), the function will infinite loop.
    // BODY: And as if that wasn't enough: it doesn't technically guarantee a
    // BODY: handle will not get reused.
    /// Add a handle to the handle table, returning the userspace handle number
    /// associated to the given handle.
    #[allow(clippy::map_entry)]
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

    /// Gets the Kernel Handle associated with the given userspace handle number.
    pub fn get_handle(&self, handle: u32) -> Result<Arc<Handle>, UserspaceError> {
        self.table.get(&handle).cloned().ok_or(UserspaceError::InvalidHandle)
    }

    /// Deletes the mapping from the given userspace handle number. Returns the
    /// underlying Kernel Handle, in case it needs to be used (e.g. for sending
    /// to another process in an IPC move).
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
    /// ThreadState is stored in the ThreadStruct as an AtomicUsize. This function casts it back to the enum.
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

// TODO: Create/use a library to create Atomic Enum.
// BODY: We have at least one (probably more) atomic enums that we rolled by hand
// BODY: in the kernel. The one I know about: ThreadStateAtomic. Really, this
// BODY: should ideally be done automatically by a crate, either a macro or a
// BODY: custom derive. This would allow us to auto-generate the documentation.
/// Stores a ThreadState atomically.
pub struct ThreadStateAtomic(AtomicUsize);

impl Debug for ThreadStateAtomic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.load(Ordering::SeqCst), f)
    }
}

#[allow(missing_docs)]
#[allow(clippy::missing_docs_in_private_items)]
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
    pub fn new(name: String, kacs: Option<&[u8]>) -> Result<Arc<ProcessStruct>, KernelError> {
        // allocate its memory space
        let pmemory = Mutex::new(ProcessMemory::default());

        // The PID.
        let pid = NEXT_PROCESS_ID.fetch_add(1, Ordering::SeqCst);
        if pid == usize::max_value() {
            panic!("Max PID reached!");
            // todo: return an error instead of panicking
        }

        let capabilities = if let Some(kacs) = kacs {
            ProcessCapabilities::parse_kcaps(kacs)?
        } else {
            ProcessCapabilities::default()
        };

        let p = Arc::new(
            ProcessStruct {
                pid,
                name,
                pmemory,
                threads: SpinLockIRQ::new(Vec::new()),
                phandles: SpinLockIRQ::new(HandleTable::default()),
                killed: AtomicBool::new(false),
                thread_maternity: SpinLock::new(Vec::new()),
                capabilities
            }
        );

        Ok(p)
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

        Arc::new(
            ProcessStruct {
                pid,
                name: String::from("init"),
                pmemory,
                threads: SpinLockIRQ::new(Vec::new()),
                phandles: SpinLockIRQ::new(HandleTable::default()),
                killed: AtomicBool::new(false),
                thread_maternity: SpinLock::new(Vec::new()),
                capabilities: ProcessCapabilities::default(),
            }
        )
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
            if let Some(t) = Weak::upgrade(weak_thread) {
                ThreadStruct::kill(t);
            }
        }
        drop(this);
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
    pub fn new(belonging_process: &Arc<ProcessStruct>, ep: VirtualAddress, stack: VirtualAddress, arg: usize) -> Result<Weak<Self>, KernelError> {

        // allocate its kernel stack
        let kstack = KernelStack::allocate_stack()?;

        // hardware context will be computed later in this function, write a dummy value for now
        let empty_hwcontext = SpinLockIRQ::new(ThreadHardwareContext::default());

        // the state of the process, Stopped
        let state = ThreadStateAtomic::new(ThreadState::Stopped);

        let t = Arc::new(
            ThreadStruct {
                state,
                kstack,
                hwcontext : empty_hwcontext,
                int_disable_counter: AtomicUsize::new(0),
                process: Arc::clone(belonging_process),
                arg
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
        let hwcontext = SpinLockIRQ::new(ThreadHardwareContext::default());

        let t = Arc::new(
            ThreadStruct {
                state,
                kstack,
                hwcontext,
                int_disable_counter: AtomicUsize::new(0),
                process: Arc::clone(&process),
                arg: 0
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
    #[allow(clippy::needless_pass_by_value)] // more readable
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
                Err(KernelError::ThreadAlreadyStarted { backtrace: Backtrace::new() })
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

