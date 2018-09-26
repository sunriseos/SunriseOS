///! Process

use stack::KernelStack;
use i386::mem::paging::InactivePageTables;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use spin::{RwLock, RwLockWriteGuard};
use sync::SpinLock;
use core::mem::size_of;

/// The struct representing a process. There's one for every process.
///
/// It contains many information about the process :
///
/// - Its type (regular userspace process, or kworker)
/// - Its state (Running, Scheduled, Stopped)
/// - Its memory pages
/// - Its kernel stack, for syscalls and interrupts
/// - Its hardware context, to be restored on rescheduling
///
/// The task_struct of the currently running process can be retrieved thanks to a pointer saved at
/// the bottom of every kernel stack, the ThreadInfoInStack structure.
#[derive(Debug)]
pub struct ProcessStruct {
    pub pstate:     ProcessState,
    pub pmemory:    ProcessMemory,
    pstack:     KernelStack,
    phwcontext: ProcessHardwareContext
}

/// Just a handy shortcut
pub type ProcessStructArc = Arc<RwLock<ProcessStruct>>;

/// The state of a process.
///
/// - Running: currently on the CPU
/// - Scheduled: scheduled to be running
/// - Stopped: not in the scheduled queue, waiting for an event
///
/// Since SMP is not supported, there is only one Running process.
#[derive(Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Scheduled,
    Stopped
}

/// The memory pages of this process
///
/// - Inactive contains the process's pages.
/// - Active means the already currently active ones, accessible through ACTIVE_PAGE_TABLES.
///
/// A ProcessMemory should be the only owner of a process' pages
#[derive(Debug)]
pub enum ProcessMemory {
    Inactive(SpinLock<InactivePageTables>),
    Active
}

/// The hardware context of a paused process. It contains just enough registers to get the process
/// running again.
///
/// All other registers are to be saved on the process's kernel stack before scheduling,
/// and restored right after re-schedule.
#[derive(Debug)]
pub struct ProcessHardwareContext {
    esp: usize, // the top of the stack, where all other registers are saved
}

impl ProcessStruct {
    /// Creates a new process.
    pub fn new() -> Arc<RwLock<ProcessStruct>> {
        use ::core::mem::ManuallyDrop;

        // allocate its memory space
        let pmemory = ProcessMemory::Inactive(SpinLock::new(InactivePageTables::new()));

        // allocate its kernel stack
        // we are creating a cyclic link, so
        // 1: create the ProcessStruct without a stack,
        // 2: create a stack with a weak link to the half-initialized process
        // 3: lately write this stack in the ProcessStruct
        // this is safe because this is entirely done internally in this function,
        // and until we return it, the half-initialized process is only known by us.
        //
        // we must wrap it in a ManuallyDrop in case function panics, unwinds and tries to drop it
        let mut fake_stack = unsafe {
            ManuallyDrop::new(::core::mem::uninitialized::<KernelStack>())
        };

        // hardware context will be computed later in this function, write a dummy value for now
        let dummy_hwconext = ProcessHardwareContext { esp: 0x55555555 };

        // the state of the process, stopped (for now ...)
        let pstate = ProcessState::Stopped;

        // must wrap in a manually drop for the same reason as stack, because it contains it
        let p = ManuallyDrop::new(
           Arc::new(
               RwLock::new(
                    ProcessStruct {
                        pstate,
                        pmemory,
                        pstack: ManuallyDrop::into_inner(fake_stack),
                        phwcontext : dummy_hwconext
                    }
                )
           )
        );

        // 2: lately create the stack with a link to the ProcessStruct
        let linked_stack = KernelStack::allocate_stack(Arc::downgrade(&p))
            .expect("Couldn't allocate a kernel stack");
        // 3: lately write the stack in the ProcessStruct
        unsafe {
            // safe because dst was uninitialized
            ::core::ptr::write(&mut p.write().pstack, linked_stack);
        }

        // the ProcessStruct is now safe
        let p = ManuallyDrop::into_inner(p);

        // prepare the process's stack for its first schedule-in
        unsafe {
            // safe because stack is empty, p has never run
            p.write().prepare_for_first_schedule(dummy_func);
        }

        fn dummy_func () -> ! {
            unsafe {
                // this is a new process, no SpinLock is held
                ::i386::instructions::interrupts::sti();
            }

            info!("Process switched to a new process");
            loop {
                // just do something for a while
                for i in 0..20 {
                    info!("i: {}", i);
                }
                // and re-schedule
                ::scheduler::schedule();
            }
        }

        p
    }

    /// Creates the very first process at boot.
    ///
    /// # Safety
    ///
    /// Use only for creating the very first process. Should never be used again after that.
    /// Must be using a valid KernelStack, a valid ActivePageTables.
    ///
    /// # Panics
    ///
    /// ThreadInfoInStack will be initialized, it must not already have been
    pub unsafe fn create_first_process() -> Arc<RwLock<ProcessStruct>> {

        // the state of the process, currently running
        let pstate = ProcessState::Running;

        // use the already allocated stack
        let mut pstack = KernelStack::get_current_stack();

        // the saved esp will be overwritten on schedule-out anyway
        let phwcontext = ProcessHardwareContext { esp: 0x55555555 };

        // the already currently active pages
        let pmemory = ProcessMemory::Active;

        let p = Arc::new(
            RwLock::new(
                ProcessStruct {
                    pstate,
                    pmemory,
                    pstack,
                    phwcontext
                }
            )
        );

        // create a link back to the ProcessStruct in its stack
        let link = Arc::downgrade(&p);
        p.write().pstack.link_boot_stack_to_process(link);

        p
    }

    /// Prepares the process for its first schedule by writing default values at the start of the
    /// stack that will be loaded in the registers in schedule-in.
    /// Parameter 'func' will be written on the stack, and ret'ed on at the end of the schedule-in.
    /// See process_switch() documentation for more details.
    ///
    /// # Safety
    ///
    /// This function will definitely fuck up your stack, so make sure you're calling it on a
    /// never-scheduled process's empty-stack.
    pub unsafe fn prepare_for_first_schedule(&mut self, func: fn() -> !) {
        #[repr(packed)]
        struct RegistersOnStack {
            eflags: u32,
            edi: u32,
            esi: u32,
            ebp: u32,
            esp: u32,
            ebx: u32,
            edx: u32,
            ecx: u32,
            eax: u32,
            callback_eip: u32
            // --------------
            // poison ebp
            // poison eip
        };

        let stack_start = self.pstack.get_stack_start() as u32;

        // *     $esp       * eflags
        //                    ...
        // *  puhad's ebp   * 0xaaaaaaaa -+
        //                    ...         |
        // *  callback eip  * ...         |
        // --------------------------     |
        // *  poison ebp * 0x00000000 <---+  < "get_stack_start()"
        // *  poison eip * 0x00000000
        let initial_registers = RegistersOnStack {
            eflags: 0x00000000, // no flag set, seems ok
            edi: 0,
            esi: 0,
            ebp: stack_start,                         // -+
            esp: 0, // ignored by the popad anyway    //  |
            ebx: 0,                                   //  |
            edx: 0,                                   //  |
            ecx: 0,                                   //  |
            eax: 0,                                   //  |
            callback_eip: func as u32                 //  |
            // --------------                             |
            // poison ebp        <------------------------+    * 'stack_start' *
            // poison eip
        };

        let initial_registers_stack_top = (self.pstack.get_stack_start()
            - ::core::mem::size_of::<RegistersOnStack>()) as *mut RegistersOnStack;

        ::core::ptr::write(initial_registers_stack_top, initial_registers);

        // put the pointer to the top of the structure as the $esp to be loaded on schedule-in
        self.phwcontext.esp = initial_registers_stack_top as usize;
    }
}

/// Performs the process switch, switching from currently running process A, to process B.
///
/// The process switch is composed of two parts :
///
/// * The "schedule out" part, where A takes care of saving its registers, prepares itself to be left,
///   and performs the switch by loading B's registers.
///   A is now stopped and waiting to be scheduled in again.
/// * The "schedule in" part, where B which was previously scheduled out by another process switch,
///   now restores the registers it had saved on the stack, finalises the switch,
///   and resumes its previous activity.
///
/// ### Schedule out:
///
/// The schedule-out code performs the following steps:
///
/// 1. change A's state from Running to Scheduled
/// 2. change B's state from Scheduled to Running
/// 3. switch to using B's memory space. KernelLand of A is copied to B at this point.
/// 4. save registers of A on its stack
/// 5. save special "hardware_context" registers of A in its ProcessStruct.
///    This is only the register containing the pointer to the top of the stack
///    where all other registers are saved.
/// 6. load B's special hardware_contexts registers.
///    This is where the process switch actually happens. Now we are running on B's stack,
///    and Program Counter was moved to B's schedule-in routine
///
/// ### Schedule in:
///
/// 1. restore the registers that it had saved on the stack
/// 2. return to what it was doing before
///
/// ### Switching to a fresh process:
///
/// In the special case where B is a newly born process, and it's its first time being scheduled (Owww, so cute),
/// it hasn't been scheduled out before, and doesn't have anything on the stack yet.
/// We choose to use the same schedule-in method for both cases, that means the schedule-in will
/// expect the new process to have a bunch of values on the stack that will be pop'ed into registers,
/// and finally ret' to a saved program counter on the stack.
/// This program counter can be used to control where the process will end-up on it's first schedule,
/// likely just a function that will jump straight to userspace.
///
/// The stack can be prepared for schedule-in by the function ProcessStruct::prepare_for_first_schedule().
///
/// # Panics
///
/// Panics if the locks protecting the ProcessStruct of any of the parameters cannot be obtained
/// Panics if B's strong count is 1, as it would be dropped as soon as we switch to it.
///
/// # Safety:
///
/// Interrupts definitely must be masked when calling this function
/// Process current **must be the current process**, otherwise Cthulhu is about to be unleashed
// todo maybe panic if process_current's lock addr is not == get_current()'s lock
#[inline(never)] // we need that sweet saved ebp + eip on the stack
pub unsafe extern "C" fn process_switch(process_current: ProcessStructArc,
                                        process_b: ProcessStructArc) {

    // check we won't drop the process before switching to it
    assert!(Arc::strong_count(&process_b) > 1, "Process being switched to would be dropped");

    let esp_to_load = {
        let mut process_current_lock = process_current.try_write()
            .expect("process_switch cannot get current process' lock for writing");
        let mut process_b_lock = process_b.try_write()
            .expect("process_switch cannot get destination process' lock for writing");

        // Switch the state
        process_current_lock.pstate = ProcessState::Stopped;
        process_b_lock.pstate = ProcessState::Running;

        // Switch the memory pages
        // B's memory will be the active one, switch it in place
        match ::core::mem::replace(&mut process_b_lock.pmemory, ProcessMemory::Active) {
            ProcessMemory::Inactive(spinlck) => {
                // Since the process is the only owner of pages, holding the pages' lock implies having
                // a ref to the process, and we own a WriteGuard on the process,
                // so the pages' spinlock cannot possibly be held by someone else.
                let old_pages = spinlck.into_inner().switch_to();
                process_current_lock.pmemory = ProcessMemory::Inactive(SpinLock::new(old_pages));
            }
            ProcessMemory::Active => {
                panic!("The process we were about to switch to had its memory marked as already active");
            }
        };

        let current_esp: usize;
        asm!("mov $0, esp" : "=r"(current_esp) : : : "intel", "volatile");

        // on restoring, esp will point to the top of the saved registers
        let esp_to_save = current_esp - (8 + 1 + 1) * size_of::<usize>();
        process_current_lock.phwcontext.esp = esp_to_save;

        let esp_to_load = process_b_lock.phwcontext.esp;

        // unlock the processes, they become available to be taken between now and when B will take
        // them again on schedule in, but since there is no SMP and interrupts are off,
        // this should be ok ...
        drop(process_b_lock);
        drop(process_current_lock);

        esp_to_load
    };

    // drop the Arcs, maybe destroying the current process
    drop(process_b);
    drop(process_current);

    asm!("
    // Push all registers on the stack, swap to B's stack, and jump to B's schedule-in
    schedule_out:
        lea eax, resume // we push a callback function, called at the end of schedule-in
        push eax
        pushad          // pushes eax, ecx, edx, ebx, ebp, original esp, ebp, esi, edi
        pushfd          // pushes eflags

        // load B's stack, and jump to its schedule-in
        mov esp, $0
        jmp schedule_in

    // Process B resumes here
    schedule_in:
        // Ok ! Welcome again to B !

        // restore the saved registers
        popfd // pop eflags
        popad // pop edi, esi, ebp, ebx, edx, ecx, eax. Pushed esp is ignored
        ret   // ret to the callback pushed on the stack

    // If this was not the first time the process was scheduled-in,
    // it ends up here
    resume:
        // return to rust code as if nothing happened
    "
    : : "r"(esp_to_load) : "eax" : "volatile", "intel");

    // ends up here if it was not our first schedule-in

    // well ... just return heh
}

/// Gets the current ProcessStruct from the Weak link at the base of current stack
/// Must be called when using a valid KernelStack, where the ThreadInfoInStack has been initialized
///
/// # Panics
///
/// Panics if the Weak link in the stack is broken
///
/// # Unsafe
///
/// This function is unsafe when the stack is not a KernelStack, but this should never be the case
/// after boot setup has finished, and making it actually unsafe would be a real pain.
/// See todo in KernelStack::get_kernel_stack()
pub fn get_current_process() -> Arc<RwLock<ProcessStruct>> {
    unsafe {
        // todo this is actually not safe. See doc comment
        KernelStack::get_current_linked_process()
    }.expect("The weak link in current stack points to a dropped ProcessStruct")
}
