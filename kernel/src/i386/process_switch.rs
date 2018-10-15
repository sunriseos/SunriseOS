//! Arch-specific process switch functions
//!
//! This modules describe low-level functions and structures needed to perform a process switch

use process::{ProcessStruct, ProcessState, ProcessMemory, ProcessStructArc};
use scheduler::get_current_process;
use gdt;
use sync::SpinLock;
use alloc::sync::Arc;
use spin::RwLock;
use core::mem::size_of;
use i386::TssStruct;

/// The hardware context of a paused process. It contains just enough registers to get the process
/// running again.
///
/// All other registers are to be saved on the process's kernel stack before scheduling,
/// and restored right after re-schedule.
///
/// Stored in the ProcessStruct of every process.
#[derive(Debug)]
pub struct ProcessHardwareContext {
    esp: usize, // the top of the stack, where all other registers are saved
}

impl ProcessHardwareContext {
    pub fn new() -> Self {
        // the saved esp will be overwritten on schedule-out anyway
        ProcessHardwareContext { esp: 0x55555555 }
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
/// The stack can be prepared for schedule-in by the function prepare_for_first_schedule().
///
/// # Return
///
/// Returns an Arc to the current ProcessSwitch after the switch, which was passed on during the switch.
///
/// # Panics
///
/// Panics if the locks protecting the ProcessStruct of current or B process cannot be obtained.
///
/// # Safety:
///
/// Interrupts definitely must be masked when calling this function
#[inline(never)] // we need that sweet saved ebp + eip on the stack
pub unsafe extern "C" fn process_switch(process_b: ProcessStructArc, process_current: ProcessStructArc) -> ProcessStructArc {

    let esp_to_load = {
        let mut process_current_lock_pmemory = process_current.pmemory.try_lock()
            .expect("process_switch cannot get current process' lock for writing");
        let mut process_b_lock_pmemory = process_b.pmemory.try_lock()
            .expect("process_switch cannot get destination process' lock for writing");
        let mut process_current_lock_phwcontext = process_current.phwcontext.try_lock()
            .expect("process_switch cannot get current process' lock for writing");
        let mut process_b_lock_phwcontext = process_b.phwcontext.try_lock()
            .expect("process_switch cannot get destination process' lock for writing");

        // Switch the memory pages
        // B's memory will be the active one, switch it in place
        match ::core::mem::replace(&mut *process_b_lock_pmemory, ProcessMemory::Active) {
            ProcessMemory::Inactive(spinlck) => {
                // Since the process is the only owner of pages, holding the pages' lock implies having
                // a ref to the process, and we own a WriteGuard on the process,
                // so the pages' spinlock cannot possibly be held by someone else.
                let old_pages = spinlck.into_inner().switch_to();
                *process_current_lock_pmemory = ProcessMemory::Inactive(SpinLock::new(old_pages));
            }
            ProcessMemory::Active => {
                panic!("The process we were about to switch to had its memory marked as already active");
            }
        };

        let current_esp: usize;
        asm!("mov $0, esp" : "=r"(current_esp) : : : "intel", "volatile");

        // on restoring, esp will point to the top of the saved registers
        let esp_to_save = current_esp - (8 + 1 + 1) * size_of::<usize>();
        process_current_lock_phwcontext.esp = esp_to_save;

        let esp_to_load = process_b_lock_phwcontext.esp;

        // unlock the processes, they become available to be taken between now and when B will take
        // them again on schedule in, but since there is no SMP and interrupts are off,
        // this should be ok ...
        drop(process_b_lock_pmemory);
        drop(process_current_lock_pmemory);
        drop(process_b_lock_phwcontext);
        drop(process_current_lock_phwcontext);

        esp_to_load
    };

    // current is still stored in scheduler's global CURRENT_PROCESS, so it's not dropped yet.
    drop(process_current);

    // we pass a pointer to its ProcessStruct to the process we're about to switch to.
    // Arc::into_raw does not decrement the reference count, so it's temporarily leaked.
    // This also prevents process B to be dropped when we're about to switch to it.
    let process_b_whoami = Arc::into_raw(process_b);
    let whoami: *const ProcessStruct;

    asm!("
    // Push all registers on the stack, swap to B's stack, and jump to B's schedule-in
    schedule_out:
        lea eax, resume // we push a callback function, called at the end of schedule-in
        push eax
        pushad          // pushes eax, ecx, edx, ebx, ebp, original esp, ebp, esi, edi
        pushfd          // pushes eflags

        // load B's stack, and jump to its schedule-in
        mov esp, $1

    // Process B resumes here
    schedule_in:
        // Ok ! Welcome again to B !

        // restore the saved registers
        popfd           // pop eflags
        mov [esp], edi  // edi contains our precious ProcessStruct ptr, we do not want to lose it.
        popad           // pop edi (overwritten), esi, ebp, ebx, edx, ecx, eax. Pushed esp is ignored
        ret             // ret to the callback pushed on the stack

    // If this was not the first time the process was scheduled-in,
    // it ends up here
    resume:
        // return to rust code as if nothing happened
    "
    : "={edi}"(whoami) // at re-schedule, $edi contains a pointer to our ProcessStruct
    : "r"(esp_to_load), "{edi}"(process_b_whoami)
    : "eax"
    : "volatile", "intel");

    // ends up here if it was not our first schedule-in

    // recreate the Arc to our ProcessStruct from the pointer that was passed to us
    let me = unsafe { Arc::from_raw(whoami) };

    // Set the ESP0
    let tss = gdt::MAIN_TASK.addr() as *mut TssStruct;
    (*tss).esp0 = me.pstack.get_stack_start() as u32;

    me
}



/// Prepares the process for its first schedule by writing default values at the start of the
/// stack that will be loaded in the registers in schedule-in.
/// See process_switch() documentation for more details.
///
/// # Safety
///
/// This function will definitely fuck up your stack, so make sure you're calling it on a
/// never-scheduled process's empty-stack.
pub unsafe fn prepare_for_first_schedule(p: &ProcessStruct, entrypoint: usize, userspace_stack: usize) {
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

    let stack_start = p.pstack.get_stack_start() as u32;

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
        ebx: userspace_stack as u32,              //  |
        edx: 0,                                   //  |
        ecx: 0,                                   //  |
        eax: entrypoint as u32,                   //  |
        callback_eip: first_schedule as u32       //  |
        // --------------                             |
        // poison ebp        <------------------------+    * 'stack_start' *
        // poison eip
    };

    let initial_registers_stack_top = (p.pstack.get_stack_start()
        - ::core::mem::size_of::<RegistersOnStack>()) as *mut RegistersOnStack;

    ::core::ptr::write(initial_registers_stack_top, initial_registers);

    // put the pointer to the top of the structure as the $esp to be loaded on schedule-in
    p.phwcontext.lock().esp = initial_registers_stack_top as usize;
}

/// The function ret'd on, on a process' first schedule.
/// Interrupts are still off.
#[naked]
fn first_schedule() {
    // just get the ProcessStruct pointer in $edi, the entrypoint in $eax, and call a rust function
    unsafe {
        asm!("
        push ebx
        push eax
        push edi
        call $0
        " : : "i"(first_schedule_inner as *const u8) : : "volatile", "intel");
    }

    extern "C" fn first_schedule_inner(whoami: *const ProcessStruct, entrypoint: usize, userspace_stack: usize) -> ! {
        // reconstruct an Arc to our ProcessStruct from the leaked pointer
        let current = unsafe { Arc::from_raw(whoami) };

        // Set the ESP0
        let tss = gdt::MAIN_TASK.addr() as *mut TssStruct;
        unsafe {
            // Safety: TSS is always valid.
            (*tss).esp0 = current.pstack.get_stack_start() as u32;
        }

        // call the scheduler to finish the high-level process switch mechanics
        ::scheduler::scheduler_first_schedule(current, entrypoint, userspace_stack);

        unreachable!()
    }
}

pub fn jump_to_entrypoint(ep: usize, userspace_stack_ptr: usize) {
    unsafe {
        asm!("
        mov ax,0x2B // Set data segment selector to Userland Data, Ring 3
        mov ds,ax
        mov es,ax
        mov fs,ax
        mov gs,ax

        // Build the fake stack for IRET
        push 0x33   // Userland Stack, Ring 3
        push $1     // Userspace ESP
        pushfd
        push 0x23   // Userland Code, Ring 3
        push $0     // Entrypoint
        iretd
        " :: "r"(ep), "r"(userspace_stack_ptr) :: "intel", "volatile");
    }
}
