//! Arch-specific process switch functions
//!
//! This modules describe low-level functions and structures needed to perform a process switch

use crate::process::ThreadStruct;
use alloc::sync::Arc;
use core::mem::size_of;
use crate::i386::gdt::{GDT, MAIN_TASK};
use crate::i386::gdt::GdtIndex;

/// The hardware context of a paused thread. It contains just enough registers to get the thread
/// running again.
///
/// All other registers are to be saved on the thread's kernel stack before scheduling,
/// and restored right after re-schedule.
///
/// Stored in the ThreadStruct of every thread.
#[derive(Debug)]
pub struct ThreadHardwareContext {
    /// The top of the stack, where all other registers are saved.
    esp: usize,
}

impl Default for ThreadHardwareContext {
    /// Creates an empty ThreadHardwareContext.
    fn default() -> Self {
        // the saved esp will be overwritten on schedule-out anyway
        Self { esp: 0x55555555 }
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
/// Panics if the locks protecting the MAIN_TASK TSS or DOUBLE_FAULT_TSS cannot be obtained.
///
/// # Safety:
///
/// Interrupts definitely must be masked when calling this function
#[inline(never)] // we need that sweet saved ebp + eip on the stack
pub unsafe extern "C" fn process_switch(thread_b: Arc<ThreadStruct>, thread_current: Arc<ThreadStruct>) -> Arc<ThreadStruct> {

    let esp_to_load = {
        // todo do not try to change cr3 if thread_b belongs to the same process.
        //let mut thread_current_lock_pmemory = thread_current.pmemory.try_lock()
        //    .expect("process_switch cannot get current thread' lock for writing");
        let mut thread_b_lock_pmemory = thread_b.process.pmemory.try_lock()
            .expect("process_switch cannot get destination thread' lock for writing");
        let mut thread_current_lock_phwcontext = thread_current.hwcontext.try_lock()
            .expect("process_switch cannot get current thread' lock for writing");
        let     thread_b_lock_phwcontext = thread_b.hwcontext.try_lock()
            .expect("process_switch cannot get destination thread' lock for writing");

        // Switch the memory pages
        thread_b_lock_pmemory.switch_to();

        // Update the TLS segments. They are not loaded yet.
        let mut gdt = GDT
            .r#try().expect("GDT not initialized")
            .try_lock().expect("Could not lock GDT");
        gdt.table[GdtIndex::UTlsRegion as usize].set_base(thread_b.tls_region.addr() as u32);
        gdt.table[GdtIndex::UTlsElf as usize].set_base(thread_b.tls_elf.lock().addr() as u32);
        gdt.commit(None, None, None, None, None, None);

        let current_esp: usize;
        asm!("mov $0, esp" : "=r"(current_esp) : : : "intel", "volatile");

        // on restoring, esp will point to the top of the saved registers
        let esp_to_save = current_esp - (8 + 1 + 1) * size_of::<usize>();
        thread_current_lock_phwcontext.esp = esp_to_save;

        let esp_to_load = thread_b_lock_phwcontext.esp;

        // unlock the threads, they become available to be taken between now and when B will take
        // them again on schedule in, but since there is no SMP and interrupts are off,
        // this should be ok ...
        drop(thread_b_lock_pmemory);
        //drop(thread_current_lock_pmemory);
        drop(thread_b_lock_phwcontext);
        drop(thread_current_lock_phwcontext);

        esp_to_load
    };

    // Set IOPB back to "nothing allowed" state
    // todo do not change iopb if thread_b belongs to the same process.

    // MAIN_TSS should otherwise only be locked during DOUBLE_FAULTING,
    // in which case we really shouldn't be context-switching.
    let mut main_tss = MAIN_TASK.try_lock()
        .expect("Cannot lock main tss");
    for ioport in &thread_current.process.capabilities.ioports {
        let ioport = *ioport as usize;
        main_tss.iopb[ioport / 8] = 0xFF;
    }
    drop(main_tss);

    // current is still stored in scheduler's global CURRENT_PROCESS, so it's not dropped yet.
    drop(thread_current);

    // we pass a pointer to its ThreadStruct to the thread we're about to switch to.
    // Arc::into_raw does not decrement the reference count, so it's temporarily leaked.
    // This also prevents thread B to be dropped when we're about to switch to it.
    let thread_b_whoami = Arc::into_raw(thread_b);
    let whoami: *const ThreadStruct;

    asm!("
    // Push all registers on the stack, swap to B's stack, and jump to B's schedule-in
    schedule_out:
        lea eax, resume // we push a callback function, called at the end of schedule-in
        push eax
        pushad          // pushes eax, ecx, edx, ebx, ebp, original esp, ebp, esi, edi
        pushfd          // pushes eflags

        // load B's stack, and jump to its schedule-in
        mov esp, $1

    // thread B resumes here
    schedule_in:
        // Ok ! Welcome again to B !

        // restore the saved registers
        popfd           // pop eflags
        mov [esp], edi  // edi contains our precious ThreadStruct ptr, we do not want to lose it.
        popad           // pop edi (overwritten), esi, ebp, ebx, edx, ecx, eax. Pushed esp is ignored
        ret             // ret to the callback pushed on the stack

    // If this was not the first time the thread was scheduled-in,
    // it ends up here
    resume:
        // return to rust code as if nothing happened
    "
    : "={edi}"(whoami) // at re-schedule, $edi contains a pointer to our ThreadStruct
    : "r"(esp_to_load), "{edi}"(thread_b_whoami)
    : "eax"
    : "volatile", "intel");

    // ends up here if it was not our first schedule-in

    // recreate the Arc to our ThreadStruct from the pointer that was passed to us
    let me = unsafe { Arc::from_raw(whoami) };

    // MAIN_TSS should have been unlocked during schedule-out. Re-take it.
    let mut main_tss = MAIN_TASK.try_lock()
        .expect("Cannot lock main tss");

    // Set the ESP0
    main_tss.tss.esp0 = me.kstack.get_stack_start() as u32;

    // Set IOPB
    for ioport in &me.process.capabilities.ioports {
        let ioport = *ioport as usize;
        main_tss.iopb[ioport / 8] &= !(1 << (ioport % 8));
    }

    me
}



/// Prepares the thread for its first schedule by writing default values at the start of the
/// stack that will be loaded in the registers in schedule-in.
/// See process_switch() documentation for more details.
///
/// # Safety
///
/// This function will definitely fuck up your stack, so make sure you're calling it on a
/// never-scheduled thread's empty-stack.
#[allow(clippy::fn_to_numeric_cast)]
pub unsafe fn prepare_for_first_schedule(t: &ThreadStruct, entrypoint: usize, userspace_args: (usize, usize), userspace_stack: usize) {
    #[repr(packed)]
    #[allow(clippy::missing_docs_in_private_items)]
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

    let stack_start = t.kstack.get_stack_start() as u32;

    // *     $esp       * eflags
    //                    ...
    // *  puhad's ebp   * 0xaaaaaaaa -+
    //                    ...         |
    // *  callback eip  * ...         |
    // --------------------------     |
    // *  poison ebp * 0x00000000 <---+  < "get_stack_start()"
    // *  poison eip * 0x00000000
    let initial_registers = RegistersOnStack {
        // Please keep the order of those arguments - they are currently ordered
        // the same way `pushad; pushfd;` does.
        eflags: 0x00000000, // no flag set, seems ok
        edi: 0, // Overwritten by process_switch
        esi: 0,
        ebp: stack_start,                         // -+
        esp: 0, // ignored by the popad anyway    //  |
        ebx: userspace_stack as u32,              //  |
        edx: userspace_args.1 as u32,             //  |
        ecx: userspace_args.0 as u32,             //  |
        eax: entrypoint as u32,                   //  |
        callback_eip: first_schedule as u32       //  |
        // --------------                             |
        // poison ebp        <------------------------+    * 'stack_start' *
        // poison eip
    };

    let initial_registers_stack_top = (t.kstack.get_stack_start()
        - ::core::mem::size_of::<RegistersOnStack>()) as *mut RegistersOnStack;

    ::core::ptr::write(initial_registers_stack_top, initial_registers);

    // put the pointer to the top of the structure as the $esp to be loaded on schedule-in
    t.hwcontext.lock().esp = initial_registers_stack_top as usize;
}

/// The function ret'd on, on a thread's first schedule - as setup by the prepare_for_first_schedule.
///
/// At this point, interrupts are still off. This function should ensure the thread is properly
/// switched (set up ESP0, IOPB and whatnot) and call [`scheduler_first_schedule`].
///
/// # Safety:
///
/// * Interrupts must be disabled.
/// * Arguments must respect the [`prepare_for_first_schedule`] ABI, and be popped into registers.
///
/// [`scheduler_first_schedule`]: crate::scheduler::scheduler_first_schedule.
#[naked]
unsafe fn first_schedule() {
    // just get the ProcessStruct pointer in $edi, the entrypoint in $eax, and call a rust function
    unsafe {
        asm!("
        push ebx
        push edx
        push ecx
        push eax
        push edi
        call $0
        " : : "i"(first_schedule_inner as *const u8) : : "volatile", "intel");
    }

    /// Stack is set-up, now we can run rust code.
    extern "C" fn first_schedule_inner(whoami: *const ThreadStruct, entrypoint: usize, arg1: usize, arg2: usize, userspace_stack: usize) -> ! {
        // reconstruct an Arc to our ProcessStruct from the leaked pointer
        let current = unsafe { Arc::from_raw(whoami) };

        // MAIN_TSS must have been unlocked by now.
        let mut main_tss = MAIN_TASK.try_lock()
            .expect("Cannot lock main tss");

        // Set the ESP0
        main_tss.tss.esp0 = current.kstack.get_stack_start() as u32;

        // todo do not touch iopb if we come from a thread of the same process.
        // Set IOPB
        for ioport in &current.process.capabilities.ioports {
            let ioport = *ioport as usize;
            main_tss.iopb[ioport / 8] &= !(1 << (ioport % 8));
        }

        drop(main_tss); // unlock it

        // call the scheduler to finish the high-level process switch mechanics
        unsafe {
            // safe: interrupts are off
            crate::scheduler::scheduler_first_schedule(current, || jump_to_entrypoint(entrypoint, userspace_stack, arg1, arg2));
        }

        unreachable!()
    }
}

/// Jumps to Userspace, and run a userspace program.
///
/// This function is called on the first schedule of a process or thread,
/// after all the process_switch mechanics is over, and the thread is good to go.
///
/// It jumps to ring 3 by pushing the given `ep` and `userspace_stack_ptr` on the KernelStack,
/// and executing an `iret`.
///
/// Just before doing the `iret`, it clears all general-purpose registers.
///
/// This way, just after the `iret`, cpu will be in ring 3, witl all of its registers cleared,
/// `$eip` pointing to `ep`, and `$esp` pointing to `userspace_stack_ptr`.
fn jump_to_entrypoint(ep: usize, userspace_stack_ptr: usize, arg1: usize, arg2: usize) -> ! {
    // gonna write constants in the code, cause not enough registers.
    // just check we aren't hard-coding the wrong values.
    const_assert_eq!((GdtIndex::UCode as u16) << 3 | 0b11, 0x2B);
    const_assert_eq!((GdtIndex::UData as u16) << 3 | 0b11, 0x33);
    const_assert_eq!((GdtIndex::UTlsRegion as u16) << 3 | 0b11, 0x3B);
    const_assert_eq!((GdtIndex::UTlsElf as u16) << 3 | 0b11, 0x43);
    const_assert_eq!((GdtIndex::UStack as u16) << 3 | 0b11, 0x4B);


    unsafe {
        // Safety: This is paired with an undropped SpinLockIrq (interrupt_manager) in scheduler::internal_schedule.
        // (Normally, this SpinLockIrq evens out with an identical one in the same function in the new process,
        // however, when a new process starts this object is not present, therefore we must manually decrement
        // the counter.)
        // Additionally, an iret occurs later in this function, enabling interrupts.
        crate::sync::spin_lock_irq::decrement_lock_count();
    }

    unsafe {
        asm!("
        mov ax,0x33  // ds, es <- UData, Ring 3
        mov ds,ax
        mov es,ax
        mov ax,0x3B  // fs     <- UTlsRegion, Ring 3
        mov fs,ax
        mov ax, 0x43 // gs     <- UTlsElf, Ring 3
        mov gs,ax

        // Build the fake stack for IRET
        push 0x4B   // Userland Stack, Ring 3
        push $1     // Userspace ESP
        pushfd
        push 0x2B   // Userland Code, Ring 3
        push $0     // Entrypoint

        // Clean up all registers. Also setup arguments.
        // mov ecx, arg1
        // mov edx, arg2
        mov eax, 0
        mov ebx, 0
        mov ebp, 0
        mov edi, 0
        mov esi, 0

        iretd
        " :: "r"(ep), "r"(userspace_stack_ptr), "{ecx}"(arg1), "{edx}"(arg2) :
             /* Prevent using eax as input, it's used early. */ "eax" : "intel", "volatile");
    }

    unreachable!()
}
