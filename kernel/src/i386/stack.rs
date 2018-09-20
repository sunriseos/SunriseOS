//! Kernel stack
//!
//! A kernel stack is structured as follow :
//!
//!          No Page Guard
//!     j--------------------j  < 0xaaaaffff
//!     | |  thread_info   | |  < current
//!     | j----------------j |
//!     |                    |
//!     |       STACK        |
//!     |                    |
//!     j--------------------j
//!     |                    |
//!     |        |||         |
//!     |        VVV         |
//!     |                    |
//!     |                    |
//!     j--------------------j
//!     |                    |
//!     |                    |
//!     |     PAGE_GUARD     |
//!     |                    |
//!     |                    |
//!     j--------------------j < 0xaaaa0000
//!
//!  The `current` macro retrieves the thread_info structure at the base of the stacks from $esp.
//!  Since the stack is several pages long, we must ensure the stack respects some alignment
//!  in order to be able to find its bottom from any page.

use ::core::mem::size_of;
use paging::*;
use i386::mem::VirtualAddress;
use process::ProcessStruct;
use spin::RwLock;
use alloc::sync::{Arc, Weak};

/// The size of a kernel stack, not accounting for the page guard
pub const STACK_SIZE: usize            = 4;
pub const STACK_SIZE_WITH_GUARD: usize = STACK_SIZE + 1;

/// The alignment of the stack. ceil(log2(STACK_SIZE_WITH_GUARD * PAGE_SIZE))
const STACK_ALIGNEMENT: usize = 15;

/// A structure representing a kernel stack
#[derive(Debug)]
pub struct KernelStack {
    stack_address: VirtualAddress // This falls in the page guard
}

impl KernelStack {
    /// Allocates the kernel stack of a process.
    /// Puts a weak link to the ProcessStruct at the base of the stack,
    /// that can be used from anywhere to retrieve the current ProcessStruct.
    pub fn allocate_stack(belonging_process: Weak<RwLock<ProcessStruct>>) -> Option<KernelStack> {
        let mut tables = ACTIVE_PAGE_TABLES.lock();
        tables.find_available_virtual_space_aligned::<KernelLand>(STACK_SIZE_WITH_GUARD, STACK_ALIGNEMENT)
            .map(|va| {
                tables.map_range_allocate(VirtualAddress(va.addr() + PAGE_SIZE), STACK_SIZE,
                                          EntryFlags::WRITABLE);
                tables.map_page_guard(va);

                let mut me = KernelStack { stack_address: va };

                unsafe {
                    // it has just been allocated, we're not overwriting data
                    ::core::ptr::write(
                        (me.stack_address.addr() + ThreadInfoInStack::THREAD_INFO_OFFSET) as *mut ThreadInfoInStack,
                        ThreadInfoInStack::new(belonging_process));
                    // This is safe because va points to valid memory
                    me.create_poison_pointers();
                };
                me
            })
    }

    /// Allocates a kernel stack without linking it to a process
    ///
    /// # Caution
    ///
    /// This does not link the ThreadInfoInStack at the bottom of the stack to a process,
    /// this will be done when boot becomes the first process.
    ///
    /// This enables using KernelStacks early during boot, before we have processes
    pub fn allocate_boot_stack() -> Option<KernelStack> {
        Self::allocate_stack(Weak::new())
    }

    /// Finish initializing a boot stack by linking it to a ProcessStruct.
    /// This is used only for when the boot becomes the first process.
    ///
    /// # Panics
    ///
    /// Panics if a ProcessStruct is already linked in KernelStack
    pub fn link_boot_stack_to_process(&mut self, process: Weak<RwLock<ProcessStruct>>) {
        // Get the address of the ThreadInfoInStack in the stack
        let ti_ptr = (self.stack_address.addr() + ThreadInfoInStack::THREAD_INFO_OFFSET) as *mut ThreadInfoInStack;
        unsafe {
            // safe because KernelStack is well defined so it points to valid memory
            assert!((*ti_ptr).process_struct.upgrade().is_none(), "Trying to link an already linked KernelStack");
            (*ti_ptr).process_struct = process;
        }
    }

    /// Gets the bottom of the stack by and'ing $esp with STACK_ALIGNMENT
    ///
    /// extern "C" to make sure it is called with a sane ABI
    extern "C" fn get_current_stack_bottom() -> usize {
        let esp_ptr: usize;
        unsafe { asm!("mov $0, esp" : "=r"(esp_ptr) ::: "intel" ) };
        esp_ptr & (0xFFFFFFFF << STACK_ALIGNEMENT) // 0x....0000
    }

    /// Retrieves the current stack from $esp
    ///
    /// # Safety
    ///
    /// We must be using a KernelStack ! Not any random stack
    ///
    /// Also unsafe because it creates duplicates of the stack structure,
    /// who's only owner should be the ProcessStruct it belongs to.
    /// This enables having several mut references pointing to the same underlying memory.
    /// Caller has to make sure no references to the stack exists when calling this function.
    ///
    /// The safe method of getting the stack is by getting current ProcessStruct, *lock it*,
    /// and use its pstack.
    // todo put a magic value in ThreadInfoInStack
    // we could then check if we are using a KernelStack by :
    // 1 - checking $esp & aligment + t_i_offset is readable memory
    // 2 - read it and check it against the magic value
    // then we know if we are using one or not.
    pub unsafe fn get_current_stack() -> KernelStack {
        let stack_bottom = Self::get_current_stack_bottom();
        KernelStack { stack_address: VirtualAddress(stack_bottom) }
    }

    /// Tries to get an Arc to the current ProcessStruct
    /// from the weak link saved at the base of the current stack,
    /// which is itself retrieved from $esp.
    ///
    /// # Safety
    ///
    /// We must be using a KernelStack ! Not any random stack
    // todo see todo in get_current_stack()
    pub unsafe fn get_current_linked_process() -> Option<Arc<RwLock<ProcessStruct>>> {
        let stack_bottom = Self::get_current_stack_bottom();
        let ti_ptr = (stack_bottom + ThreadInfoInStack::THREAD_INFO_OFFSET) as *const ThreadInfoInStack;
        unsafe {
            // safe because KernelStack is well defined so it points to valid memory
            (*ti_ptr).process_struct.upgrade()
        }
    }

    /// We keep 2 poison pointers for fake saved ebp and saved esp at the base of the stack
    const STACK_POISON_SIZE: usize = 2 * size_of::<usize>();

    /// Puts two poisons pointers at the base of the stack for the saved ebp and saved eip
    unsafe fn create_poison_pointers(&mut self) {
        let saved_eip: *mut usize = (self.stack_address.addr() + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                                               - size_of::<ThreadInfoInStack>()
                                                               - size_of::<usize>()
                                    ) as *mut usize;
        let saved_ebp: *mut usize = saved_eip.offset(-1);
        *saved_eip = 0x00000000;
        *saved_ebp = 0x00000000;
    }

    /// Get the address of the beginning of usable stack.
    /// Used for initializing $esp and $ebp of a newborn process
    pub fn get_stack_start(&self) -> usize {
         self.stack_address.addr() + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                   - size_of::<ThreadInfoInStack>()
                                   - Self::STACK_POISON_SIZE
    }

    /// Switch to this kernel stack.
    /// The function passed as parameter will be called with the new stack, and should never return
    pub unsafe fn switch_to(self, f: fn() -> !) -> ! {
        let new_ebp_esp = self.get_stack_start();
        asm!("
        mov ebp, $0
        mov esp, $0
        jmp $1"
        :
        : "r"(new_ebp_esp), "r"(f)
        : "memory"
        : "intel", "volatile");

        unreachable!();
    }

    /// Dumps the stack on all the Loggers, displaying it in a frame-by-frame format
    ///
    /// # Safety
    ///
    /// We must be using a kernel stack ! Not any random stack
    // todo see todo on get_current_stack()
    pub unsafe fn dump_current_stack() {
        let mut ebp;
        let mut esp;
        let mut eip;
        asm!("      mov $0, ebp
                    mov $1, esp

                    // eip can only be read through the stack after a call instruction
                    call read_eip
              read_eip:
                    pop $2"
            : "=r"(ebp), "=r"(esp), "=r"(eip) ::: "volatile", "intel" );
        let stack = Self::get_current_stack();

        let stack_bottom = (stack.stack_address.addr() + PAGE_SIZE) as *const u8;
        let stack_slice = ::core::slice::from_raw_parts(stack_bottom,
                                                        STACK_SIZE * PAGE_SIZE - size_of::<ThreadInfoInStack>());

        dump_stack(stack_slice, stack_bottom as usize, esp, ebp, eip);
    }

    // TODO destroy the stack ?
}

/* ********************************************************************************************** */

/// Dumps a stack on all the Loggers, displaying it in a frame-by-frame format
/// The stack is passed as a slice. The function starts at given esp, and goes down, frame by frame.
/// The original address of the stack must be given, this way it can even work on a stack that is not identity mapped,
/// therefore it should even be possible to use it on a user stack
///
/// The function will stop if it encounters:
/// * a null pointer as saved ebp/eip (expected at the bottom of the stack)
/// * any ebp/esp falling outside of the stack
///
/// The data of every stack frame will be hexdumped
pub fn dump_stack(stack: &[u8], orig_address: usize, mut esp: usize, mut ebp: usize, mut eip: usize) {
    use logger::*;
    use core::fmt::Write;
    use utils::print_hexdump_as_if_at_addr;

    writeln!(Loggers, "---------- Dumping stack ---------");
    writeln!(Loggers, "# Stack start: {:#010x}, Stack end: {:#010x}", orig_address, orig_address + stack.len());
    let mut frame_nb = 0;
    loop {
        if eip == 0x00000000 || ebp == 0x00000000 { break; } // reached end of stack

        writeln!(Loggers, "> Frame #{} - eip: {:#010x} - esp: {:#010x} - ebp: {:#010x}", frame_nb, eip, esp, ebp);
        let esp_off = esp - orig_address;
        let ebp_off = ebp - orig_address;
        if esp_off >= stack.len() { writeln!(Loggers, "Invalid esp"); break; }
        if ebp_off >  stack.len() { writeln!(Loggers, "Invalid ebp"); break; }
        let frame_slice = &stack[esp_off..ebp_off];
        print_hexdump_as_if_at_addr(frame_slice, orig_address + esp_off);

        // fetch saved ebp/eip at [ebp]
        if ebp_off + 8 > stack.len() { writeln!(Loggers, "Cannot access saved ebp/eip"); break; }
        let saved_ebp_addr = &stack[ebp_off + 0] as *const u8 as *const usize;
        let saved_eip_addr = &stack[ebp_off + 4] as *const u8 as *const usize;

        writeln!(Loggers, "Saved ebp: {:#010x} @ {:#010x} (ebp) - Saved eip: {:#010x} @ {:#010x} (ebp + 4)",
                 unsafe {*saved_ebp_addr}, saved_ebp_addr as usize,
                 unsafe {*saved_eip_addr}, saved_eip_addr as usize);

        // move esp down one stack frame
        esp = ebp;

        // move ebp and eip to the saved value
        ebp = unsafe { *saved_ebp_addr };
        eip = unsafe { *saved_eip_addr };

        frame_nb += 1;
    }
    writeln!(Loggers, "-------- End of stack dump --------");
}

/* ********************************************************************************************** */

/// The structure we keep at the end of the stack that points back to the current process
#[repr(C)]
#[derive(Debug)]
struct ThreadInfoInStack {
    process_struct: Weak<RwLock<ProcessStruct>>
}

impl ThreadInfoInStack {
    /// Creates a ThreadInfoInStack with no associated process yet
    fn new(link: Weak<RwLock<ProcessStruct>>) -> Self {
        ThreadInfoInStack { process_struct: link }
    }

    const THREAD_INFO_OFFSET: usize = STACK_SIZE_WITH_GUARD * PAGE_SIZE - size_of::<ThreadInfoInStack>();
}
