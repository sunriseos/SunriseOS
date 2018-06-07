///! Kernel stack
/// ------------
/// A kernel stack is structured as follow :
///
///          No Page Guard
///     j--------------------j  < 0xaaaaffff
///     | |  thread_info   | |  < current
///     | j----------------j |
///     |                    |
///     |       STACK        |
///     |                    |
///     j--------------------j
///     |                    |
///     |        |||         |
///     |        VVV         |
///     |                    |
///     |                    |
///     j--------------------j
///     |                    |
///     |                    |
///     |     PAGE_GUARD     |
///     |                    |
///     |                    |
///     j--------------------j < 0xaaaa0000
///
///  The `current` macro retrieves the thread_info structure at the base of the stacks from $esp
///  Since the stack is several pages long, we must ensure the stack respects some alignment
///  in order to be able to find its bottom from any page.

use ::core::mem::size_of;
use paging::*;

/// The size of a kernel stack, not accounting for the page guard
pub const STACK_SIZE: usize            = 2;
pub const STACK_SIZE_WITH_GUARD: usize = STACK_SIZE + 1;

/// 3 pages of stack means it must be aligned on 2^14
const STACK_ALIGNEMENT: usize = 14;

/// A structure representing a kernel stack
#[derive(Debug)]
pub struct KernelStack {
    stack_address: usize // This falls in the page guard
}

impl KernelStack {
    /// Allocates the kernel stack
    // TODO We should also work on InactivePageTables, but for that we need an InactivePage structure
    // TODO that can temporary map a page so we can write to it
    pub fn allocate_stack(tables: &mut ActivePageTables) -> Option<KernelStack> {
        tables.find_available_virtual_space_aligned::<KernelLand>(STACK_SIZE_WITH_GUARD, STACK_ALIGNEMENT)
            .map(|va| {
                tables.map_range_allocate(va + PAGE_SIZE, STACK_SIZE,
                                          EntryFlags::PRESENT | EntryFlags::WRITABLE);
                tables.map_page_guard(va);

                let mut me = KernelStack { stack_address: va };
                unsafe {
                    // This is safe because va points to valid memory
                    ThreadInfoInStack::new(&mut me);
                    me.create_poison_pointers();
                };
                me
            })
    }

    /// We keep 2 poison pointers for fake saved ebp and saved esp at the base of the stack
    const STACK_POISON_SIZE: usize = 2 * size_of::<usize>();

    /// Puts two poisons pointers at the base of the stack for the saved ebp and saved eip
    unsafe fn create_poison_pointers(&mut self) {
        let saved_eip: *mut usize = (self.stack_address + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                                        - size_of::<ThreadInfoInStack>()
                                                        - size_of::<usize>()
                                    ) as *mut usize;
        let saved_ebp: *mut usize = saved_eip.offset(-1);
        *saved_eip = 0x00000000;
        *saved_ebp = 0x00000000;
    }

    /// Switch to this kernel stack.
    /// The function passed as parameter will be called with the new stack, and should never return
    pub unsafe fn switch_to(self, f: fn() -> !) -> ! {
        let new_ebp_esp: usize = self.stack_address + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                                    - size_of::<ThreadInfoInStack>()
                                                    - Self::STACK_POISON_SIZE;
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

    // TODO get current stack pointer from $esp

    // TODO destroy the stack ?
}

/* ********************************************************************************************** */

// TODO move this to the scheduler
#[repr(C)]
#[derive(Debug)]
pub struct ThreadInfoInStack {
    shitty_place_holder_field: usize,
}

const THREAD_INFO_OFFSET: usize = STACK_SIZE_WITH_GUARD * PAGE_SIZE - size_of::<ThreadInfoInStack>();

impl ThreadInfoInStack {
    /// Initializes a ThreadInfoInStack in the kernel Stack
    ///
    /// # Safety
    ///
    /// This requires KernelStack's va to point to a valid memory region of at least
    /// ThreadInfoInStack's size.
    unsafe fn new(stack: &mut KernelStack) {
        let ti = ThreadInfoInStack { shitty_place_holder_field: 0xabba1974 };

        // Copy it to the kernel stack
        let ti_ptr = (stack.stack_address + THREAD_INFO_OFFSET) as *mut ThreadInfoInStack;
        *ti_ptr = ti;
    }
}
