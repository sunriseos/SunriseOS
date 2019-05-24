//! Bootstrap stack
//!
//! A bootstrap stack is structured as follow :
//!
//!     j--------------------j  < 0xaaaa0000 = BootstrapStack.stack_address
//!     |                    |
//!     |                    |
//!     |     PAGE GUARD     |
//!     |                    |
//!     |                    |
//!     j--------------------j
//!     |                    |
//!     |                    |
//!     |        AAA         |
//!     |        |||         |
//!     |                    |
//!     j--------------------j
//!     |                    |
//!     |       STACK        |
//!     |                    |
//!     | j----------------j |
//!     | |  poison value  | |
//!     j-j----------------j-j < 0xaaaaffff
//!          No Page Guard
//!
//!  Since the stack is several pages long, we must ensure the stack respects some alignment
//!  in order to be able to find its bottom from any page.
//!
//! Must be consistent with KernelStack, as kernel considers it's already running on a KernelStack.

use core::mem::size_of;
use crate::paging::*;
use crate::address::VirtualAddress;
use sunrise_libutils::log2_ceil;

/// The size of a kernel stack in pages, not accounting for the page guard
// Make sure this value is the same as the one in kernel, or bad things happen.
pub const STACK_SIZE: usize            = 8;
/// The size of a kernel stack in pages, with the page guard.
pub const STACK_SIZE_WITH_GUARD: usize = STACK_SIZE + 1;

/// The size of the kernel stack, with the page guard, as a byte count instead of a page count.
/// Used to calculate alignment.
const STACK_SIZE_WITH_GUARD_IN_BYTES: usize = STACK_SIZE_WITH_GUARD * PAGE_SIZE;

/// The alignment of the stack.
const STACK_ALIGNMENT: usize = log2_ceil(STACK_SIZE_WITH_GUARD_IN_BYTES);

/// A structure representing a kernel stack
#[derive(Debug)]
pub struct BootstrapStack {
    stack_address: VirtualAddress // This falls in the page guard
}

impl BootstrapStack {
    /// Allocates the bootstrap stack
    pub fn allocate_stack() -> Option<BootstrapStack> {
        let mut tables = ACTIVE_PAGE_TABLES.lock();
        tables.find_available_virtual_space_aligned::<KernelLand>(STACK_SIZE_WITH_GUARD, STACK_ALIGNMENT)
            .map(|va| {
                tables.map_range_allocate(VirtualAddress(va.addr() + PAGE_SIZE), STACK_SIZE,
                                          EntryFlags::WRITABLE);
                tables.map_page_guard(va);

                let mut me = BootstrapStack { stack_address: va };
                unsafe {
                    // This is safe because va points to valid memory
                    me.create_poison_pointers();
                };
                me
            })
    }

    /// We keep 2 poison pointers for fake saved ebp and saved esp at the base of the stack
    const STACK_POISON_SIZE: usize = 2 * size_of::<usize>();

    /// Puts two poisons pointers at the base of the stack for the saved ebp and saved eip
    unsafe fn create_poison_pointers(&mut self) {
        let saved_eip: *mut usize = (self.stack_address.addr() + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                                               - size_of::<usize>()
                                    ) as *mut usize;
        let saved_ebp: *mut usize = saved_eip.offset(-1);
        *saved_eip = 0x00000000;
        *saved_ebp = 0x00000000;
    }

    /// Get the address of the beginning of usable stack.
    /// Used for initializing $esp and $ebp of a newborn process
    /// Points to the last poison pointer, for saved $ebp
    pub fn get_stack_start(&self) -> usize {
         self.stack_address.addr() + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                   - Self::STACK_POISON_SIZE
    }
}
