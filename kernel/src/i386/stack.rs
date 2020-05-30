//! Kernel stack
//!
//! A kernel stack is structured as follow :
//!
//!     j--------------------j  < 0xaaaa0000 = KernelStack.stack_address
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

use core::mem::size_of;
use crate::paging::lands::{VirtualSpaceLand, UserLand, KernelLand};
use crate::paging::{PAGE_SIZE, process_memory::QueryMemory, MappingAccessRights, PageState, kernel_memory::get_kernel_memory};
use crate::frame_allocator::{FrameAllocator, FrameAllocatorTrait};
use crate::mem::VirtualAddress;
use crate::error::KernelError;
use xmas_elf::ElfFile;
use xmas_elf::symbol_table::{Entry32, Entry};
use rustc_demangle::demangle as rustc_demangle;
use crate::scheduler;
use sunrise_libutils::log2_ceil;

/// The size of a kernel stack in pages, not accounting for the page guard
// Make sure this value is the same as the one in bootstrap, or bad things happen.
pub const STACK_SIZE: usize            = 8;
/// The size of a kernel stack in pages, with the page guard.
pub const STACK_SIZE_WITH_GUARD: usize = STACK_SIZE + 1;

/// The size of the kernel stack, with the page guard, as a byte count instead of a page count.
/// Used to calculate alignment.
const STACK_SIZE_WITH_GUARD_IN_BYTES: usize = STACK_SIZE_WITH_GUARD * PAGE_SIZE;

/// The alignment of the stack.
const STACK_ALIGNMENT: usize = log2_ceil(STACK_SIZE_WITH_GUARD_IN_BYTES);

/// A structure representing a kernel stack.
#[derive(Debug)]
pub struct KernelStack {
    /// The aligned address at the beginning of the stack.
    ///
    /// It falls in the page guard.
    stack_address: VirtualAddress
}

impl KernelStack {
    /// Allocates the kernel stack of a process.
    pub fn allocate_stack() -> Result<KernelStack, KernelError> {
        let mut memory = get_kernel_memory();
        let va = memory.find_virtual_space_aligned(STACK_SIZE_WITH_GUARD * PAGE_SIZE,
                                                   2usize.pow(STACK_ALIGNMENT as u32))?;
        let region = FrameAllocator::allocate_region(STACK_SIZE * PAGE_SIZE)?;

        memory.map_phys_region_to(region, va + PAGE_SIZE, MappingAccessRights::k_rw());
        memory.guard(va, PAGE_SIZE);

        let mut me = KernelStack { stack_address: va };

        // This is safe because va points to valid memory
        unsafe { me.create_poison_pointers(); };

        Ok(me)
    }

    /// Aligns down a pointer to what would be the beginning of the stack,
    /// by `and`ing with [STACK_ALIGNMENT].
    ///
    /// This is the value usually stored in `KernelStack.stack_address`.
    ///
    /// Result falls in the page guard.
    fn align_to_stack_bottom(esp: usize) -> usize {
        esp & (0xFFFFFFFF << STACK_ALIGNMENT) // 0x....0000
    }

    /// Gets the bottom of the stack by `and`ing `$esp` with [STACK_ALIGNMENT].
    ///
    /// This is the value usually stored in `KernelStack.stack_address`.
    ///
    /// Result falls in the page guard.
    ///
    // extern "C" to make sure it is called with a sane ABI
    extern "C" fn get_current_stack_bottom() -> usize {
        let esp_ptr: usize;
        unsafe { llvm_asm!("mov $0, esp" : "=r"(esp_ptr) ::: "intel" ) };
        Self::align_to_stack_bottom(esp_ptr)
    }

    /// Retrieves the current stack from `$esp`.
    ///
    /// Should be used only to retrieve the KernelStack that was given to us by the bootstrap.
    ///
    /// # Safety
    ///
    /// Unsafe because it creates duplicates of the stack structure,
    /// whose only owner should be the ProcessStruct it belongs to.
    /// This enables having several mut references pointing to the same underlying memory.
    /// Caller has to make sure no references to the stack exists when calling this function.
    ///
    /// The safe method of getting the stack is by getting current [`ProcessStruct`], *lock it*,
    /// and use its `pstack`.
    ///
    /// [`ProcessStruct`]: crate::process::ProcessStruct
    pub unsafe fn get_current_stack() -> KernelStack {
        let stack_bottom = Self::get_current_stack_bottom();
        KernelStack { stack_address: VirtualAddress(stack_bottom) }
    }

    /// We keep 2 poison pointers for fake `saved ebp` and `saved eip` at the base of the stack.
    const STACK_POISON_SIZE: usize = 2 * size_of::<usize>();

    /// Puts two poisons pointers at the base of the stack for the `saved ebp` and `saved eip`.
    unsafe fn create_poison_pointers(&mut self) {
        let saved_eip: *mut usize = (self.stack_address.addr() + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                                               - size_of::<usize>()
                                    ) as *mut usize;
        let saved_ebp: *mut usize = saved_eip.offset(-1);
        *saved_eip = 0x00000000;
        *saved_ebp = 0x00000000;
    }

    /// Get the address of the beginning of usable stack.
    ///
    /// Used for initializing `$esp` and `$ebp` of a newborn process.
    ///
    /// Points to the last poison pointer, for saved `$ebp`.
    pub fn get_stack_start(&self) -> usize {
         self.stack_address.addr() + STACK_SIZE_WITH_GUARD * PAGE_SIZE
                                   - Self::STACK_POISON_SIZE
    }

    /// Dumps the stack, displaying it in a frame-by-frame format.
    ///
    /// It can accepts an elf symbols which will be used to enhance the stack dump.
    pub fn dump_current_stack<'a>(elf_symbols: Option<(&ElfFile<'a>, &'a [Entry32])>) {
        let ebp;
        let esp;
        let eip;
        unsafe {
            llvm_asm!("
                mov $0, ebp
                mov $1, esp

                // eip can only be read through the stack after a call instruction
                call read_eip
            read_eip:
                pop $2"
            : "=r"(ebp), "=r"(esp), "=r"(eip) ::: "volatile", "intel" );
        }

        let source = StackDumpSource::new(esp, ebp, eip);

        unsafe {
            // safe: the constructed slice will be "under" the current stack top,
            //       it is considered temporarily immutable,
            //       and nobody except our thread has access to it.
            dump_stack(&source, elf_symbols);
        }
    }
}

impl Drop for KernelStack {
    /// We deallocate the stack when it is dropped
    fn drop(&mut self) {
        debug!("Dropping KernelStack {:?}", self);
        get_kernel_memory().unmap(self.stack_address, STACK_SIZE_WITH_GUARD * PAGE_SIZE);
    }
}

/* ********************************************************************************************** */

/// The minimal information needed to perform a stack dump.
#[derive(Debug)]
pub struct StackDumpSource {
    /// The initial top of the stack.
    esp: usize,
    /// The initial bottom of the first stack frame.
    ebp: usize,
    /// The initial pc.
    eip: usize
}

impl StackDumpSource {
    /// Creates a StackDumpSource from :
    ///
    /// * the initial top of the stack.
    /// * the initial bottom of the first stack frame.
    /// * the initial ip.
    pub fn new(esp: usize, ebp: usize, eip: usize) -> Self {
        Self { esp, ebp, eip }
    }
}

/// Dumps the stack from the given information, displaying it
/// in a frame-by-frame format.
///
/// This function can work on both a KernelStack and a stack in UserLand.
/// If `esp` is in KernelLand, this function will consider that we're dumping
/// a KernelStack, check that every page of what we're expecting to be a stack is mapped,
/// and dump it.
///
/// Otherwise, it will get the UserLand mapping that `esp` falls in, and dump only in this mapping.
///
/// # Safety
///
/// This function checks whether the stack is properly mapped before attempting to access it.
/// It then creates a &[u8] from what could be a shared resource.
///
/// The caller must make sure the mapping pointed to by `esp` cannot be modified while this
/// function is at work. This will often mean checking that the thread whose stack we're dumping
/// is stopped and will remain unscheduled at least until this function returns.
#[allow(unused_must_use)]
pub unsafe fn dump_stack<'a>(source: &StackDumpSource, elf_symbols: Option<(&ElfFile<'a>, &'a [Entry32])>) {
    use crate::devices::rs232::SerialLogger;
    use core::fmt::Write;

    writeln!(SerialLogger, "---------- Dumping stack ---------");

    if KernelLand::contains_address(VirtualAddress(source.esp)) {
        writeln!(SerialLogger, "# Dumping KernelStack");
        dump_kernel_stack(source.esp, source.ebp, source.eip, elf_symbols)
    } else if UserLand::contains_address(VirtualAddress(source.esp)) {
        writeln!(SerialLogger, "# Dumping UserLand stack");
        dump_user_stack(source.esp, source.ebp, source.eip, elf_symbols)
    } else {
        writeln!(SerialLogger, "# Invalid esp: {:x?}", source.esp);
    }

    writeln!(SerialLogger, "-------- End of stack dump --------");

    /// Attempts to dump a KernelStack.
    fn dump_kernel_stack<'b>(mut esp: usize, ebp: usize, eip: usize, elf: Option<(&ElfFile<'b>, &'b [Entry32])>) {

        // check if esp falls in the page_guard of what would be a KernelStack
        if esp < (KernelStack::align_to_stack_bottom(esp) + PAGE_SIZE) {
            // esp has stack overflowed. can we use ebp as esp ?
            if KernelStack::align_to_stack_bottom(esp) + PAGE_SIZE <= ebp
                && ebp < KernelStack::align_to_stack_bottom(esp) + STACK_SIZE_WITH_GUARD * PAGE_SIZE {
                writeln!(SerialLogger, "# Stack overflow detected! Using EBP as esp. (esp was {:#x})", esp);
                esp = ebp;
            } else {
                // ebp does not even fall in the same KernelStack.
                writeln!(SerialLogger, "# Invalid esp and ebp. esp: {:#x}, ebp: {:#x}, eip: {:#x}", esp, ebp, eip);
                return;
            }
        }

        let mut kmemory = get_kernel_memory();

        let stack_bottom = KernelStack::align_to_stack_bottom(esp) + PAGE_SIZE;

        // Check we have STACK_SIZE pages mapped as readable (at least) from stack_bottom.
        for i in 0..STACK_SIZE {
            let addr = VirtualAddress(stack_bottom + i * PAGE_SIZE);
            if let PageState::Present(_) = kmemory.mapping_state(addr) {
                continue;
            } else {
                // if a page was not mapped, then it's not a KernelStack
                writeln!(SerialLogger, "# Invalid esp, does not point to a KernelStack. esp: {:#x}, ebp: {:#x}, eip: {:#x}", esp, ebp, eip);
                return;
            }
        }
        // all pages were mapped. if it's not a KernelStack, at least it's close enough !
        let stack_slice = unsafe { ::core::slice::from_raw_parts(stack_bottom as *const u8,
                                                                 STACK_SIZE * PAGE_SIZE) };

        dump_stack_from_slice(stack_slice, stack_bottom, esp, ebp, eip, elf)
    }

    /// Takes the mapping `esp` falls into, consider it a stack and attempts to dump it.
    fn dump_user_stack<'c>(esp: usize, ebp: usize, eip: usize, elf: Option<(&ElfFile<'c>, &'c [Entry32])>) {
        let process = scheduler::get_current_process();
        let pmemory = process.pmemory.lock();

        // does esp point to a mapping ?
        if let QueryMemory::Used(mapping) = pmemory.query_memory(VirtualAddress(esp)) {
            // a stack would at least be readable and writable
            if mapping.flags().contains(MappingAccessRights::u_rw()) {
                let stack_slice = unsafe { ::core::slice::from_raw_parts(mapping.address().addr() as *const u8,
                                                                         mapping.length()) };
                return dump_stack_from_slice(stack_slice, mapping.address().addr(), esp, ebp, eip, elf);
            }
        }
        writeln!(SerialLogger, "# Invalid esp, does not point to a valid mapping. esp: {:#x}, ebp: {:#x}, eip: {:#x}", esp, ebp, eip);
    }
}

/// Dumps a stack, displaying it in a frame-by-frame format.
///
/// The stack is passed as a slice. The function starts at given esp, and goes down, frame by frame.
/// The original address of the stack must be given, this way it can even work on a stack that is not identity mapped,
/// therefore it should even be possible to use it on a user stack
///
/// The function will stop if it encounters:
///
/// * a null pointer as saved ebp/eip (expected at the bottom of the stack)
/// * any ebp/esp falling outside of the stack
///
/// The data of every stack frame will be hexdumped.
#[allow(unused_must_use)]
#[allow(clippy::cast_ptr_alignment)] // we're x86_32 only
fn dump_stack_from_slice<'a>(stack: &[u8], orig_address: usize, mut esp: usize, mut ebp: usize, mut eip: usize, elf: Option<(&ElfFile<'a>, &'a [Entry32])>) {
    use crate::devices::rs232::SerialLogger;
    use core::fmt::Write;
    use crate::utils::print_hexdump_as_if_at_addr;

    writeln!(SerialLogger, "# Stack start: {:#010x}, Stack end: {:#010x}", orig_address, orig_address + stack.len() - 1);

    let mut frame_nb = 0;
    loop {
        if eip == 0x00000000 || ebp == 0x00000000 { break; } // reached end of stack

        let mut funcname = "unknown";
        if let Some((elf, symbol_section)) = elf {
            if let Some(entry) = symbol_section.iter()
                .find(|entry| entry.value() <= (eip as u64) && (eip as u64) < entry.value() + entry.size())
            {
                if let Ok(s) = entry.get_name(elf) {
                    funcname = s;
                }
            }
        }
        writeln!(SerialLogger, "> Frame #{} - {}, eip: {:#010x} - esp: {:#010x} - ebp: {:#010x}", frame_nb, rustc_demangle(funcname), eip, esp, ebp);
        // todo: subtracts underflows ! This made me panic in the panic handler D:
        let esp_off = esp - orig_address;
        let ebp_off = ebp - orig_address;
        if esp_off >= stack.len() { writeln!(SerialLogger, "Invalid esp"); break; }
        if ebp_off >  stack.len() { writeln!(SerialLogger, "Invalid ebp"); break; }
        let frame_slice = &stack[esp_off..ebp_off];
        print_hexdump_as_if_at_addr(&mut SerialLogger, frame_slice, orig_address + esp_off);

        // fetch saved ebp/eip at [ebp]
        if ebp_off + 8 > stack.len() { writeln!(SerialLogger, "Cannot access saved ebp/eip"); break; }
        let saved_ebp_addr = &stack[ebp_off + 0] as *const u8 as *const usize;
        let saved_eip_addr = &stack[ebp_off + 4] as *const u8 as *const usize;

        writeln!(SerialLogger, "Saved ebp: {:#010x} @ {:#010x} (ebp) - Saved eip: {:#010x} @ {:#010x} (ebp + 4)",
                 unsafe {*saved_ebp_addr}, saved_ebp_addr as usize,
                 unsafe {*saved_eip_addr}, saved_eip_addr as usize);

        // move esp down one stack frame
        esp = ebp;

        // move ebp and eip to the saved value
        ebp = unsafe { *saved_ebp_addr };
        eip = unsafe { *saved_eip_addr };

        frame_nb += 1;
    }
}
