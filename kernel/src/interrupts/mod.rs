use i386::structures::idt::{ExceptionStackFrame, PageFaultErrorCode, Idt};
use i386::instructions::interrupts::sti;
use i386::pio::Pio;
use io::Io;
use mem::{VirtualAddress, PhysicalAddress};
use paging::lands::KernelLand;
use paging::{MappingFlags, kernel_memory::get_kernel_memory};
use i386::{stack, TssStruct, PrivilegeLevel};
use i386;
use gdt;
use xmas_elf::ElfFile;
use xmas_elf::sections::SectionData;

use core::fmt::Write;
use core::slice;
use sync::SpinLock;
use sync;
use utils;
use devices::pic;

mod irq;
mod syscalls;

extern "x86-interrupt" fn divide_by_zero_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("Attempted to divide by zero: {:?}", stack_frame);
}

extern "x86-interrupt" fn debug_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("An unexpected debug interrupt occured: {:?}", stack_frame);
}

extern "x86-interrupt" fn non_maskable_interrupt_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("An unexpected non-maskable (but still kinda maskable) interrupt occured: {:?}", stack_frame);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: &mut ExceptionStackFrame) {}

extern "x86-interrupt" fn overflow_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("Unexpected overflow interrupt occured: {:?}", stack_frame);
}

extern "x86-interrupt" fn bound_range_exceeded_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("Unexpected bound-range exception occured: {:?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("An invalid opcode was executed: {:?}", stack_frame);
}

extern "x86-interrupt" fn device_not_available_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("A device not available exception occured: {:?}");
}

fn double_fault_handler() {
    // Disable interrupts forever!
    unsafe {
        sync::permanently_disable_interrupts();
    }

    // Acquire kernel elf.
    let info = i386::multiboot::get_boot_information();
    let mut module = ::elf_loader::map_grub_module(info.module_tags().nth(0).unwrap());
    let elf = module.elf.as_mut().expect("double_fault_handler: failed to parse module kernel elf");

    // Get the Main TSS so I can recover some information about what happened.
    unsafe {
        // Safety: gdt::MAIN_TASK should always point to a valid TssStruct.
        if let Some(tss_main) = (gdt::MAIN_TASK.addr() as *const TssStruct).as_ref() {
            // First print the registers
            info!("Double fault!
                    EIP={:#010x} CR3={:#010x}
                    EAX={:#010x} EBX={:#010x} ECX={:#010x} EDX={:#010x}
                    ESI={:#010x} EDI={:#010X} ESP={:#010x} EBP={:#010x}",
                   tss_main.eip, tss_main.cr3,
                   tss_main.eax, tss_main.ebx, tss_main.ecx, tss_main.edx,
                   tss_main.esi, tss_main.edi, tss_main.esp, tss_main.ebp);

            // Then print the stack
            let st = match elf.find_section_by_name(".symtab").expect("Missing .symtab").get_data(&elf).expect("Missing .symtab") {
                SectionData::SymbolTable32(st) => st,
                _ => panic!(".symtab is not a SymbolTable32"),
            };

            stack::KernelStack::dump_stack(tss_main.esp as usize, tss_main.ebp as usize, tss_main.eip as usize, Some((&elf, st)));
        }

        // And finally, panic
        panic!("Double fault!")
    }

}

extern "x86-interrupt" fn invalid_tss_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    panic!("Invalid TSS! {:?} {}", stack_frame, errcode);
}

extern "x86-interrupt" fn segment_not_present_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    panic!("Segment Not Present: {:?} {}", stack_frame, errcode);
}

extern "x86-interrupt" fn stack_segment_fault_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    panic!("Stack Segment Fault: {:?} {}", stack_frame, errcode);
}

extern "x86-interrupt" fn general_protection_fault_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    // Disable interrupts forever!
    unsafe {
        sync::permanently_disable_interrupts();
    }

    panic!("General Protection Fault: {:?} {}", stack_frame, errcode);
}

extern "x86-interrupt" fn page_fault_handler(stack_frame: &mut ExceptionStackFrame, page: PageFaultErrorCode) {
    let cause_address = ::paging::read_cr2();
    panic!("Page fault: {:?} {:?} {:?}", cause_address, stack_frame, page);
}

extern "x86-interrupt" fn x87_floating_point_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("x87 floating point fault: {:?}", stack_frame);
}

extern "x86-interrupt" fn alignment_check_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    panic!("Alignment check exception: {:?} {}", stack_frame, errcode);
}

extern "x86-interrupt" fn machine_check_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("Unrecoverable machine check exception: {:?}", stack_frame);
}

extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("SIMD floating point exception: {:?}", stack_frame);
}

extern "x86-interrupt" fn virtualization_handler(stack_frame: &mut ExceptionStackFrame) {
    panic!("Unexpected virtualization exception: {:?}", stack_frame);
}

extern "x86-interrupt" fn security_exception_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    panic!("Unexpected security exception: {:?} {}", stack_frame, errcode);
}

/// This is the function called on int 0x80.
///
/// The ABI is linuxy, but modified to allow multiple register returns:
///
/// # Inputs
///
/// - eax  system call number
/// - ebx  arg1
/// - ecx  arg2
/// - edx  arg3
/// - esi  arg4
/// - edi  arg5
/// - ebp  arg6
///
/// # Outputs
///
/// - eax  error code
/// - ebx  ret1
/// - ecx  ret2
/// - edx  ret3
/// - esi  ret4
/// - edi  ret5
/// - ebp  ret6
///
/// What this wrapper does is creating an instance of the Registers structure on the stack as argument
/// to the syscall dispatcher. The syscall dispatcher will then modify this structure to reflect what
/// the registers should look like on syscall exit, and the wrapper pops those modified values.
///
/// We don't use the x86-interrupt llvm feature because syscall arguments are passed in registers, and
/// it does not enable us to access those saved registers.
///
/// We do *NOT* restore registers before returning, as they all are used for parameter passing.
/// It is the caller's job to save the one it needs.
#[naked]
extern "C" fn syscall_handler() {
    unsafe {
        asm!("
        cld         // direction flag will be restored on return when iret pops EFLAGS
        // Construct Registers structure - see syscalls for more info
        push ebp
        push edi
        push esi
        push edx
        push ecx
        push ebx
        push eax
        // Push pointer to Registers structure as argument
        push esp
        call $0
        // Restore registers.
        mov ebx, [esp + 0x08]
        mov ecx, [esp + 0x0C]
        mov edx, [esp + 0x10]
        mov esi, [esp + 0x14]
        mov edi, [esp + 0x18]
        mov ebp, [esp + 0x1C]
        mov eax, [esp + 0x04]
        add esp, 0x20
        iretd
        " :: "i"(syscalls::syscall_handler_inner as *const u8) :: "volatile", "intel" );
    }
}

lazy_static! {
    static ref IDT: SpinLock<Option<VirtualAddress>> = SpinLock::new(None);
}

/// Initialize the interrupt subsystem. Sets up the PIC and the IDT.
///
/// # Safety
///
/// Should only be called once!
pub unsafe fn init() {
    pic::init();

    {
        let page = get_kernel_memory().get_page();
        let idt = page.addr() as *mut u8 as *mut Idt;
        unsafe {
            (*idt).init();
            (*idt).divide_by_zero.set_handler_fn(divide_by_zero_handler);
            (*idt).debug.set_handler_fn(debug_handler);
            (*idt).non_maskable_interrupt.set_handler_fn(non_maskable_interrupt_handler);
            (*idt).breakpoint.set_handler_fn(breakpoint_handler);
            (*idt).overflow.set_handler_fn(overflow_handler);
            (*idt).bound_range_exceeded.set_handler_fn(bound_range_exceeded_handler);
            (*idt).invalid_opcode.set_handler_fn(invalid_opcode_handler);
            (*idt).device_not_available.set_handler_fn(device_not_available_handler);
            (*idt).double_fault.set_handler_task_gate_addr(double_fault_handler as u32);
            // coprocessor_segment_overrun
            (*idt).invalid_tss.set_handler_fn(invalid_tss_handler);
            (*idt).segment_not_present.set_handler_fn(segment_not_present_handler);
            (*idt).stack_segment_fault.set_handler_fn(stack_segment_fault_handler);
            (*idt).general_protection_fault.set_handler_fn(general_protection_fault_handler);
            (*idt).page_fault.set_handler_fn(page_fault_handler);
            (*idt).x87_floating_point.set_handler_fn(x87_floating_point_handler);
            (*idt).alignment_check.set_handler_fn(alignment_check_handler);
            (*idt).machine_check.set_handler_fn(machine_check_handler);
            (*idt).simd_floating_point.set_handler_fn(simd_floating_point_handler);
            (*idt).virtualization.set_handler_fn(virtualization_handler);
            (*idt).security_exception.set_handler_fn(security_exception_handler);

            for (i, handler) in irq::IRQ_HANDLERS.iter().enumerate() {
                (*idt).interrupts[i].set_handler_fn(*handler);
            }

            // Add entry for syscalls
            let syscall_int = (*idt)[0x80].set_interrupt_gate_addr(syscall_handler as u32);
            syscall_int.set_privilege_level(PrivilegeLevel::Ring3);
            syscall_int.disable_interrupts(false);
        }
        let mut lock = IDT.lock();
        *lock = Some(page);
        (*idt).load();
    }

    sti();
}
