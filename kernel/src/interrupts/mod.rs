use i386::structures::idt::{ExceptionStackFrame, PageFaultErrorCode, Idt};
use i386::instructions::interrupts::sti;
use i386::pio::Pio;
use io::Io;
use i386::mem::VirtualAddress;
use i386::PrivilegeLevel;

use core::fmt::Write;
use spin::Mutex;
use paging::{KernelLand, get_page};
use devices::pic;

mod irq;

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
    panic!("Double fault!");
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
/// The ABI is the same as linux, that is to say :
///
/// - eax  system call number
/// - ebx  arg1
/// - ecx  arg2
/// - edx  arg3
/// - esi  arg4
/// - edi  arg5
/// - ebp  arg6
/// - return value is put in eax
///
/// What this wrapper does is simply pushing the registers on the stack as argument to the syscall dispatcher
///
/// We don't use the x86-interrupt llvm feature because syscall arguments are passed in registers, and
/// it does not enable us to access those saved registers.
///
/// We do *NOT* restore registers before returning, as they all are used for parameter passing.
/// It is the caller's job to save the one it needs.
#[naked]
extern "C" fn syscall_handler() {
    extern fn syscall_handler_inner(syscall_nr: u32, arg1: u32, arg2: u32, arg3: u32, arg4: u32, arg5: u32, arg6: u32) -> u32 {
        use logger::Logger;
        use ::devices::rs232::SerialLogger;
        info!("Handling syscall {} - arg1: {}, arg2: {}, arg3: {}, arg4: {}, arg5: {}, arg6: {}",
                syscall_nr, arg1, arg2, arg3, arg4, arg5, arg6);
        match syscall_nr {
            1 => { info!("syscall 1 !"); 0},
            2 => { info!("syscall 2 !"); 0},
            u => { info!("unknown syscall_nr {}", u); 255 }
        }
    }

    unsafe {
        asm!("
        cld         // direction flag will be restored on return when iret pops EFLAGS
        push ebp
        push edi
        push esi
        push edx
        push ecx
        push ebx
        push eax
        call $0
        add esp, 28  // drop the pushed arguments
        iretd
        " :: "i"(syscall_handler_inner as *const u8) :: "volatile", "intel" );
    }
}

/// A bit of asm making a syscall
pub unsafe fn syscall(syscall_nr: u32, arg1: u32, arg2: u32, arg3: u32, arg4: u32, arg5: u32, arg6: u32) -> u32 {
    let result: u32;
    asm!("
    int 0x80        // make the call
    "
    : "={eax}"(result)
    : "{eax}"(syscall_nr), "{ebx}"(arg1), "{ecx}"(arg2), "{edx}"(arg3), "{esi}"(arg4), "{edi}"(arg5), "{ebp}"(arg6)
    : // no clobbers left - we already clobbered the world
    : "volatile", "intel");
    result
}

lazy_static! {
    static ref IDT: Mutex<Option<VirtualAddress>> = Mutex::new(None);
}

/// initialize the interrupt subsystem. Sets up the PIC and the IDT.
pub unsafe fn init() {
    pic::init();

    {
        let page = get_page::<KernelLand>();
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
            let mut lock = IDT.lock();
            *lock = Some(page);
            (*idt).load();
        }
        let mut lock = IDT.lock();
        *lock = Some(page);
        (*idt).load();
    }

    sti();
}
