//! Interrupt handling.
//!
//! All exceptions are considered unrecoverable errors, and kill the process that issued it.
//!
//! Feature `panic-on-exception` makes the kernel stop and panic when a thread generates
//! an exception. This is useful for debugging.

use crate::i386::structures::idt::{ExceptionStackFrame, PageFaultErrorCode, Idt};
use crate::i386::instructions::interrupts::sti;
use crate::mem::VirtualAddress;
use crate::paging::kernel_memory::get_kernel_memory;
use crate::i386::PrivilegeLevel;
use crate::scheduler::get_current_thread;
use crate::process::{ProcessStruct, ThreadState};
use crate::sync::SpinLockIRQ;
use core::sync::atomic::Ordering;

use core::fmt::Arguments;
use crate::sync::SpinLock;
use crate::scheduler;
use crate::i386::gdt::GdtIndex;
use crate::i386::gdt::DOUBLE_FAULT_TASK;
use crate::panic::{kernel_panic, PanicOrigin};
use crate::i386::structures::gdt::SegmentSelector;
use crate::i386::registers::eflags::EFlags;

mod irq;
pub mod syscalls;

/// Represents a register backup.
#[repr(C)]
#[derive(Debug, Clone, Default)]
#[allow(clippy::missing_docs_in_private_items)]
#[allow(missing_docs)]
pub struct UserspaceHardwareContext {
    pub esp: usize,
    pub ebp: usize,
    pub edi: usize,
    pub esi: usize,
    pub edx: usize,
    pub ecx: usize,
    pub ebx: usize,
    pub eax: usize,
    // pushed by cpu:
    pub errcode: usize,
    pub eip: usize,
    pub cs: usize,
    pub eflags: usize,
}

impl core::fmt::Display for UserspaceHardwareContext {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        writeln!(f, "EIP={:#010x} ESP={:#010x} EBP={:#010x}\n\
                     EAX={:#010x} EBX={:#010x} ECX={:#010x} EDX={:#010x}\n\
                     ESI={:#010x} EDI={:#010X}\n\
                     EFLAGS={:?}\n\
                     CS={:?}",
                     self.eip, self.esp, self.ebp,
                     self.eax, self.ebx, self.ecx, self.edx,
                     self.esi, self.edi,
                     EFlags::from_bits_truncate(self.eflags as u32),
                     SegmentSelector(self.cs as u16),
        )
    }
}

/// Checks if our thread was killed, in which case unschedule ourselves.
///
/// # Note
///
/// As this function will be the last that will be called by a thread before dying,
/// caller must make sure all of its scope variables are ok to be leaked.
pub fn check_thread_killed() {
    if scheduler::get_current_thread().state.load(Ordering::SeqCst) == ThreadState::Killed {
        let lock = SpinLockIRQ::new(());
        loop { // in case of spurious wakeups
            let _ = scheduler::unschedule(&lock, lock.lock());
        }
    }
}

/// Panics with an informative message.
fn panic_on_exception(exception_string: Arguments<'_>, exception_stack_frame: &ExceptionStackFrame) -> ! {
    kernel_panic(&PanicOrigin::UserspaceFault {
        exception_message: exception_string,
        userspace_hardware_context: UserspaceHardwareContext {
            cs: exception_stack_frame.code_segment as usize,
            eflags: exception_stack_frame.cpu_flags as usize,
            eip: exception_stack_frame.instruction_pointer.addr(),
            esp: exception_stack_frame.stack_pointer.addr(),
            .. UserspaceHardwareContext::default()
        }
    });
}

/// Divide by zero interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn divide_by_zero_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Divide Error Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("Divide Error Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Debug interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn debug_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Debug Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("Debug Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Non maskable interruption handler. Unconditionally panics the kernel.
extern "x86-interrupt" fn non_maskable_interrupt_handler(stack_frame: &mut ExceptionStackFrame) {
    // unconditionally panic
    panic_on_exception(format_args!("An unexpected non-maskable (but still kinda maskable) interrupt occured"), stack_frame);
}

/// Breakpoint interruption handler. Does nothing.
extern "x86-interrupt" fn breakpoint_handler(_stack_frame: &mut ExceptionStackFrame) {
    // don't do anything
}

/// Overflow interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn overflow_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Overflow Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("Overflow Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Bound range exceeded interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn bound_range_exceeded_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("BOUND Range Exceeded Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("BOUND Range Exceeded Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Invalid opcode interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn invalid_opcode_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Invalid opcode Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("Invalid opcode Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Device not available interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn device_not_available_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Device Not Available Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("Device Not Available Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Double fault handler. Panics the kernel unconditionally.
fn double_fault_handler() {
    kernel_panic(&PanicOrigin::DoubleFault);
}

/// Invalid tss interruption handler. Panics the kernel unconditionally.
extern "x86-interrupt" fn invalid_tss_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    // inconditionally panic
    panic_on_exception(format_args!("Invalid TSS Exception: error code {:?}", errcode), stack_frame);
}

/// Segment not present interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn segment_not_present_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Segment Not Present: error code: {:?}", errcode), stack_frame);
        }

        let thread = get_current_thread();
        error!("Segment Not Present in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Stack segment fault handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn stack_segment_fault_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Stack Fault Exception: error code: {:?}", errcode), stack_frame);
        }

        let thread = get_current_thread();
        error!("Exception : Stack Fault Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// General protection fault handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn general_protection_fault_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("General Protection Fault Exception: error code: {:?}", errcode), stack_frame);
        }

        let thread = get_current_thread();
        error!("Exception : General Protection Fault Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Page fault handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn page_fault_handler(stack_frame: &mut ExceptionStackFrame, errcode: PageFaultErrorCode) {
    {
        let cause_address = crate::paging::read_cr2();

        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Page Fault accessing {:?}, error: {:?}", cause_address, errcode), stack_frame);
        }

        let thread = get_current_thread();
        error!("Exception : Page Fault accessing {:?}, error: {:?} in {:#?}", cause_address, errcode, thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// X87 floating point interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn x87_floating_point_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("x87 FPU floating-point error"), stack_frame);
        }

        let thread = get_current_thread();
        error!("x87 FPU floating-point error in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Alignment check interruption handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn alignment_check_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Alignment Check Exception: error code: {:?}", errcode), stack_frame);
        }

        let thread = get_current_thread();
        error!("Alignment Check Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Machine check interruption handler. Panics the kernel unconditionally.
extern "x86-interrupt" fn machine_check_handler(stack_frame: &mut ExceptionStackFrame) {
    // unconditionally panic
    panic_on_exception(format_args!("Machine-Check Exception"), stack_frame);
}

/// SIMD exception handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn simd_floating_point_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("SIMD Floating-Point Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("SIMD Floating-Point Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Virtualization exception handler. Kills the process unconditionally.
///
/// If the panic-on-exception feature is enabled, this will also panic the kernel.
extern "x86-interrupt" fn virtualization_handler(stack_frame: &mut ExceptionStackFrame) {
    {
        if cfg!(feature = "panic-on-exception") {
            panic_on_exception(format_args!("Virtualization Exception"), stack_frame);
        }

        let thread = get_current_thread();
        error!("Virtualization Exception in {:#?}", thread);
        ProcessStruct::kill_process(thread.process.clone());
    }

    check_thread_killed();
}

/// Security exception handler. Panics the kernel unconditionally.
extern "x86-interrupt" fn security_exception_handler(stack_frame: &mut ExceptionStackFrame, errcode: u32) {
    // unconditionally panic
    panic_on_exception(format_args!("Unexpected Security Exception: error code {:?}", errcode), stack_frame);
}

// gonna write constants in the code, cause not enough registers.
// just check we aren't hard-coding the wrong values.
const_assert_eq!((GdtIndex::KTls as u16) << 3 | 0b00, 0x18);
const_assert_eq!((GdtIndex::UTlsRegion as u16) << 3 | 0b11, 0x3B);
const_assert_eq!((GdtIndex::UTlsElf as u16) << 3 | 0b11, 0x43);

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
        // Load kernel tls segment
        mov ax, 0x18
        mov gs, ax
        // Push pointer to Registers structure as argument
        push esp
        call $0
        // Load userspace tls segment
        mov ax, 0x43
        mov gs, ax
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
    /// IDT address. Initialized in `init()`.
    static ref IDT: SpinLock<Option<VirtualAddress>> = SpinLock::new(None);
}

/// Initialize the interrupt subsystem. Sets up the PIC and the IDT.
///
/// # Safety
///
/// Should only be called once!
#[allow(clippy::cast_ptr_alignment)] // this function is x86_32 only
#[allow(clippy::fn_to_numeric_cast)] // this function is x86_32 only
pub unsafe fn init() {
    crate::i386::interrupt::init();

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
            DOUBLE_FAULT_TASK.lock().set_ip(double_fault_handler as u32);
            (*idt).double_fault.set_handler_task_gate(GdtIndex::FTSS.selector());
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
