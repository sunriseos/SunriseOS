use i386::structures::idt::{ExceptionStackFrame, Idt};
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

extern "x86-interrupt" fn ignore_handler(stack_frame: &mut ExceptionStackFrame) {}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: &mut ExceptionStackFrame) {
    info!("Interrupt is on! \\o/\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode(stack_frame: &mut ExceptionStackFrame) {
    loop {}
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
        let serial = &mut SerialLogger;
        writeln!(serial, "Handling syscall - {} - arg1: {}, arg2: {}, arg3: {}, arg4: {}, arg5: {}, arg6: {}",
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
            (*idt).breakpoint.set_handler_fn(breakpoint_handler);
            for (i, handler) in irq::IRQ_HANDLERS.iter().enumerate() {
                (*idt).interrupts[i].set_handler_fn(*handler);
            }
            // Add entry for syscalls
            let syscall_int = (*idt)[0x80].set_handler_addr(syscall_handler as u32);
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
