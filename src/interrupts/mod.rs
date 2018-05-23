use i386::structures::idt::{ExceptionStackFrame, Idt};
use i386::instructions::interrupts::sti;
use i386::pio::Pio;
use io::Io;
use i386::mem::VirtualAddress;

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
