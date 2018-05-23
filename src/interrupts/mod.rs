use i386::structures::idt::{ExceptionStackFrame, Idt};
use i386::instructions::{port::{inb, outb}, interrupts::sti};

use print::Printer;
use core::fmt::Write;
use frame_alloc::{Frame, FrameAllocator};
use spin::Mutex;
use devices::pic;

mod irq;

extern "x86-interrupt" fn ignore_handler(stack_frame: &mut ExceptionStackFrame) {}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: &mut ExceptionStackFrame) {
    writeln!(Printer, "Interrupt is on! \\o/\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn invalid_opcode(stack_frame: &mut ExceptionStackFrame) {
    loop {}
}

lazy_static! {
    static ref IDT: Mutex<Option<Frame>> = Mutex::new(None);
}

/// initialize the interrupt subsystem. Sets up the PIC and the IDT.
pub unsafe fn init() {
    pic::init();

    {
        let frame = FrameAllocator::alloc_frame();
        let ptr = frame.dangerous_as_physical_ptr();
        let idt = ptr as *mut u8 as *mut Idt;
        (*idt).init();
        (*idt).breakpoint.set_handler_fn(breakpoint_handler);
        for interrupt in &mut (*idt).interrupts[0..16] {
            interrupt.set_handler_fn(ignore_handler);
        }
        for (i, handler) in irq::IRQ_HANDLERS.iter().enumerate() {
            (*idt).interrupts[i].set_handler_fn(*handler);
        }
        let mut lock = IDT.lock();
        *lock = Some(frame);
        (*idt).load();
    }

    sti();
}
