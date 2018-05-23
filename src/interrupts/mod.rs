use i386::structures::idt::{ExceptionStackFrame, Idt};
use i386::instructions::{port::{inb, outb}, interrupts::sti};

use print::Printer;
use core::fmt::Write;
use frame_alloc::{Frame, FrameAllocator};
use spin::Mutex;

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

fn io_wait() {
    // Port 0x80 is used for 'checkpoints' during POST.
    // The Linux kernel seems to think it is free for use :-/
    unsafe { outb(0x80, 0); }
}

/// Command port for the primary PIC
const PIC1_COMMAND: u16 = 0x20;
/// Data port for the primary PIC
const PIC1_DATA: u16 = 0x21;
/// Command port for the secondary PIC
const PIC2_COMMAND: u16 = 0xA0;
/// Data port for the secondary PIC
const PIC2_DATA: u16 = 0xA1;

bitflags! {
    pub struct ICW1: u8 {
        /// If this bit is set, ICW4 has to be read. If ICW4 is not needed, set
        /// ICW4 to 0
        const ICW4      = 0x01;
        /// Single. Means that this is the only 8259A in the system. If SINGLE
        // is 1, no ICW3 will be issued.
        const SINGLE    = 0x02;
        /// Call Address Interval. Used only in 8085, not 8086. 1=ISR's are 4
        /// bytes apart (0200, 0204, etc) 0=ISR's are 8 byte apart (0200, 0208,
        /// etc)
        const INTERVAL4 = 0x04;
        /// If LEVEL = 1, then the 8259A will operate in the level interrupt
        /// mode. Edge detect logic on the interrupt inputs will be disabled.
        const LEVEL     = 0x08;
        /// Should always be set to 1.
        const INIT      = 0x10;
    }
}
const ICW4_8086: u8     = 0x01;       /* 8086/88 (MCS-80/85) mode */
//const icw4_auto         = 0x02;       /* Auto (normal) EOI */
//const icw4_buf_slave    = 0x08;       /* Buffered mode/slave */
//const icw4_buf_master   = 0x0C;       /* Buffered mode/master */
//const icw4_sfnm         = 0x10;       /* Special fully nested (not) */

/// setup the 8259 pic. redirect the IRQ to user interrupt 32+.
fn init_pic() {

    unsafe {
        // save masks
        let a1 = inb(PIC1_DATA);
        let a2 = inb(PIC2_DATA);

        // starts the initialization sequence (in cascade mode)
        outb(PIC1_COMMAND, (ICW1::INIT | ICW1::ICW4).bits());
        io_wait();
        outb(PIC2_COMMAND, (ICW1::INIT | ICW1::ICW4).bits());
        io_wait();
        // ICW2: Master PIC vector offset
        outb(PIC1_DATA, 0x20);
        io_wait();
        // ICW2: Slave PIC vector offset
        outb(PIC2_DATA, 0x28);
        io_wait();
        // ICW3: tell Master PIC that there is a slave PIC at IRQ2 (0000 0100)
        outb(PIC1_DATA, 4);
        io_wait();
        // ICW3: tell Slave PIC its cascade identity (0000 0010)
        outb(PIC2_DATA, 2);
        io_wait();

        outb(PIC1_DATA, ICW4_8086);
        io_wait();
        outb(PIC2_DATA, ICW4_8086);
        io_wait();

        outb(PIC1_DATA, a1);   // restore saved masks.
        outb(PIC2_DATA, a2);
    }
}

/// initialize the interrupt subsystem. Sets up the PIC and the IDT.
pub fn init() {
    init_pic();

    {
        let frame = FrameAllocator::alloc_frame();
        let ptr = frame.dangerous_as_physical_ptr();
        let idt = ptr as *mut u8 as *mut Idt;
        unsafe {
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
    }
    unsafe {
        asm!("int3" : : : : "volatile");

        sti();
    }
}
