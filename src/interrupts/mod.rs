use i386::structures::idt::{ExceptionStackFrame, Idt};
use i386::instructions::interrupts::sti;
use i386::pio::Pio;
use io::Io;
use i386::mem::VirtualAddress;

use core::fmt::Write;
use spin::Mutex;
use paging::{KernelLand, get_page};

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

fn io_wait() {
    // Port 0x80 is used for 'checkpoints' during POST.
    // The Linux kernel seems to think it is free for use :-/
    Pio::<u8>::new(0x80).write(0);
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
        let mut pic1_data = Pio::<u8>::new(PIC1_DATA);
        let mut pic2_data = Pio::<u8>::new(PIC2_DATA);
        let mut pic1_cmd = Pio::<u8>::new(PIC1_COMMAND);
        let mut pic2_cmd = Pio::<u8>::new(PIC2_COMMAND);

        let a1 = pic1_data.read();
        let a2 = pic2_data.read();

        // starts the initialization sequence (in cascade mode)
        pic1_cmd.write((ICW1::INIT | ICW1::ICW4).bits());
        io_wait();
        pic2_cmd.write((ICW1::INIT | ICW1::ICW4).bits());
        io_wait();
        // ICW2: Master PIC vector offset
        pic1_data.write(0x20);
        io_wait();
        // ICW2: Slave PIC vector offset
        pic2_data.write(0x28);
        io_wait();
        // ICW3: tell Master PIC that there is a slave PIC at IRQ2 (0000 0100)
        pic1_data.write(4);
        io_wait();
        // ICW3: tell Slave PIC its cascade identity (0000 0010)
        pic2_data.write(2);
        io_wait();

        pic1_data.write(ICW4_8086);
        io_wait();
        pic2_data.write(ICW4_8086);
        io_wait();

        pic1_data.write(a1);   // restore saved masks.
        pic2_data.write(a2);
    }
}

/// initialize the interrupt subsystem. Sets up the PIC and the IDT.
pub fn init() {
    init_pic();

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
    }
    unsafe {
        asm!("int3" : : : : "volatile");

        sti();
    }
}
