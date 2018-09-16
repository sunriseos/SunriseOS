use i386::pio::Pio;
use io::Io;
use i386::structures::idt::ExceptionStackFrame;
use core::fmt::Write;
use devices::pic;
use logger::Loggers;

fn acknowledge_irq(irq: u8) {
    pic::get().acknowledge(irq)
}

extern "x86-interrupt" fn timer_handler(stack_frame: &mut ExceptionStackFrame) {
    // TODO: Reroute this into a generic interrupt system?
    acknowledge_irq(0);
}

macro_rules! irq_handler_none {
    ($irq:expr, $name:ident) => {{
        extern "x86-interrupt" fn $name(stack_frame: &mut ExceptionStackFrame) {
            // TODO: Reroute this into a generic interrupt system?
            acknowledge_irq($irq);
        }
        $name
    }}
}

macro_rules! irq_handler {
    ($irq:expr, $name:ident) => {{
        extern "x86-interrupt" fn $name(stack_frame: &mut ExceptionStackFrame) {
            acknowledge_irq($irq);
            ::event::dispatch_event($irq);
        }
        $name
    }}
}

pub static IRQ_HANDLERS : [extern "x86-interrupt" fn(stack_frame: &mut ExceptionStackFrame); 16] = [
    irq_handler_none!(0, timer_handler),
    irq_handler!(1, keyboard_handler),
    irq_handler!(2, cascade_handler),
    irq_handler!(3, serial2_handler),
    irq_handler!(4, serial1_handler),
    irq_handler!(5, sound_handler),
    irq_handler!(6, floppy_handler),
    irq_handler!(7, parallel1_handler),
    irq_handler!(8, rtc_handler),
    irq_handler!(9, acpi_handler),
    irq_handler!(10, irq10_handler),
    irq_handler!(11, irq11_handler),
    irq_handler!(12, mouse_handler),
    irq_handler!(13, irq13_handler),
    irq_handler!(14, primary_ata_handler),
    irq_handler!(15, secondary_ata_handler),
];