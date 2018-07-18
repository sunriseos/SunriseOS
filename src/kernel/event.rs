use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Default)]
struct Event {
    count: AtomicUsize,
    ack: AtomicUsize,
}

impl Event {
    const fn new() -> Event {
        Event {
            count: AtomicUsize::new(0),
            ack: AtomicUsize::new(0)
        }
    }

    fn wait(&self) {
        loop {
            if self.ack.load(Ordering::SeqCst) < self.count.load(Ordering::SeqCst) {
                self.ack.fetch_add(1, Ordering::SeqCst);
                return;
            }
            // TODO: This would normally call schedule.
            unsafe { asm!("HLT" : : : : "volatile"); }
        }
    }

    fn signal(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
    }
}

pub fn dispatch_event(irq: usize) {
    IRQ_EVENTS[irq].signal();
}

pub fn wait_event(irq: usize) {
    IRQ_EVENTS[irq].wait();
}

static IRQ_EVENTS: [Event; 16] = [
    Event::new(), Event::new(), Event::new(), Event::new(),
    Event::new(), Event::new(), Event::new(), Event::new(),
    Event::new(), Event::new(), Event::new(), Event::new(),
    Event::new(), Event::new(), Event::new(), Event::new(),
];
