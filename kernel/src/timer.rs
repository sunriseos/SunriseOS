//! The core timing of Sunrise.

use core::sync::atomic::{AtomicUsize, Ordering};

use super::event;
use super::event::{IRQEvent, Waitable};
use super::sync::Once;
use super::utils::div_ceil;

/// This represent the information to derive all internal timing in Sunrise.
struct KernelTimerInfo {
    /// The frequency of the oscillator used as primary source of this timer, when not divided, in Hertz.
    ///
    /// The value here is only informative, you should use `.irq_periode_ns`.
    oscillator_frequency: u64,

    /// The IRQ period used on this timer in nanoseconds.
    pub irq_period_ns: u64,

    /// The IRQ number that the timer use.
    pub irq_number: u8,

    /// Get the current tick in nanoseconds.
    pub get_tick: fn() -> u64,
}

/// Stores the information needed for Sunrise's internal timing.
static KERNEL_TIMER_INFO: Once<KernelTimerInfo> = Once::new();

/// Set the information required for Sunrise timer to work.
/// 
/// # Panics
///
/// Panics if the timer info has already been initialized.
pub fn set_kernel_timer_info(irq_number: u8, oscillator_frequency: u64, irq_period_ns: u64, get_tick: fn() -> u64) {
    assert!(KERNEL_TIMER_INFO.r#try().is_none(), "Kernel Timer Info is already initialized!");
    KERNEL_TIMER_INFO.call_once(|| {
        KernelTimerInfo {
            irq_number,
            oscillator_frequency,
            irq_period_ns,
            get_tick
        }
    });
}

/// Returns a stream of event that trigger every `ns` amount of nanoseconds.
/// 
/// # Note
/// 
/// - If the timer resolution cannot handle it, this is not going to be accurate.
/// - Minimal resolution for HPET (10Mhz) / HPET QEMU (100Mhz): 100ns / 10ns
/// - Minimal resolution for PIC (~1Mhz): 10ms
pub fn wait_ns(ns: usize) -> impl Waitable {
    let timer_info = KERNEL_TIMER_INFO.r#try().expect("Kernel Timer Info is not initialized!");
    IRQTimer::new(ns, timer_info.irq_number, timer_info.irq_period_ns)
}

#[derive(Debug)]
/// A stream of event that trigger every `ns` amount of nanoseconds, by counting interruptions.
pub struct IRQTimer {
    /// Approximation of number of ns spent between triggers.
    every_ns: usize,
    /// IRQ event period in nanoseconds.
    irq_period_ns: u64,
    /// The IRQ that we wait on.
    parent_event: IRQEvent,
    /// The reset value of ``.countdown_value``.
    reset_value: usize,
    /// Number of IRQ triggers to wait for. Derived from `.every_ns`. This is the exact time amout that is used.
    countdown_value: AtomicUsize
}

impl IRQTimer {
    /// Create a new IRQ timer instance from the time to wait (in ns), the irq number and irq event period (in ns).
    pub fn new(ns: usize, irq: u8, irq_period_ns: u64) -> Self {
        let mut reset_value = div_ceil(ns as u64, irq_period_ns) as usize;
        if reset_value == 0 {
            reset_value = 1;
        }

        IRQTimer {
            every_ns: ns,
            irq_period_ns,
            parent_event: event::wait_event(irq),
            reset_value,
            countdown_value: AtomicUsize::new(0)
        }
    }
}

impl Waitable for IRQTimer {
    fn register(&self) {
        self.parent_event.register()
    }

    fn is_signaled(&self) -> bool {
        // First, reset the spins if necessary
        self.countdown_value.compare_and_swap(0, self.reset_value, Ordering::SeqCst);

        // Then, check if it's us.
        self.parent_event.is_signaled()
            // Then, check if we need more spins.
            && self.countdown_value.fetch_sub(1, Ordering::SeqCst) == 1
    }
}

/// Gets the current tick in nanosecond according to the [KERNEL_TIMER_INFO].
///
/// The tick should be monotonically increasing. Note that the underlying timer
/// might not have nanosecond precision - the HPET, for instance, has a worst
/// precision of 100ns.
pub fn get_tick() -> u64 {
    let timer_info = KERNEL_TIMER_INFO.r#try().expect("Kernel Timer Info is not initialized!");

    (timer_info.get_tick)()
}