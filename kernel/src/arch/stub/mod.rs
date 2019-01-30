//! Stub implementation of the arch-independant API
//!
//! This is the stub implementation of the arch-independant API. Its aim is to
//! ease porting efforts by providing a copy-pastable module to start a new
//! implementation of the arch-specific component, and to provide the test builds
//! with a simple implementation.

/// Enable interruptions. After calling this function, hardware should call
/// [crate::event::dispatch_event] whenever it receives an interruption.
pub unsafe fn enable_interrupts() {
}

/// Disable interruptions, returning true if they were previously enabled, or
/// false if they were already disabled. After calling this function, no hardware
/// should call [crate::event::dispatch_event]. Interruptions should be queued
/// until either [enable_interrupts] is called or a process switch is performed.
pub unsafe fn disable_interrupts() -> bool {
    false
}
