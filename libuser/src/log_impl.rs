//! Implementation for the log crate
//!
//! Redirects all logs to the kernel logger (output_debug_string syscall). No
//! filtering is done, so everything will be sent.

use log::{self, Log, LevelFilter, Metadata, Record};
use crate::syscalls::output_debug_string;

/// Log implementation structure.
///
/// See module documentation for more information.
struct Logger;

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        let level = match record.level() {
            log::Level::Error => 10,
            log::Level::Warn => 30,
            log::Level::Info => 50,
            log::Level::Debug => 70,
            log::Level::Trace => 90,
        };
        let _ = output_debug_string(&*format!("{}", record.args()), level, record.target());
    }

    fn flush(&self) {}
}

/// Initializes the global logger with the svc logger.
///
/// This should be called early in the execution of a Rust program. Any log
/// events that occur before initialization will be ignored.
///
/// # Panics
///
/// This function will panic if it is called more than once, or if another
/// library has already initialized a global logger.
pub fn init() {
    log::set_logger(&Logger)
        .expect("log_impl::init to be called only once");
    log::set_max_level(LevelFilter::Trace);
    info!("Logging enabled");
}
