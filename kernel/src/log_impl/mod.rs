//! A simple log implementation based on env_logger
#![allow(clippy::missing_docs_in_private_items)]
mod filter;

use log::{self, Log, Metadata, Record, LevelFilter};
use crate::arch::get_logger;
use core::fmt::Write;
use crate::arch::get_cmdline;
use crate::sync::{RwLock, Once};
use crate::scheduler;

struct Logger {
    filter: RwLock<filter::Filter>
}

#[allow(unused_must_use)]
impl Log for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter.read().enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if self.filter.read().matches(record) {
            if let Some(thread) = scheduler::try_get_current_thread() {
                writeln!(get_logger(), "[{}] - {} - {} - {}", record.level(), record.target(), thread.process.name, record.args());
            } else {
                writeln!(get_logger(), "[{}] - {} - {}", record.level(), record.target(), record.args());
            }
        }
    }

    fn flush(&self) {}
}

static LOGGER: Once<Logger> = Once::new();

/// Initializes the Logger in a heapless environment.
pub fn early_init() {
    let filter = filter::Builder::new()
        .filter(None, LevelFilter::Trace)
        .build();
    log::set_logger(LOGGER.call_once(|| Logger { filter: RwLock::new(filter) } ))
        .expect("log_impl::init to be called before logger is initialized");
    log::set_max_level(LevelFilter::Trace);
    info!("Logging enabled");
}

/// Reinitializes the logger using the cmdline. This requires the heap.
pub fn init() {
    let logger = LOGGER.r#try().expect("early_init to be called before init");
    let newfilter = filter::Builder::new().parse(get_cmdline()).build();
    *logger.filter.write() = newfilter;
}
