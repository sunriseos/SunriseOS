//! A simple log implementation based on env_logger

mod filter;

use log::{self, Log, Metadata, Record, LevelFilter};
use logger::Loggers;
use spin::Once;
use core::fmt::Write;
use i386::multiboot::get_boot_information;
use spin::RwLock;

struct Logger {
    filter: RwLock<filter::Filter>
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.filter.read().enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if self.filter.read().matches(record) {
            writeln!(Loggers, "[{}] - {} - {}", record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Once<Logger> = Once::new();

/// Initializes the Logger in a heapless environment.
pub fn early_init() {
    let filter = filter::Builder::new()
        .filter(None, LevelFilter::Info)
        .build();
    log::set_logger(LOGGER.call_once(|| Logger { filter: RwLock::new(filter) } ))
        .expect("log_impl::init to be called before logger is initialized");
    log::set_max_level(LevelFilter::Trace);
    info!("Logging enabled");
}

/// Reinitializes the logger using the cmdline. This requires the heap.
pub fn init() {
    let logger = LOGGER.try().expect("early_init to be called before init");
    let cmdline = get_boot_information().command_line_tag().unwrap().command_line();
    let newfilter = filter::Builder::new().parse(cmdline).build();
    *logger.filter.write() = newfilter;
}
