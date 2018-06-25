//! A simple log implementation based on env_logger

mod filter;

use log::{self, Log, Metadata, Record, LevelFilter};
use logger::Loggers;
use spin::Once;
use core::fmt::Write;
use i386::multiboot::get_boot_information;

struct Logger {
    filter: filter::Filter
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if self.filter.matches(record) {
            writeln!(Loggers, "[{}] - {} - {}", record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Once<Logger> = Once::new();

pub fn init() {
    let cmdline = get_boot_information().command_line_tag().unwrap().command_line();
    let filter = filter::Builder::new().parse(cmdline).build();
    log::set_logger(LOGGER.call_once(|| Logger { filter: filter } ))
        .expect("log_impl::init to be called before logger is initialized");
    log::set_max_level(LevelFilter::Debug);
    info!("Logging enabled");
}
