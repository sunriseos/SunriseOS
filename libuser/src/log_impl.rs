//! Implementation for the log crate
//!
//! Redirects all logs to the kernel logger (output_debug_string syscall). No
//! filtering is done, so everything will be sent.

use spin::Mutex;
use arrayvec::ArrayString;
use log::{self, Log, LevelFilter, Metadata, Record};
use syscalls::output_debug_string;
use core::fmt::{self, Write};

lazy_static! {
    /// Buffer where pending writes are stored. The buffer is only flushed when
    /// a \n is written, or when it's full.
    ///
    /// In practice, every log will cause a single line (at least) to be written.
    static ref SVC_LOG_BUFFER: Mutex<ArrayString<[u8; 256]>> = Mutex::new(ArrayString::new());
}

/// Log implementation structure.
///
/// See module documentation for more information.
struct Logger;

impl Log for Logger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let _ = writeln!(Logger, "[{}] - {} - {}", record.level(), record.target(), record.args());
    }

    fn flush(&self) {}
}

impl fmt::Write for Logger {
    fn write_str(&mut self, data: &str) -> fmt::Result {
        let mut svc_log_buffer = SVC_LOG_BUFFER.lock();
        if let Ok(()) = svc_log_buffer.try_push_str(data) {
            if let Some(pos) = svc_log_buffer.rfind('\n') {
                let _ = output_debug_string(&svc_log_buffer.as_str()[..pos]);
                *svc_log_buffer = ArrayString::from(&svc_log_buffer[pos + 1..]).unwrap();
            }
        } else {
            // Worse-case. Just print it all out and start fresh.
            if !svc_log_buffer.is_empty() {
                let _ = output_debug_string(svc_log_buffer.as_str());
            }
            let _ = output_debug_string(data);
            let _ = svc_log_buffer.clear();
        }
        Ok(())
    }
}

pub fn init() {
    log::set_logger(&Logger)
        .expect("log_impl::init to be called only once");
    log::set_max_level(LevelFilter::Trace);
    info!("Logging enabled");
}
