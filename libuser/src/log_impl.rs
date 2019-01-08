use spin::Mutex;
use arrayvec::ArrayString;
use log::{self, Log, LevelFilter, Metadata, Record};
use syscalls::output_debug_string;
use core::fmt::{self, Write};

lazy_static! {
    static ref SVC_LOG_SPACE: Mutex<ArrayString<[u8; 4096]>> = Mutex::new(ArrayString::new());
}

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
        let mut svc_log_space = SVC_LOG_SPACE.lock();
        let available_capacity = svc_log_space.capacity() - svc_log_space.len();
        if data.len() > available_capacity {
            // Worse-case. Just print it all out and start fresh.
            let _ = output_debug_string(svc_log_space.as_str());
            let _ = output_debug_string(data);
            let _ = svc_log_space.clear();
        } else {
            svc_log_space.push_str(data);
            if let Some(pos) = svc_log_space.find('\n') {
                let _ = output_debug_string(&svc_log_space.as_str()[..pos]);
                *svc_log_space = ArrayString::from(&svc_log_space[pos + 1..]).unwrap();
            }
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
