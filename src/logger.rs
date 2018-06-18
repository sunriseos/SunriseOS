//! The kernel loggers

use spin::Mutex;

/// The possible colors for logging.
/// If the logger does not implement some colors they should fallback to the nearest color
#[derive(Debug, Copy, Clone)]
pub enum LogColor {
    Black,
    White,
    Blue,
    Green,
    Cyan,
    Red,
    Magenta,
    Brown,
    Pink,
    Yellow,
    LightGray,
    DarkGray,
    LightBlue,
    LightGreen,
    LightCyan,
    LightRed,
    LightYellow,
    LightMagenta,
    DefaultForeground,
    DefaultBackground,
}

/// The attributes of a log message
#[derive(Debug, Copy, Clone)]
pub struct LogAttributes {
    pub foreground: LogColor,
    pub background: LogColor,
    pub bold: bool,
    pub underlined: bool,
    pub blink: bool,
}

impl LogAttributes {
    pub fn new(foreground: LogColor, background: LogColor,
               bold: bool, underlined: bool, blink: bool) -> LogAttributes {
        LogAttributes {
            foreground, background,
            bold, underlined, blink
        }
    }

    pub fn new_fg(foreground: LogColor) -> LogAttributes {
        let default = LogAttributes::default();
        LogAttributes { foreground, ..default }
    }

    pub fn new_fg_bg(foreground: LogColor, background: LogColor) -> LogAttributes {
        let default = LogAttributes::default();
        LogAttributes { foreground, background, ..default }
    }
}

/// Default attribute is white foreground on black background
impl Default for LogAttributes {
    fn default() -> Self {
        LogAttributes { foreground: LogColor::DefaultForeground,
                        background: LogColor::DefaultBackground,
                        bold: false, underlined: false, blink: false }
    }
}

/* ********************************************************************************************** */

/// A logger must implement this trait
pub trait Logger {
    /// Logs a string
    fn print(&mut self, string: &str);

    /// Logs a string and adds a line feed
    fn println(&mut self, string: &str) {
        self.print(string);
        self.print("\n");
    }

    /// Logs a string with attributes
    fn print_attr(&mut self, string: &str, attr: LogAttributes);

    /// Logs a string with attributes and adds a line feed
    fn println_attr(&mut self, string: &str, attr: LogAttributes) {
        self.print_attr(string, attr);
        self.print("\n");
    }

    /// Forces unlock the mutex
    unsafe fn force_unlock(&mut self);

    /// Clears the whole screen (if possible)
    fn clear(&mut self) {}
}

/* ********************************************************************************************** */

pub struct RegisteredLogger {
    name:   &'static str,
    logger: &'static mut (Logger + Send + Sync)
}

/// We keep an array of 8 possible loggers
lazy_static! {
    //static ref LOGGERS_ARRAY : Mutex<[Option<(&str, &'static mut (Logger + Send + Sync))>; 8]>
    static ref LOGGERS_ARRAY : Mutex<[Option<RegisteredLogger>; 8]>
        = Mutex::new([None, None, None, None, None, None, None, None]);
}

pub struct Loggers;

impl Loggers {
    /// Registers a logger.
    /// All subsequent logs will also be sent to it
    ///
    /// # PANICS
    ///
    /// Panics if the loggers array is full
    /// Panics if the name was already registered
    // TODO return an Error type
    pub fn register_logger(name: &'static str, logger: &'static mut (Logger + Send + Sync)) {
        for registered in LOGGERS_ARRAY.lock().iter_mut().filter_map(|v| v.as_mut()) {
            if registered.name == name {
                panic!("Logger name was already registered");
            }
        }
        for slot in LOGGERS_ARRAY.lock().iter_mut() {
            if slot.is_none() {
                ::core::mem::replace(slot, Some(RegisteredLogger { name, logger }));
                return;
            }
        }
        panic!("Logger array was full");
    }

    /// Deregisters a logger.
    /// Logs will no longer be sent to it
    ///
    /// # PANICS
    ///
    /// Panics if the logger was not in the loggers array
    // TODO return an Error type
    pub fn deregister_logger(name: &'static str) {
        for slot in LOGGERS_ARRAY.lock().iter_mut() {
            if let Some(registered) = slot {
                if registered.name == name {
                    ::core::mem::replace(slot, None);
                    return;
                }
            }
        }
        panic!("Logger was not registered");
    }
}

/// The logger list is itself a logger. Logging to it will log on all registered loggers
impl Logger for Loggers {
    fn print(&mut self, string: &str) {
        for registered in LOGGERS_ARRAY.lock().iter_mut().filter_map(|v| v.as_mut()) {
            registered.logger.print(string);
        }
    }

    fn println(&mut self, string: &str) {
        for registered in LOGGERS_ARRAY.lock().iter_mut().filter_map(|v| v.as_mut()) {
            registered.logger.println(string);
        }
    }

    fn print_attr(&mut self, string: &str, attr: LogAttributes) {
        for registered in LOGGERS_ARRAY.lock().iter_mut().filter_map(|v| v.as_mut()) {
            registered.logger.print_attr(string, attr);
        }
    }

    fn println_attr(&mut self, string: &str, attr: LogAttributes) {
        for registered in LOGGERS_ARRAY.lock().iter_mut().filter_map(|v| v.as_mut()) {
            registered.logger.println_attr(string, attr);
        }
    }

    fn clear(&mut self) {
        for registered in LOGGERS_ARRAY.lock().iter_mut().filter_map(|v| v.as_mut()) {
            registered.logger.clear();
        }
    }

    unsafe fn force_unlock(&mut self) {
        LOGGERS_ARRAY.force_unlock();
        for registered in LOGGERS_ARRAY.lock().iter_mut().filter_map(|v| v.as_mut()) {
            registered.logger.force_unlock();
        }
    }
}

impl ::core::fmt::Write for Loggers
{
    fn write_str(&mut self, s: &str) -> Result<(), ::core::fmt::Error> {
        self.print(s);
        Ok(())
    }
}
