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

    /// Clears the whole screen (if possible)
    fn clear(&mut self) {}
}

