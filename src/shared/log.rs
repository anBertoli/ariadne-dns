pub use crate::debug;
pub use crate::error;
pub use crate::info;
pub use crate::warn;
use serde::{Deserialize, Serialize};
use std::sync;

static LOG_LEVEL_ONCE: sync::Once = sync::Once::new();
static mut LOG_LEVEL: LogLevel = LogLevel::Debug;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialOrd, PartialEq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

pub fn init_log(lvl: LogLevel) {
    if LOG_LEVEL_ONCE.is_completed() {
        return;
    }
    unsafe {
        LOG_LEVEL_ONCE.call_once(|| {
            LOG_LEVEL = lvl;
        });
    }
}

pub fn log_level() -> LogLevel {
    if !LOG_LEVEL_ONCE.is_completed() {
        panic!("log not initialized");
    }
    unsafe { LOG_LEVEL }
}

#[macro_export]
macro_rules! debug {
    ($fmt:expr) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Debug {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "DEBUG".bold().bright_magenta(), $fmt);
        };
    }};

    ($fmt:expr, $($arg:tt)*) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Debug {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "DEBUG".bold().bright_magenta(), format!($fmt, $($arg)*));
        }
    }}
}

#[macro_export]
macro_rules! info {
    ($fmt:expr) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Info {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "INFO".bold().bright_green(), $fmt);
        };
    }};

    ($fmt:expr, $($arg:tt)*) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Info {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "INFO".bold().bright_green(), format!($fmt, $($arg)*));
        }
    }}
}

#[macro_export]
macro_rules! warn {
    ($fmt:expr) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Warn {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "WARN".bold().bright_yellow(), $fmt);
        };
    }};

    ($fmt:expr, $($arg:tt)*) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Warn {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "WARN".bold().bright_yellow(), format!($fmt, $($arg)*));
        };
    }}
}

#[macro_export]
macro_rules! error {
    ($fmt:expr) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Error {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "ERROR".bold().bright_red(), $fmt);
        };
    }};

    ($fmt:expr, $($arg:tt)+) => {{
        use colored::*;
        if log::log_level() <= log::LogLevel::Error {
            let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S");
            println!("{} {} {}", timestamp, "ERROR".bold().bright_red(), format!($fmt, $($arg)*));
        };
    }}
}
