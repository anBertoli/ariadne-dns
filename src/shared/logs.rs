pub use log::Level;
use simple_logger::SimpleLogger;

/// Initialize the logging facility with Debug level.
/// Panics if it's called more than one time.
pub fn init_log() {
    SimpleLogger::new()
        .with_level(Level::Debug.to_level_filter())
        .init()
        .unwrap()
}

#[inline]
pub fn set_max_level(lvl: Level) {
    log::set_max_level(lvl.to_level_filter())
}
