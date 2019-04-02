use log::{Log, Level, Metadata, Record, SetLoggerError};

use syscalls::*;

struct SimpleUntracedLogger {
    level: Level,
}

fn write_str(s: &str) {
    let stderr_fileno = 2i64;
    let len = s.bytes().len();
    let buf: *const u8 = s.as_ptr();
    let _ = syscall(SYS_write as i32, stderr_fileno, buf as i64, len as i64, 0, 0, 0);
}

impl Log for SimpleUntracedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn flush(&self) {
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let msg = format!(
                "[{:<5}] {}\n",
                record.level().to_string(),
                record.args());
            write_str(&msg);
        }
    }
}

pub fn init_with_level(level: Level) -> Result<(), SetLoggerError> {
    let logger = SimpleUntracedLogger { level };
    log::set_boxed_logger(Box::new(logger))?;
    log::set_max_level(level.to_level_filter());
    Ok(())
}

pub fn init() -> Result<(), SetLoggerError> {
    init_with_level(Level::Trace)
}
