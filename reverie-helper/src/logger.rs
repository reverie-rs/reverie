//! safe logger for writing reverie tools (shared library)
//!
//! log is enabled by passing `TOOL_LOG=xxx` from reverie
//!
//! NB: tools can use rust `log` crate, but must use this
//! logger as backend. That is because logging in captured syscalls is
//! very low level, roughly the same (or sligher higher) level as signal
//! handlers, allocation should be reduced to minimum (if not none); and
//! must also keep thread-safe in mind.
//!
//! NB: any allocation (i.e.: `toString`) is considered DANGEROUS.
//! we use a global static ring buffer to avoid allocations, and use CAS
//! spinlocks to prevent race condition. note the same thread can call
//! spin lock multiple times.
//!

use core::fmt::{Arguments, Error, Write};
use log::{Level, Log, Metadata, Record, SetLoggerError};

use crate::spinlock::SpinLock;
use syscalls::*;

const RING_BUFF_SIZE: usize = 16384;

struct RingBuffer {
    bytes: [u8; RING_BUFF_SIZE],
    size: isize,
    begin: isize,
    end: isize,
    is_empty: bool,
    rawfd: i32,
}
static mut RING_BUFFER: RingBuffer = RingBuffer {
    bytes: [0; RING_BUFF_SIZE],
    size: RING_BUFF_SIZE as isize,
    begin: 0,
    end: 0,
    is_empty: true,
    rawfd: 2,
};

struct RingBufferLogger {}
static LOGGER: RingBufferLogger = RingBufferLogger {};
static LOGGER_LOCK: SpinLock = SpinLock::new();

fn enter_critical_section() {
    LOGGER_LOCK.lock();
}

fn leave_critical_section() {
    LOGGER_LOCK.unlock();
}

fn update_buffer(
    rb: &mut RingBuffer,
    buffer: *const u8,
    n: isize,
    update_begin: bool,
) {
    let ptr_begin = unsafe { rb.bytes.as_ptr().offset(rb.begin) };
    let ptr_end = unsafe { rb.bytes.as_ptr().offset(rb.end) };
    let ptr_min = rb.bytes.as_ptr();
    let ptr_max = unsafe { rb.bytes.as_ptr().offset(rb.size) };
    debug_assert!(ptr_begin >= ptr_min);
    debug_assert!(ptr_end < ptr_max);
    assert!(n <= rb.size);

    if n == 0 {
        return;
    }

    rb.is_empty = false;

    if rb.end + n < rb.size {
        unsafe {
            core::ptr::copy_nonoverlapping(
                buffer,
                ptr_end as *mut u8,
                n as usize,
            );
        };
        if update_begin {
            rb.begin = rb.end;
        }
        rb.end += n;
    } else {
        let i = rb.size - rb.end;
        let j = n - i;
        unsafe {
            core::ptr::copy_nonoverlapping(
                buffer,
                ptr_end as *mut u8,
                i as usize,
            );
            core::ptr::copy_nonoverlapping(
                buffer.offset(i),
                ptr_min as *mut u8,
                j as usize,
            );
        }
        if update_begin {
            rb.begin = rb.end;
        }
        rb.end = j;
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __log_format_args {
    ($($args:tt)*) => {
        format_args!($($args)*)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __log_format_args_nl {
    ($($args:tt)*) => {
        format_args_nl!($($args)*)
    };
}

/// log without checking log level
#[macro_export(local_inner_macros)]
macro_rules! msg {
    ($($arg:tt)*) => ({
        $crate::logger::__internal_ring_buffer_eprint(__log_format_args!($($arg)*));
    })
}

/// log without checking log level
#[macro_export(local_inner_macros)]
macro_rules! msgln {
    ($($arg:tt)*) => ({
        $crate::logger::__internal_ring_buffer_eprint(__log_format_args_nl!($($arg)*));
    })
}

#[allow(unused)]
#[doc(hidden)]
pub fn __internal_do_rb_flush() {
    LOGGER.flush();
}

/// flush the logger
#[macro_export(local_inner_macros)]
macro_rules! flush {
    () => {{
        $crate::logger::__internal_do_rb_flush();
    }};
}

fn ll_write(rawfd: i32, buffer: *const u8, size: usize) {
    let _ = syscall!(SYS_write, rawfd, buffer, size);
}

fn log_enabled(level: Level) -> bool {
    let log_level_ptr = 0x7000_1038 as *const i64;
    let log_level = unsafe { core::ptr::read(log_level_ptr) };
    log_level >= level as i64
}

static LOG_LEVEL_STR: &[&str] =
    &["", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
fn log_level_str(level: Level) -> &'static str {
    let i = level as usize;
    LOG_LEVEL_STR[i % 6]
}

impl Log for RingBufferLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        log_enabled(metadata.level())
    }
    fn log(&self, record: &Record) {
        enter_critical_section();
        if self.enabled(record.metadata()) {
            msg!("[{:<5}] {}", log_level_str(record.level()), record.args());
        }
        leave_critical_section();
    }
    fn flush(&self) {
        enter_critical_section();
        unsafe { flush_buffer(&mut RING_BUFFER, &ll_write) };
        leave_critical_section();
    }
}

fn ring_buffer_write<F>(rb: &mut RingBuffer, s: &str, flush: F)
where
    F: Fn(i32, *const u8, usize),
{
    match core::slice::memchr::memrchr(b'\n', s.as_bytes()) {
        None => update_buffer(rb, s.as_ptr(), s.bytes().len() as isize, false),
        Some(i) => {
            let i = 1 + i;
            let j = s.bytes().len() - i;
            let first = s.as_ptr();
            let second = unsafe { first.offset(1 + i as isize) };
            update_buffer(rb, first, i as isize, false);
            flush_buffer(rb, flush);
            update_buffer(rb, second, j as isize, false);
        }
    }
}

fn flush_buffer<F>(rb: &mut RingBuffer, flush: F)
where
    F: Fn(i32, *const u8, usize),
{
    if rb.is_empty {
        return;
    }
    unsafe {
        if rb.end > rb.begin {
            flush(
                rb.rawfd,
                rb.bytes.as_ptr().offset(rb.begin),
                (rb.end - rb.begin) as usize,
            );
        } else {
            let i = rb.size - rb.end;
            let j = rb.size - (rb.begin - rb.end) - i;
            flush(rb.rawfd, rb.bytes.as_ptr().offset(rb.begin), i as usize);
            flush(rb.rawfd, rb.bytes.as_ptr(), j as usize);
        }
    };
    rb.end = rb.begin;
    rb.is_empty = true;
}

/// initialize the logger
pub fn init() -> Result<(), SetLoggerError> {
    let log_level_ptr = 0x7000_1038 as *const i64;
    let log_level = unsafe { core::ptr::read(log_level_ptr) };
    let level = match log_level {
        1 => Some(Level::Error),
        2 => Some(Level::Warn),
        3 => Some(Level::Info),
        4 => Some(Level::Debug),
        5 => Some(Level::Trace),
        _ => None,
    };
    log::set_logger(&LOGGER)?;
    if let Some(lvl) = level {
        log::set_max_level(lvl.to_level_filter());
    }
    Ok(())
}

impl Write for RingBuffer {
    fn write_str(&mut self, s: &str) -> Result<(), Error> {
        ring_buffer_write(self, s, ll_write);
        Ok(())
    }
}

#[doc(hidden)]
pub fn __internal_ring_buffer_eprint(args: Arguments) {
    unsafe { rb_print_to(args, &mut RING_BUFFER) };
}

fn rb_print_to(args: Arguments, file: &mut RingBuffer) {
    core::fmt::write(file, args).expect("write failed");
}

/// print to stderr, *NOT* thread-safe
#[macro_export(local_inner_macros)]
macro_rules! unsafe_msg {
    ($($arg:tt)*) => ({
        $crate::stdio::_eprint(__log_format_args!($($arg)*));
    })
}
