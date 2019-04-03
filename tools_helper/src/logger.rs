#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub enum Level {
    Error = 0x1,
    Warn,
    Info,
    Debug,
    Trace
}

pub fn log_enabled(level: Level) -> bool {
    let log_level_ptr = 0x7000_1038 as *const i64;
    let log_level = unsafe { core::ptr::read(log_level_ptr) };
    log_level >= level as i64
}

#[macro_export(local_inner_macros)]
macro_rules! error {
    (target: $target:expr, $($arg:tt)+) => (
        log!(target: $target, $crate::logger::Level::Error, $($arg)+);
    );
    ($($arg:tt)+) => (
        log!($crate::logger::Level::Error, $($arg)+);
    )
}

#[macro_export(local_inner_macros)]
macro_rules! warn {
    (target: $target:expr, $($arg:tt)+) => (
        log!(target: $target, $crate::logger::Level::Warn, $($arg)+);
    );
    ($($arg:tt)+) => (
        log!($crate::logger::Level::Warn, $($arg)+);
    )
}

#[macro_export(local_inner_macros)]
macro_rules! info {
    (target: $target:expr, $($arg:tt)+) => (
        log!(target: $target, $crate::logger::Level::Info, $($arg)+);
    );
    ($($arg:tt)+) => (
        log!($crate::logger::Level::Info, $($arg)+);
    )
}

#[macro_export(local_inner_macros)]
macro_rules! debug {
    (target: $target:expr, $($arg:tt)+) => (
        log!(target: $target, $crate::logger::Level::Debug, $($arg)+);
    );
    ($($arg:tt)+) => (
        log!($crate::logger::Level::Debug, $($arg)+);
    )
}

#[macro_export(local_inner_macros)]
macro_rules! trace {
    (target: $target:expr, $($arg:tt)+) => (
        log!(target: $target, $crate::logger::Level::Trace, $($arg)+);
    );
    ($($arg:tt)+) => (
        log!($crate::logger::Level::Trace, $($arg)+);
    )
}

#[macro_export(local_inner_macros)]
macro_rules! log {
    (target: $target:expr, $lvl:expr, $($arg:tt)+) => ({
        let lvl = $lvl;
        if $crate::logger::log_enabled(lvl) {
            $crate::stdio::_eprint(__log_format_args!($($arg)+));
        }
    });
    ($lvl:expr, $($arg:tt)+) => (log!(target: __log_module_path!(), $lvl, $($arg)+));
}

#[macro_export(local_inner_macros)]
macro_rules! msg {
    ($($arg:tt)*) => ({
        $crate::stdio::_eprint(__log_format_args!($($arg)*));
    })
}

#[doc(hidden)]
#[macro_export]
macro_rules! __log_format_args {
    ($($args:tt)*) => {
        format_args_nl!($($args)*)
    };
}
