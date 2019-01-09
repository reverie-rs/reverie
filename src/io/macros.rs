
#![feature(format_args_nl)]

#[macro_use]

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::io::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ($crate::io::_eprint(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprintln {
    () => (eprint!("\n"));
    ($($arg:tt)*) => ({
        $crate::io::_eprint(format_args_nl!($($arg)*));
    })
}

#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => ({
        $crate::io::_print(format_args_nl!($($arg)*));
    })
}
