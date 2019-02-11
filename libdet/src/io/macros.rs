
#[macro_export]
macro_rules! raw_print {
    ($($arg:tt)*) => ($crate::io::stdio::_raw_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! raw_eprint {
    ($($arg:tt)*) => ($crate::io::stdio::_raw_eprint(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! raw_eprintln {
    () => (eprint!("\n"));
    ($($arg:tt)*) => ({
        $crate::io::stdio::_raw_eprint(format_args_nl!($($arg)*));
    })
}

#[macro_export]
macro_rules! raw_println {
    () => (print!("\n"));
    ($($arg:tt)*) => ({
        $crate::io::stdio::_raw_print(format_args_nl!($($arg)*));
    })
}

