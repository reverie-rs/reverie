
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::io::stdio::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => ($crate::io::stdio::_eprint(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! eprintln {
    () => (eprint!("\n"));
    ($($arg:tt)*) => ({
        $crate::io::stdio::_eprint(format_args_nl!($($arg)*));
    })
}

#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => ({
        $crate::io::stdio::_print(format_args_nl!($($arg)*));
    })
}

