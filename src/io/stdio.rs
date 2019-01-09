
use core::fmt;
use core::fmt::*;
use core::*;

struct RawStdio {
    fileno: i32,
}

impl Write for RawStdio {
    fn write_str(&mut self, s: &str) -> Result {
        Ok(())
    }
}

pub fn _print(args: fmt::Arguments) {
    print_to(args, RawStdio{fileno:1}, "stdout");
}

pub fn _eprint(args: fmt::Arguments) {
    print_to(args, RawStdio{fileno:2}, "stderr");
}

fn print_to(
    args: fmt::Arguments,
    file: RawStdio,
    label: &str,
)
{
}
