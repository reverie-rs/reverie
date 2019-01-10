use core::fmt::*;
use core::*;
use crate::syscall::*;

struct RawStdio {
    fileno: i32,
}

impl Write for RawStdio {
    fn write_str(&mut self, s: &str) -> Result {
        let fd = self.fileno;
        let len = s.bytes().len();
        let buf: *const u8 = s.as_ptr();
        untraced_syscall(WRITE as i32, fd as i64, buf as i64, len as i64, 0, 0, 0);
        Ok(())
    }
}

pub fn _print(args: fmt::Arguments) {
    print_to(args, &mut RawStdio{fileno:1}, "stdout");
}

pub fn _eprint(args: fmt::Arguments) {
    print_to(args, &mut RawStdio{fileno:2}, "stderr");
}

fn print_to(
    args: fmt::Arguments,
    file: &mut RawStdio,
    _label: &str,
)
{
    core::fmt::write(file, args).expect("write failed");
}
