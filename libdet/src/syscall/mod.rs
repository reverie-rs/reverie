
pub use self::nr::SyscallNo::*;
pub use self::nr::SyscallNo;
pub use self::raw::*;
pub use self::helper::*;

mod nr;
mod raw;
mod helper;

const SYSCALL_MAX_ARGS: usize = 6;

pub struct Syscall {
    nr: SyscallNo,
    args: [i64; SYSCALL_MAX_ARGS],
}

impl Syscall {
    fn new(&self, nr: i32, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> Syscall {
        let aa = [a0, a1, a2, a3, a4, a5];
        Syscall{nr: SyscallNo::from(nr), args: aa}
    }
    fn run(&self) -> Result<i32, &'static str> {
        Ok(0)
    }
}

pub trait InterceptedSyscall {
    fn nr(&self) -> SyscallNo;
    fn run(&self, a0:i64, a1:i64, a2:i64, a3:i64, a4:i64, a5:i64) -> Result<i32, &'static str>;
}
