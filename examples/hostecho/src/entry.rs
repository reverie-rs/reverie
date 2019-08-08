//! echo entrypoint who defines `captured_syscall`
//!
use syscalls::*;

use crate::show::*;
use crate::local_state::{ProcessState};

#[no_mangle]
pub extern "C" fn captured_syscall(
    p: &mut ProcessState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    let sc = syscalls::SyscallNo::from(no);

    let tid = syscall!(SYS_gettid).unwrap();

    let info = SyscallInfo::from(tid as i32, sc, a0, a1, a2, a3, a4, a5);
    eprint!("{}", info);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    eprintln!("{}", SyscallRetInfo::from(tid as i32, sc, info.args_after_syscall(), ret, info.nargs_before == 0));
    ret
}
