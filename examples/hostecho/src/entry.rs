//! echo entrypoint who defines `captured_syscall`
//!
use api::task::*;
use api::remote::*;

use crate::show::*;

#[no_mangle]
pub extern "C" fn captured_syscall(
    g: &mut dyn GlobalState,
    p: &mut dyn ProcessState,
    no: i32,
    args: SyscallArgs
) -> i64 {
    let sc = syscalls::SyscallNo::from(no);

    let tid = p.gettid();

    let info = SyscallInfo::from(tid, sc, &args);
    eprint!("{}", info);
    let retval = p.inject_syscall(sc, args);
    let info = info.set_retval(retval);
    eprintln!("{}", info);
    retval
}
