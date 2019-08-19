//! echo entrypoint who defines `captured_syscall`
//!

use api::task::*;
use api::remote::*;

use std::io::Result;

use crate::show::*;

pub async fn captured_syscall(
    g: &mut dyn GlobalState,
    p: &mut dyn ProcessState,
    no: i32,
    args: SyscallArgs
) -> i64 {
    let sc = syscalls::SyscallNo::from(no);

    /*
    let tid = p.gettid();

    let info = SyscallInfo::from(tid, sc, &args);
    eprint!("{}", info);
    let retval_fut = traced_syscall(p, sc, args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5);
    let retval = retval_fut.await;
    let info = info.set_retval(retval);
    eprintln!("{}", info);
    retval
     */
    -38
}
