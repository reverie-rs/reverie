//! echo entrypoint who defines `captured_syscall`
//!

use api::task::*;
use api::remote::*;

use syscalls::SyscallNo;
use std::io::Result;

use nix::unistd::Pid;
use nix::sys::ptrace;

use futures::future::{Future, FutureExt};

use crate::show::*;

pub fn captured_syscall_prehook(
    g: &mut dyn GlobalState,
    p: &mut dyn ProcessState,
    pid: Pid,
    sc: SyscallNo,
    args: SyscallArgs
) {
    let info = SyscallInfo::from(pid, sc, &args);
    eprint!("{}", info);
}

pub fn captured_syscall_posthook(
    g: &mut dyn GlobalState,
    p: &mut dyn ProcessState,
    pid: Pid,
    sc: SyscallNo,
    retval: i64,
    args: SyscallArgs
) {
    let info = SyscallInfo::from(pid, sc, &args).set_retval(retval);
    eprintln!("{}", info);
}
