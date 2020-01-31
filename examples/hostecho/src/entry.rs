/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * 
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

//! echo entrypoint who defines `captured_syscall`
//!

use reverie_api::remote::*;
use reverie_api::task::*;

use std::io::Result;
use syscalls::SyscallNo;

use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::show::*;

pub fn captured_syscall_prehook(
    g: &mut dyn GlobalState,
    p: &mut dyn ProcessState,
    pid: Pid,
    sc: SyscallNo,
    args: SyscallArgs,
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
    args: SyscallArgs,
) {
    let info = SyscallInfo::from(pid, sc, &args).set_retval(retval);
    eprintln!("{}", info);
}
