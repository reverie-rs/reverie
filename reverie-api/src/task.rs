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

//! task structure and traits
use nix::sys::signal::Signal;
use nix::unistd::Pid;

use syscalls::SyscallNo;

use crate::remote::Injector;

pub trait GlobalState {
    fn new() -> Self
    where
        Self: Sized;
}

pub trait ProcessState: Task + Injector {
    fn new(pid: Pid) -> Self
    where
        Self: Sized;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// XXX: iternal only
    Ready,
    /// busy
    Running,
    // stopped by breakpoint at @pc
    //Breakpoint(u64),
    /// stopped by signal
    Stopped(Signal),
    /// signaled
    Signaled(Signal),
    /// exec event
    Exec,
    /// clone event
    Clone(Pid),
    /// fork/vfork event
    Fork(Pid),
    /// seccomp event
    Seccomp(SyscallNo),
    /// XXX: internal only
    Syscall(SyscallNo),
    /// XXX: internal only
    VforkDone,
    /// exited
    Exited(Pid, i32),
}

/// Task which can be scheduled by `Sched`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunTask<Task> {
    /// `Task` Exited with an exit code
    Exited(i32),
    /// `Task` can be scheduled
    Runnable(Task),
    /// Blocked `Task`
    Blocked(Task),
    /// A task tuple `(prent, child)` returned from `fork`/`vfork`/`clone`
    Forked(Task, Task),
}

pub trait Task: Injector {
    fn new(pid: Pid) -> Self
    where
        Self: Sized;
    fn cloned(&self, child: Pid) -> Self
    where
        Self: Sized;
    fn forked(&self, child: Pid) -> Self
    where
        Self: Sized;
    fn gettid(&self) -> Pid;
    fn getpid(&self) -> Pid;
    fn getppid(&self) -> Pid;
    fn getpgid(&self) -> Pid;
    fn exited(&self, exit_code: i32) -> Option<i32>;
}
