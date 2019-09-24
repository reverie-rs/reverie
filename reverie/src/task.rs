//! task structure and traits
use libc;
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd;
use nix::unistd::Pid;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::ptr::NonNull;

use reverie_common::consts;
use reverie_common::consts::*;

use syscalls::SyscallNo;

use crate::hooks;
use crate::remote::*;
use crate::stubs;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TaskState {
    /// XXX: iternal only
    Ready,
    /// busy
    Running,
    // stopped by breakpoint at @pc
    //Breakpoint(u64),
    /// stopped by signal
    Stopped(signal::Signal),
    /// signaled
    Signaled(signal::Signal),
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

pub trait Task {
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
