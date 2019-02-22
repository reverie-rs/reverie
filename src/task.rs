use libc;
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd;
use nix::unistd::Pid;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::ptr::NonNull;

use crate::consts;
use crate::consts::*;
use crate::hooks;
use crate::nr;
use crate::proc::*;
use crate::remote::*;
use crate::sched::Scheduler;
use crate::stubs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Stopped(signal::Signal),
    Signaled(signal::Signal),
    Event(u64),
    Exited(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunTask<Task> {
    Exited(i32),
    Runnable(Task),
    Forked(Task, Task),
}

pub trait Task {
    fn new(pid: Pid) -> Self
    where
        Self: Sized;
    fn cloned(&self) -> Self
    where
        Self: Sized;
    fn forked(&self) -> Self
    where
        Self: Sized;
    fn gettid(&self) -> Pid;
    fn getpid(&self) -> Pid;
    fn getppid(&self) -> Pid;
    fn getpgid(&self) -> Pid;
    fn exited(&self) -> Option<i32>;
    /// take ownership of `self`
    fn run(self) -> Result<RunTask<Self>>
    where
        Self: Sized;
}
