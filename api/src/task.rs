//! task structure and traits

use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd;
use nix::unistd::Pid;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::ptr::NonNull;

use crate::remote::Injector;

pub trait GlobalState {
    fn new() -> Self where Self: Sized;
}

pub trait ProcessState: Task + Injector {
    fn new(pid: Pid) -> Self where Self: Sized;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Stopped(signal::Signal),
    Signaled(signal::Signal),
    Event(u64),
    Syscall,
    Exited(i32),
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
    fn new(pid: Pid) -> Self where Self: Sized;
    fn cloned(&self) -> Self where Self: Sized;
    fn forked(&self) -> Self where Self: Sized;
    fn gettid(&self) -> Pid;
    fn getpid(&self) -> Pid;
    fn getppid(&self) -> Pid;
    fn getpgid(&self) -> Pid;
    fn exited(&self) -> Option<i32>;
}

pub trait Runnable<G> where G: GlobalState {
    type Item;
    /// take ownership of `self`
    fn run(self, glob: &mut G) -> Result<RunTask<Self::Item>>;
}
