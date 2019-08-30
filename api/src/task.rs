//! task structure and traits

use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd::Pid;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::ptr::NonNull;
use std::boxed::Box;

use core::pin::Pin;
use futures::prelude::Future;
use futures::task::{Poll, Context};
use futures::task::Poll::*;

use syscalls::SyscallNo;

use crate::remote::Injector;

pub type EventHandler = Box<dyn FnMut(&dyn Task) -> Result<()>>;

pub trait TaskEventHandler {
    fn new_event_handler(
        on_exec: EventHandler,
        on_fork: EventHandler,
        on_clone: EventHandler,
        on_exit: EventHandler,
    ) -> Self;
}

pub struct TaskEventCB {
    pub on_task_exec: Box<dyn FnMut(&mut dyn Task) -> Result<()>>,
    pub on_task_fork: Box<dyn FnMut(&mut dyn Task) -> Result<()>>,
    pub on_task_clone: Box<dyn FnMut(&mut dyn Task) -> Result<()>>,
    pub on_task_exit: Box<dyn FnOnce(i32) -> Result<()>>,
}

impl TaskEventCB {
    pub fn new(execfn: Box<dyn FnMut(&mut dyn Task) -> Result<()>>,
               forkfn: Box<dyn FnMut(&mut dyn Task) -> Result<()>>,
               clonefn: Box<dyn FnMut(&mut dyn Task) -> Result<()>>,
               exitfn: Box<dyn FnOnce(i32) -> Result<()>>) -> Self {
        TaskEventCB {
            on_task_exec: execfn,
            on_task_fork: forkfn,
            on_task_clone: clonefn,
            on_task_exit: exitfn,
        }
    }
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    fn getpid(&self) -> Pid;
    fn gettid(&self) -> Pid;
    fn getppid(&self) -> Pid;
    fn getpgid(&self) -> Pid;
    fn exited(&self, code: i32) -> Option<i32>;
}

/*
pub trait Runnable<G>
where
    G: GlobalState,
{
    type Item;
    /// take ownership of `self`
    fn run(self, glob: &mut G) -> Pin<Box<dyn Future<Output = RunTask<Self::Item>>>>;
}
*/
