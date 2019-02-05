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
use crate::stubs;
use crate::sched::Scheduler;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    Running,
    Stopped(Option<signal::Signal>),
    Signaled(signal::Signal),
    Event(u64),
    Exited(i32),
}

pub trait Task {
    fn new(pid: Pid) -> Self where Self: Sized;
    fn reset(&mut self);
    fn getpid(&self) -> Pid;
    fn getppid(&self) -> Pid;
    fn gettid(&self) -> Pid;
    fn forked(&self, child: Pid) -> Self;
    fn cloned(&self, child: Pid) -> Self;
    fn exited(&self) -> Option<i32>;
    fn run(&mut self) -> Result<Option<Self>> where Self: Sized;
}
