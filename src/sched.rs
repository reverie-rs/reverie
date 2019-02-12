use nix::sys::signal;
use nix::sys::wait;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

use crate::remote::*;
use crate::task::Task;

pub trait Scheduler<Task> {
    fn new() -> Self
    where
        Self: Sized;
    fn add(&mut self, task: Task);
    fn remove(&mut self, task: &mut Task);
    fn next(&mut self) -> Option<Task>;
    fn size(&self) -> usize;
}
