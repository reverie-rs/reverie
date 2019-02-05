
use std::io::{Result, Error, ErrorKind};
use std::collections::HashMap;
use nix::unistd::Pid;
use nix::sys::wait;
use nix::sys::signal;
use nix::sys::wait::WaitStatus;

use crate::remote::*;
use crate::task::Task;

pub trait Scheduler<Task> {
    fn new() -> Self where Self: Sized;
    fn add(&mut self, task: Task);
    fn remove(&mut self, task: &mut Task);
    fn next(&mut self) -> Option<Task>;
    fn size(&self) -> usize;
}
