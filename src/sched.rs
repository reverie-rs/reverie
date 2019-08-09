//! `Scheduler` trait
use nix::sys::signal;
use nix::sys::wait;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

use crate::remote::*;
use crate::task::Task;
use crate::state::*;

pub trait Scheduler {
    type Item;
    fn new() -> Self where Self::Item: Sized;
    fn add(&mut self, task: Box<Task<Item = Self::Item>>);
    fn add_blocked(&mut self, task: impl<Item> Task<Item = Self::Item>);
    fn add_and_schedule(&mut self, task: impl<Item> Task<Item = Self::Item>);
    fn remove(&mut self, task: &mut impl<Item> Task<Item = Self::Item>);
    fn next(&mut self) -> Option<impl<Item> Task<Item = Self::Item>>;
    fn size(&self) -> usize;
}

pub trait SchedulerEventLoop<G>: Scheduler where G: GlobalState {
    fn event_loop(&mut self, glob: &mut G) -> i32;
}
