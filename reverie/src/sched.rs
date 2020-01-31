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

//! `Scheduler` trait
use nix::sys::signal;
use nix::sys::wait;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

use crate::remote::*;
use crate::task::Task;
use reverie_common::state::ReverieState;

pub trait Scheduler<Task> {
    fn new() -> Self
    where
        Self: Sized;
    fn add(&mut self, task: Task);
    fn add_blocked(&mut self, task: Task);
    fn add_and_schedule(&mut self, task: Task);
    fn remove(&mut self, task: &mut Task);
    fn next(&mut self) -> Option<Task>;
    fn size(&self) -> usize;
    fn event_loop(&mut self) -> i32;
}
