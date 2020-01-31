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

use crate::task::*;
use std::boxed::Box;
use std::io;

pub type EventHandler = Box<dyn FnMut(&dyn Task) -> io::Result<()>>;

pub trait TaskEventHandler {
    fn new_event_handler(
        on_exec: EventHandler,
        on_fork: EventHandler,
        on_clone: EventHandler,
        on_exit: EventHandler,
    ) -> Self;
}

pub struct TaskEventCB {
    pub on_task_exec: Box<dyn FnMut(&mut dyn Task) -> io::Result<()>>,
    pub on_task_fork: Box<dyn FnMut(&mut dyn Task) -> io::Result<()>>,
    pub on_task_clone: Box<dyn FnMut(&mut dyn Task) -> io::Result<()>>,
    pub on_task_exit: Box<dyn FnOnce(i32) -> io::Result<()>>,
}

impl TaskEventCB {
    pub fn new(
        execfn: Box<dyn FnMut(&mut dyn Task) -> io::Result<()>>,
        forkfn: Box<dyn FnMut(&mut dyn Task) -> io::Result<()>>,
        clonefn: Box<dyn FnMut(&mut dyn Task) -> io::Result<()>>,
        exitfn: Box<dyn FnOnce(i32) -> io::Result<()>>,
    ) -> Self {
        TaskEventCB {
            on_task_exec: execfn,
            on_task_fork: forkfn,
            on_task_clone: clonefn,
            on_task_exit: exitfn,
        }
    }
}
