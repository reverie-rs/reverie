
use std::io::{Result};
use std::collections::HashMap;
use nix::unistd::Pid;

use crate::remote::*;
use crate::task::{Task};

pub struct TracedTasks {
    tasks: HashMap<Pid, Task>,
}

impl TracedTasks{
    pub fn new() -> Self {
        TracedTasks {tasks: HashMap::new()}
    }
    pub fn add(&mut self, task: Task) -> Result<()> {
        self.tasks.insert(task.pid, task);
        Ok(())
    }
    pub fn remove(&mut self, pid: Pid) -> Result<()> {
        self.tasks.remove(&pid);
        Ok(())
    }
    pub fn get(&self, pid: Pid) -> &Task {
        self.tasks.get(&pid).expect(&format!("unknown pid {}", pid))
    }
    pub fn get_mut(&mut self, pid: Pid) -> &mut Task {
        self.tasks.get_mut(&pid).expect(&format!("unknown pid {}", pid))
    }
    pub fn size(&self) -> usize {
        self.tasks.len()
    }
}
