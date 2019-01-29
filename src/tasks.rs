
use std::io::{Result};
use std::collections::HashMap;
use nix::unistd::Pid;

use crate::remote::*;

pub struct TracedTasks{
    tasks: HashMap<Pid, TracedTask>,
}

impl TracedTasks{
    pub fn new() -> Self {
        TracedTasks{tasks: HashMap::new()}
    }
    pub fn add(&mut self, task: TracedTask) -> Result<()> {
        self.tasks.insert(task.pid, task);
        Ok(())
    }
    pub fn remove(&mut self, pid: Pid) -> Result<()> {
        self.tasks.remove(&pid);
        Ok(())
    }
    pub fn get(&self, pid: Pid) -> &TracedTask {
        self.tasks.get(&pid).unwrap()
    }
    pub fn get_mut(&mut self, pid: Pid) -> &mut TracedTask {
        self.tasks.get_mut(&pid).unwrap()
    }
}
