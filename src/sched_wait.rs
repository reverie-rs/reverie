// simple (de)scheduler with `waitpid`
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, wait};
use nix::unistd::Pid;
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};

use crate::consts;
use crate::nr::*;
use crate::remote;
use crate::remote::*;
use crate::sched::*;
use crate::task::*;
use crate::traced_task::TracedTask;
use crate::traced_task::*;

pub struct SchedWait {
    tasks: HashMap<Pid, TracedTask>,
}

impl Scheduler<TracedTask> for SchedWait {
    fn new() -> Self {
        SchedWait {
            tasks: HashMap::new(),
        }
    }
    fn add(&mut self, task: TracedTask) {
        let pid = Task::getpid(&task);
        self.tasks.insert(pid, task);
    }
    fn remove(&mut self, task: &mut TracedTask) {
        self.tasks.remove(&Task::getpid(task));
    }
    fn next(&mut self) -> Option<TracedTask> {
        ptracer_get_next(self)
    }
    fn size(&self) -> usize {
        self.tasks.len()
    }
}

fn ptracer_get_next(tasks: &mut SchedWait) -> Option<TracedTask> {
    while let Ok(status) = wait::waitpid(None, None) {
        match status {
            WaitStatus::Exited(pid, exit_code) => {
                tasks
                    .tasks
                    .entry(pid)
                    .and_modify(|t| t.state = TaskState::Exited(exit_code));
                tasks.tasks.remove(&pid);
            }
            WaitStatus::Signaled(pid, signal, _core) => {
                let mut task = tasks
                    .tasks
                    .remove(&pid)
                    .expect(&format!("unknown pid {}", pid));
                task.state = TaskState::Signaled(signal);
                return Some(task);
            }
            WaitStatus::Continued(pid) => {
                let mut task = tasks
                    .tasks
                    .remove(&pid)
                    .expect(&format!("unknown pid {}", pid));
                task.state = TaskState::Running;
                return Some(task);
            }
            WaitStatus::PtraceEvent(pid, signal, event) if signal == signal::SIGTRAP => {
                let mut task = tasks
                    .tasks
                    .remove(&pid)
                    .expect(&format!("unknown pid {}", pid));
                task.state = TaskState::Event(event as u64);
                return Some(task);
            }
            WaitStatus::PtraceSyscall(pid) => panic!("ptrace syscall"),
            WaitStatus::Stopped(pid, sig) => {
                let mut task = tasks
                    .tasks
                    .remove(&pid)
                    .expect(&format!("unknown pid {}", pid));
                task.state = TaskState::Stopped(Some(sig));
                return Some(task);
            }
            otherwise => panic!("unknown status: {:?}", otherwise),
        }
    }
    None
}
