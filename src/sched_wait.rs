// simple (de)scheduler with `waitpid`
use std::io::{Result, Error, ErrorKind};
use std::collections::HashMap;
use nix::unistd::Pid;
use nix::sys::{wait, signal, ptrace};
use nix::sys::wait::WaitStatus;

use crate::remote::*;
use crate::task::*;
use crate::traced_task::*;
use crate::sched::*;
use crate::nr::*;
use crate::consts;
use crate::remote;
use crate::traced_task::TracedTask;

pub struct SchedWait {
    tasks: HashMap<Pid, TracedTask>,
}

impl Scheduler<TracedTask> for SchedWait {
    fn new() -> Self {
        SchedWait {tasks: HashMap::new()}
    }
    fn add(&mut self, task: TracedTask) {
        self.tasks.insert(Task::getpid(&task), task);
    }
    fn remove(&mut self, task: &mut TracedTask) {
        self.tasks.remove(&Task::getpid(task));
    }
    fn next(&mut self) -> Option<&mut TracedTask> {
        match ptracer_get_next(self) {
            Ok(res) => Some(res),
            Err(_) => None,
        }
    }
    fn size(&self) -> usize {
        self.tasks.len()
    }
}
    
fn ptracer_get_next (tasks: &mut SchedWait) -> Result<&mut TracedTask> {
    loop {
        match wait::waitpid(None, None) {
            Err(failure) => {
                return Err(Error::new(ErrorKind::Other, failure));
            },
            Ok(WaitStatus::Exited(pid, exit_code)) => {
                tasks.tasks.entry(pid).and_modify(|t|t.state = TaskState::Exited(exit_code));
                tasks.tasks.remove(&pid);
            },
            Ok(WaitStatus::Signaled(pid, signal, _core)) => {
                let task = tasks.tasks.get_mut(&pid).expect(&format!("unknown pid {}", pid));
                task.state = TaskState::Signaled(signal);
                return Ok(task);
            },
            Ok(WaitStatus::Continued(_newpid)) => (),
            Ok(WaitStatus::PtraceEvent(pid, signal, event)) if signal == signal::SIGTRAP => {
                let task = tasks.tasks.get_mut(&pid).expect(&format!("unknown pid {}", pid));
                let ev = task.getevent()?;
                task.state = TaskState::Event(ev as u64);
                return Ok(task);
            },
            Ok(WaitStatus::PtraceSyscall(pid)) => panic!("ptrace syscall"),
            Ok(WaitStatus::Stopped(pid, sig)) => {
                let task = tasks.tasks.get_mut(&pid).expect(&format!("unknown pid {}", pid));
                task.state = TaskState::Stopped(Some(sig));
                return Ok(task);
            },
            otherwise => panic!("unknown status: {:?}", otherwise),
        }
    }
    unreachable!("unreachable: ptrace main loop")
}
