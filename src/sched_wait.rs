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

// tracee received group stop
// NB: must be call after waitpid returned STOPPED status.
// see `man ptrace`, `Group-stop` for more details.
fn is_ptrace_group_stop(pid: Pid, sig: signal::Signal) -> bool {
    if sig == signal::SIGSTOP ||
        sig == signal::SIGTSTP ||
        sig == signal::SIGTTIN ||
        sig == signal::SIGTTOU {
            ptrace::getsiginfo(pid).is_err()
       } else {
            false
       }
}

fn ptracer_get_next(tasks: &mut SchedWait) -> Option<TracedTask> {
    while let Ok(status) = wait::waitpid(None, Some(wait::WaitPidFlag::__WALL)) {
        match status {
            WaitStatus::Exited(pid, exit_code) => {
            }
            WaitStatus::Signaled(pid, signal, _core) => {
                let mut task = tasks
                    .tasks
                    .remove(&pid)
                    .expect(&format!("signaled: unknown pid {} signal {}", pid, signal));
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
                    .expect(&format!("unknown pid {} {} {}", pid, signal, event));
                task.state = TaskState::Event(event as u64);
                return Some(task);
            }
            WaitStatus::PtraceSyscall(pid) => panic!("ptrace syscall"),
            // sometimes ptrace delivers signal even before fork/vfork event
            // in fact, Linux kernel does not guarantee the signal must happen
            // after fork/vfork
            // see: https://stackoverflow.com/questions/49354408/why-does-a-sigtrap-ptrace-event-stop-occur-when-the-tracee-receives-sigcont
            WaitStatus::Stopped(pid, sig) => {
                // ignore group-stop by let tracee continue
                // and enter next (tracer) waitpid
                if is_ptrace_group_stop(pid, sig) {
                    ptrace::cont(pid, Some(sig)).unwrap();
                } else {
                    let mut task = tasks.tasks.remove(&pid).unwrap_or(Task::new(pid));
                    task.state = TaskState::Stopped(Some(sig));
                    return Some(task);
                }
            }
            otherwise => panic!("unknown status: {:?}", otherwise),
        }
    }
    None
}
