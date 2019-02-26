// simple (de)scheduler with `waitpid`
use nix::sys::wait::{WaitStatus, WaitPidFlag};
use nix::sys::{ptrace, signal, wait};
use nix::unistd::Pid;
use std::collections::{VecDeque, HashMap};
use std::io::{Error, ErrorKind, Result};
use log::Level::Trace;

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
    run_queue: VecDeque<Pid>,
    blocked_queue: VecDeque<Pid>,
}

impl Scheduler<TracedTask> for SchedWait {
    fn new() -> Self {
        SchedWait {
            tasks: HashMap::new(),
            run_queue: VecDeque::new(),
            blocked_queue: VecDeque::new(),
        }
    }
    fn add(&mut self, task: TracedTask) {
        let tid = Task::gettid(&task);
        self.tasks.insert(tid, task);
        self.run_queue.push_back(tid);
    }
    fn add_and_schedule(&mut self, task: TracedTask) {
        let tid = task.gettid();
        let sig = task.signal_to_deliver;
        let state = task.state;
        self.tasks.insert(tid, task);
        self.run_queue.push_front(tid);
        if state == TaskState::Event(7) { // PTRACE_EVENT_SECCOMP
            ptrace::syscall(tid).expect(&format!("add_and_schedule, syscall {}", tid));
        } else {
            ptrace::cont(tid, sig).expect(&format!("add_and_schedule, resume {}", tid));
        }
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
    let mut retry = true;
    while retry {
        let tid_ = tasks
            .run_queue.pop_front()
            .or_else(||tasks.blocked_queue.pop_front());
        log::trace!("[sched] sched next {:?}", tid_);
        if tid_.is_none() { return None; }
        let tid = tid_.unwrap();
        if log::log_enabled!(Trace) {
            let mut debug_string = format!("[sched]: {:?}, task queue:", tid);
            tasks.tasks.iter().for_each(|(k, _)| debug_string += &format!(" {}", k));
            log::trace!("{}", debug_string);
        }
        while let Ok(status) = wait::waitpid(Some(tid), Some(WaitPidFlag::WNOHANG)) {
            retry = status == WaitStatus::StillAlive;
            if !retry {
                log::trace!("[sched] {} {:?}", tid, status);
            }
            match status {
                // no status change, TODO: dead lock detection?
                WaitStatus::StillAlive => {
                    tasks.blocked_queue.push_back(tid);
                    break;
                }
                WaitStatus::Signaled(pid, signal, _core) => {
                    let mut task = tasks.tasks.remove(&tid).expect(&format!("unknown pid {:}", tid));
                    task.state = TaskState::Signaled(signal);
                    return Some(task);
                }
                WaitStatus::Continued(pid) => {
                    let task = tasks.tasks.remove(&tid).expect(&format!("unknown pid {:}", tid));
                    return Some(task);
                }
                WaitStatus::PtraceEvent(pid, signal, event) if signal == signal::SIGTRAP => {
                    let mut task = tasks.tasks.remove(&tid).expect(&format!("unknown pid {:}", tid));
                    task.state = TaskState::Event(event as u64);
                    return Some(task);
                }
                WaitStatus::PtraceSyscall(pid) => {
                    assert!(pid == tid);
                    let mut task = tasks.tasks.remove(&tid).unwrap();
                    let regs = task.getregs().unwrap();
                    task.state = TaskState::Syscall(regs.rip);
                    return Some(task);
                }
                WaitStatus::Stopped(pid, sig) => {
                    // ignore group-stop
                    if !is_ptrace_group_stop(pid, sig) {
                        // NB: we use TaskState::Ready for the intial SIGSTOP
                        let mut task = tasks.tasks.remove(&tid).expect(&format!("unknown pid {:}", tid));
                        if task.state != TaskState::Ready {
                            task.state = TaskState::Stopped(sig);
                        }
                        return Some(task);
                    }
                }
                WaitStatus::Exited(pid, retval) => {
                    tasks.tasks.remove(&pid);
                    log::trace!("task {} exited with: {}", pid, retval);
                }
                otherwise => panic!("unknown status: {:?}", otherwise),
            }
        }
    }
    None
}
