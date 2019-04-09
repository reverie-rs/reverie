// simple (de)scheduler with `waitpid`
use log::Level::Trace;
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::sys::{ptrace, signal, wait};
use nix::unistd::Pid;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::sync::atomic::{Ordering, AtomicUsize};

use crate::consts;
use crate::nr::*;
use crate::remote;
use crate::remote::*;
use crate::sched::*;
use crate::task::*;
use crate::traced_task::TracedTask;
use crate::traced_task::*;
use crate::state::SystraceState;

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
    fn add_blocked(&mut self, task: TracedTask) {
        let tid = Task::gettid(&task);
        self.tasks.insert(tid, task);
        self.blocked_queue.push_back(tid);
    }
    fn add_and_schedule(&mut self, mut task: TracedTask) {
        let tid = task.gettid();
        let sig = task.signal_to_deliver;
        // PTRACE_EVENT_SECCOMP
        let is_seccomp = task.task_state_is_seccomp();
        if !is_seccomp {
            // signal is to be delivered
            task.signal_to_deliver = None;
        }
        self.tasks.insert(tid, task);
        self.run_queue.push_front(tid);
        if is_seccomp {
            let _ = ptrace::syscall(tid);
        } else {
            let _ = ptrace::cont(tid, sig);
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
    fn event_loop(&mut self, state: &mut SystraceState) -> i32 {
        sched_wait_event_loop(self, state)
    }
}

// tracee received group stop
// NB: must be call after waitpid returned STOPPED status.
// see `man ptrace`, `Group-stop` for more details.
fn is_ptrace_group_stop(pid: Pid, sig: signal::Signal) -> bool {
    if sig == signal::SIGSTOP
        || sig == signal::SIGTSTP
        || sig == signal::SIGTTIN
        || sig == signal::SIGTTOU
    {
        ptrace::getsiginfo(pid).is_err()
    } else {
        false
    }
}

fn ptracer_get_next(tasks: &mut SchedWait) -> Option<TracedTask> {
    let mut retry = true;
    while retry {
        let tid_ = tasks
            .run_queue
            .pop_front()
            .or_else(|| tasks.blocked_queue.pop_front());
        if tid_.is_none() {
            return None;
        }
        let tid = tid_.unwrap();
        loop {
            let status = wait::waitpid(Some(tid), Some(WaitPidFlag::WNOHANG));
            retry = status == Ok(WaitStatus::StillAlive);
            if !retry {
                log::trace!("[sched] {} {:?}", tid, status);
            }
            match status {
                // no status change, TODO: dead lock detection?
                Ok(WaitStatus::StillAlive) => {
                    tasks.blocked_queue.push_back(tid);
                    break;
                }
                Ok(WaitStatus::Signaled(_pid, signal, _core)) => {
                    let mut task = tasks
                        .tasks
                        .remove(&tid)
                        .expect(&format!("unknown pid {:}", tid));
                    task.state = TaskState::Signaled(signal);
                    return Some(task);
                }
                Ok(WaitStatus::Continued(_)) => {
                    let task = tasks
                        .tasks
                        .remove(&tid)
                        .expect(&format!("unknown pid {:}", tid));
                    return Some(task);
                }
                Ok(WaitStatus::PtraceEvent(_, sig, event)) if sig == signal::SIGTRAP => {
                    let mut task = tasks
                        .tasks
                        .remove(&tid)
                        .expect(&format!("unknown pid {:}", tid));
                    task.state = TaskState::Event(event as u64);
                    return Some(task);
                }
                Ok(WaitStatus::PtraceSyscall(pid)) => {
                    assert!(pid == tid);
                    let mut task = tasks.tasks.remove(&tid).unwrap();
                    task.state = TaskState::Syscall;
                    return Some(task);
                }
                Ok(WaitStatus::Stopped(pid, sig)) => {
                    // ignore group-stop
                    if !is_ptrace_group_stop(pid, sig) {
                        // NB: we use TaskState::Ready for the intial SIGSTOP
                        let mut task = tasks
                            .tasks
                            .remove(&tid)
                            .expect(&format!("unknown pid {:}", tid));
                        if task.state != TaskState::Ready {
                            task.state = TaskState::Stopped(sig);
                        }
                        return Some(task);
                    }
                }
                Ok(WaitStatus::Exited(pid, _retval)) => {
                    tasks.tasks.remove(&pid);
                    retry = true;
                    break;
                }
                Err(nix::Error::Sys(nix::errno::Errno::ECHILD)) => {
                    // a non-awaited child
                    log::debug!("[sched] waitpid {} => ECHILD", tid);
                    retry = true;
                    break;
                }
                otherwise => panic!("unknown status: {:?}", otherwise),
            }
        }
    }
    None
}

pub fn sched_wait_event_loop(sched: &mut SchedWait, _state: &mut SystraceState) -> i32 {
    let mut exit_code = 0i32;
    while let Some(task) = sched.next() {
        let tid = task.gettid();
        let run_result = task.run();
        match run_result {
            Ok(RunTask::Exited(_code)) => exit_code = _code,
            Ok(RunTask::Blocked(task1)) => {
                sched.add_blocked(task1);
            }
            Ok(RunTask::Runnable(task1)) => {
                sched.add_and_schedule(task1);
            }
            Ok(RunTask::Forked(parent, child)) => {
                sched.add(child);
                sched.add_and_schedule(parent);
            }
            // task.run could fail when ptrace failed, this *can* happen
            // when we received a PtraceEvent (such as seccomp), then
            // immediately some other thread called `exit_group`; then
            // current task received `SIGKILL` (sent by kernel), because
            // we have no way to trap `SIGKILL`, so at the time when we
            // handle the pending ptrace event, the task could have been
            // killed already. please see more details in:
            // https://github.com/strace/strace/blob/e0f0071b36215de8a592bf41ec007a794b550d45/strace.c#L2569
            //
            // we assume the task is gone if this happens.
            // below is a example of such scenario:
            //
            // === seccomp syscall SYS_pselect6 @4521d3, return: 0 (0)
            // [sched] 27604 PtraceEvent(Pid(27604), SIGTRAP, 7)
            // 27604 seccomp syscall SYS_exit_group@4520ab, hook: None, preloaded: false
            // [sched] 27607 PtraceEvent(Pid(27607), SIGTRAP, 7)
            // [main] 27607 failed to run, assuming killed
            // [sched] 27606 PtraceEvent(Pid(27606), SIGTRAP, 6)
            // [sched] 27608 PtraceEvent(Pid(27608), SIGTRAP, 6)
            // [sched] 27605 PtraceEvent(Pid(27605), SIGTRAP, 6)
            // [sched] 27604 PtraceEvent(Pid(27604), SIGTRAP, 6)
            // (all task exited)
            Err(_) => {
                // task not to be re-queued, assuming exited/killed.
                log::debug!("[sched] {} failed to run, assuming killed", tid);
                if log::log_enabled!(log::Level::Trace) {
                    let file = PathBuf::from("/proc")
                        .join(&format!("{}", tid.as_raw() as i32))
                        .join("stat");
                    if file.exists() {
                        let stat = std::fs::read_to_string(file).unwrap_or(String::new());
                        log::trace!("[sched] task {} refused to be traced while alive, stat: {}", tid, stat);
                        let regs = ptrace::getregs(tid);
                        log::trace!("rsp = {:x?},  rip = {:x?}", regs.map(|r| r.rsp), regs.map(|r| r.rip));
                    }
                }
                // see BUGS in man 2 ptrace
                //
                // A  SIGKILL  signal  may  still cause a PTRACE_EVENT_EXIT stop before
                // actual signal death.  This may be changed in the future; SIGKILL is
                // meant to always immediately kill tasks even under ptrace.
                // Last confirmed on Linux 3.13.
                //
                // Apparently this applies to kernel 4.15 as well
                //
                let status = wait::waitpid(Some(tid), None);
                log::trace!("[sched] {} {:?}", tid, status);
                assert_eq!(status, Ok(WaitStatus::PtraceEvent(tid, signal::SIGTRAP, 6)));
                //
                // NB: we *MUST* let the task to run
                // this is WHY this ptrace BUG matters, after all.
                //
                let _ = ptrace::detach(tid);
            }
        }
    }
    exit_code
}
