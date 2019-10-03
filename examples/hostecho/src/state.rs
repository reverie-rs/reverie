//! tool states
use std::collections::HashMap;
use std::io::{stderr, Result};
use std::os::unix::io::RawFd;

use reverie_api::remote::*;
use reverie_api::task::*;
use syscalls::*;

use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::wait;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;

pub struct EchoGlobalState {
    pub logger: std::io::Stderr,
    pub tasks: HashMap<Pid, EchoState>,
}

impl EchoGlobalState {
    pub fn new() -> Self {
        EchoGlobalState {
            logger: stderr(),
            tasks: HashMap::new(),
        }
    }
}

impl GlobalState for EchoGlobalState {
    fn new() -> Self {
        EchoGlobalState::new()
    }
}

//impl TaskEventHandler for EchoGlobalState {
impl EchoGlobalState {
    pub fn task_exec(&mut self, tsk: EchoState) -> Result<()> {
        self.tasks.insert(tsk.gettid(), tsk);
        Ok(())
    }
    pub fn task_fork(&mut self, tsk: EchoState) -> Result<()> {
        self.tasks.insert(tsk.gettid(), tsk);
        Ok(())
    }
    pub fn task_clone(&mut self, tsk: EchoState) -> Result<()> {
        self.tasks.insert(tsk.gettid(), tsk);
        Ok(())
    }
    pub fn task_exit(&mut self, tsk: EchoState) -> Result<()> {
        self.tasks.remove(&tsk.gettid());
        Ok(())
    }
}

pub struct EchoState {
    pub tid: Pid,
    pub pid: Pid,
    pub ppid: Pid,
    pub pgid: Pid,

    pub sockfd: RawFd,

    pub signal_to_deliver: Option<signal::Signal>,
}

#[no_mangle]
unsafe extern "C" fn init_global_state() -> Box<EchoGlobalState> {
    Box::new(EchoGlobalState::new())
}

impl EchoState {
    pub fn new(pid: Pid) -> Self {
        EchoState {
            sockfd: 0,
            tid: pid,
            pid,
            ppid: pid,
            pgid: pid,
            signal_to_deliver: None,
        }
    }
}

impl ProcessState for EchoState {
    fn new(pid: Pid) -> Self {
        EchoState::new(pid)
    }
}

impl Task for EchoState {
    fn new(pid: Pid) -> Self {
        EchoState::new(pid)
    }
    fn cloned(&self, child: Pid) -> Self {
        EchoState {
            sockfd: self.sockfd,
            tid: child,
            pid: self.pid,
            ppid: self.ppid,
            pgid: self.pgid,
            signal_to_deliver: None,
        }
    }
    fn forked(&self, child: Pid) -> Self {
        EchoState {
            sockfd: self.sockfd,
            tid: child,
            pid: self.pid,
            ppid: self.ppid,
            pgid: self.pgid,
            signal_to_deliver: None,
        }
    }
    fn exited(&self, code: i32) -> Option<i32> {
        Some(code)
    }
    fn gettid(&self) -> Pid {
        self.tid
    }
    fn getpid(&self) -> Pid {
        self.pid
    }
    fn getppid(&self) -> Pid {
        self.ppid
    }
    fn getpgid(&self) -> Pid {
        self.pgid
    }
}

#[no_mangle]
unsafe extern "C" fn init_process_state(pid: Pid) -> Box<EchoState> {
    Box::new(EchoState::new(pid))
}

impl Injector for EchoState {
    fn resolve_symbol_address(&self, _: &str) -> Option<FunAddr> {
        None
    }
    fn inject_funcall(&self, func: FunAddr, _args: &SyscallArgs) {
        unimplemented!("inject_funccall: {:x?}", func);
    }
    fn inject_syscall(&self, no: SyscallNo, args: SyscallArgs) -> i64 {
        reverie_api::remote::untraced_syscall(
            self, no, args.arg0, args.arg1, args.arg2, args.arg3, args.arg4,
            args.arg5,
        )
    }
}
