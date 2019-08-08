//! reverie local states
//!
//! `ThreadState`: per-thread states, doesn't require locks to update
//!
//! `ProcessState`: per-process states, since there're could be more than one
//! threads in a process, member update requires proper syncing.
//!

// use serde::{Serialize, Deserialize};

#[allow(unused_imports)]
use core::ffi::c_void;

use std::cell::{RefCell, UnsafeCell};
use std::os::unix::io::RawFd;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[allow(unused_imports)]
use std::collections::{HashMap, HashSet};

use nix::unistd::Pid;

use crate::consts;
use crate::profiling::*;

/// resources belongs to threads
#[repr(C)]
#[derive(Debug)]
//#[derive(Serialize, Deserialize, Default, Debug)]
pub struct ThreadState {
    pub process_state: Rc<RefCell<ProcessState>>,
}

impl ThreadState {
    pub fn new() -> Self {
        ThreadState {
            process_state: Rc::new(RefCell::new(ProcessState::new())),
        }
    }

    pub fn forked(&self) -> Self {
        ThreadState {
            process_state: Rc::new(RefCell::new(ProcessState::new())),
        }
    }

    pub fn cloned(&self) -> Self {
        ThreadState {
            process_state: self.process_state.clone(),
        }
    }
}

pub static mut PSTATE: Option<UnsafeCell<ProcessState>> = None;

#[derive(Debug, Clone, Copy)]
pub enum DescriptorScope {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy)]
pub enum DescriptorBlockingFlag {
    Blocking,
    NonBlocking,
}

#[derive(Debug, Clone, Copy)]
pub struct DescriptorType {
    pub scope: DescriptorScope,
    pub blocking: DescriptorBlockingFlag,
}

/// Resources belongs to process scope (intead of thread scope)
#[derive(Debug, Default, Clone)]
pub struct ProcessState {
    pub sockfd_read: Option<RawFd>,
    pub sockfd_write: Option<RawFd>,

    pub stats: SyscallStats,

    pub fd_status: Arc<Mutex<HashMap<RawFd, DescriptorType>>>,
    pub thread_states: Rc<RefCell<HashMap<Pid, ThreadState>>>,
}

impl ProcessState {
    pub fn new() -> Self {
        ProcessState {
            sockfd_read: None,
            sockfd_write: None,
            stats: SyscallStats::new(),
            fd_status: Arc::new(Mutex::new(HashMap::new())),
            thread_states: Rc::new(RefCell::new(HashMap::new())),
        }
    }
    pub fn forked(&self) -> Self {
        ProcessState {
            sockfd_read: self.sockfd_read.clone(),
            sockfd_write: self.sockfd_write.clone(),
            fd_status: {
                let fd_status_copied: HashMap<RawFd, DescriptorType> =
                    self.fd_status.lock().unwrap().clone();
                Arc::new(Mutex::new(fd_status_copied))
            },
            stats: SyscallStats::new(),
            thread_states: { Rc::new(RefCell::new(HashMap::new())) },
        }
    }
    pub fn cloned(&self) -> Self {
        ProcessState {
            sockfd_read: self.sockfd_read.clone(),
            sockfd_write: self.sockfd_write.clone(),
            stats: self.stats.clone(),
            fd_status: self.fd_status.clone(),
            thread_states: self.thread_states.clone(),
        }
    }
}

#[derive(Debug)]
pub struct GlobalState {
    pub global_time: u64,
    pub thread_states: HashMap<Pid, &'static ThreadState>,
}

#[no_mangle]
unsafe extern "C" fn init_process_state() {
    let new_state = ProcessState::new();
    let pstate = UnsafeCell::new(new_state);
    PSTATE = Some(pstate);
}
