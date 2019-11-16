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
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::sync::{Arc, Mutex};

#[allow(unused_imports)]
use std::collections::{HashMap, HashSet};

use nix::sys::mman;
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

impl Default for ThreadState {
    fn default() -> Self {
        ThreadState {
            process_state: Rc::new(RefCell::new(ProcessState::new())),
        }
    }
}

impl ThreadState {
    pub fn new() -> Self {
        Default::default()
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
#[derive(Debug, Clone)]
pub struct ProcessState {
    pub nr_syscalls: u64,
    pub pstate_store: NonNull<u64>,
    pub pstate_store_size: usize,
    pub sockfd_read: Option<RawFd>,
    pub sockfd_write: Option<RawFd>,

    pub stats: SyscallStats,

    pub fd_status: Arc<Mutex<HashMap<RawFd, DescriptorType>>>,
    pub thread_states: Rc<RefCell<HashMap<Pid, ThreadState>>>,
}

fn get_pstate_store() -> NonNull<u64> {
    let pid = nix::unistd::getpid();
    let offset = 4096 * (pid.as_raw() - 1) as i64;
    let mem = unsafe {
        mman::mmap(
            ptr::null_mut(),
            4096,
            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
            mman::MapFlags::MAP_SHARED,
            consts::REVERIE_GLOBAL_STATE_FD,
            offset,
        )
        .expect("mmap memfd failed")
    };
    NonNull::new(mem as *mut u64).unwrap()
}

impl Default for ProcessState {
    fn default() -> Self {
        ProcessState {
            nr_syscalls: 0,
            pstate_store: get_pstate_store(),
            pstate_store_size: 4096,
            sockfd_read: None,
            sockfd_write: None,
            stats: SyscallStats::new(),
            fd_status: Arc::new(Mutex::new(HashMap::new())),
            thread_states: Rc::new(RefCell::new(HashMap::new())),
        }
    }
}

impl ProcessState {
    pub fn new() -> Self {
        Default::default()
    }
    pub fn forked(&self) -> Self {
        ProcessState {
            nr_syscalls: self.nr_syscalls,
            pstate_store: get_pstate_store(),
            pstate_store_size: 4096,
            sockfd_read: self.sockfd_read,
            sockfd_write: self.sockfd_write,
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
            nr_syscalls: self.nr_syscalls,
            pstate_store: get_pstate_store(),
            pstate_store_size: 4096,
            sockfd_read: self.sockfd_read,
            sockfd_write: self.sockfd_write,
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

#[link_section = ".init_array"]
#[used]
static EARLY_STATE_INIT: extern "C" fn() = {
    extern "C" fn early_state_init() {
        /* nothing to do */
    };
    early_state_init
};
