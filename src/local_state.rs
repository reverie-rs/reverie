//! systrace local states
//!
//! `ThreadState`: per-thread states, doesn't require locks to update
//!
//! `ProcessState`: per-process states, since there're could be more than one
//! threads in a process, member update requires proper syncing.
//!

use std::vec::Vec;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::ffi::c_void;

/// resources belongs to threads
#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct ThreadState {
    pub raw_thread_id: i32,
    /// number of syscalls (detected)
    pub nr_syscalls: u64,
    /// number of syscalls ptraced
    pub nr_syscalls_ptraced: u64,
    /// number of syscalls get hot patched
    pub nr_syscalls_patched: u64,
    /// number of syscalls captured after hot patching
    pub nr_syscalls_captured: u64,
    /// number of retries for read syscall
    pub nr_read_retries: u64,
    /// number of retries for write syscall
    pub nr_write_retries: u64,
    /// number of getrandom syscall
    pub nr_getrandom: u64,
    /// number of opens of /dev/urandom
    pub nr_urandom_opens: u64,
    /// number of opens of /dev/random
    pub nr_random_opens: u64,
    /// number of time syscall
    /// NB: VDSO could have been disabled during runtime
    pub nr_time_calls: u64,
    /// number of replayed syscalls
    pub nr_total_replays: u64,
    /// number of blocking replays
    pub nr_blocking_replays: u64,
    /// number of injected syscalls
    pub nr_injected_syscalls: u64,
    /// number of intercepted rdtsc instructions
    pub nr_rdtsc_events: u64,
    /// number of intercepted rdtscp instructions
    pub nr_rdtscp_events: u64,
    /// number of clone syscall
    pub nr_cloned: u64,
    /// number of fork syscall
    pub nr_forked: u64,
    /// number of exit syscall/event
    pub nr_exited: u64,
    /// number of process spawned (execve)
    pub nr_process_spawned: u64,
}

impl ThreadState {
    pub fn new() -> Self {
        let state: ThreadState = unsafe {
            core::mem::zeroed()
        };
        state
    }
}

/// Resources belongs to process scope (intead of thread scope)
pub struct ProcessState {
    /// *private*: thread pointer
    pub thread_data: *const u64,
    /// opened file descriptors
    pub open_fds: *const u64,
}

/*
impl ProcessState {
    /// create an empty process state
    pub fn new() -> Self {
        ProcessState {
            thread_data: unsafe {
                core::mem::zeroed()
            },
            open_fds: Vec::new(),
        }
    }

    /// get thread pointer
    ///
    /// `tid` must belongs to current process
    pub fn get_thread_data(&self, tid: i32) -> Option<*const c_void> {
        Some(self.thread_data[tid as usize] as *const c_void)
    }

    /// set thread pointer
    pub fn set_thread_data(&mut self, tid: i32, p: *const c_void) {
        self.thread_data[tid as usize] = p as u64;
    }
}
*/
