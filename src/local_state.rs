//! systrace local states
//!
//! `ThreadState`: per-thread states, doesn't require locks to update
//!
//! `ProcessState`: per-process states, since there're could be more than one
//! threads in a process, member update requires proper syncing.
//!

use serde::{Serialize, Deserialize};

#[allow(unused_imports)]
use core::ffi::c_void;

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
#[derive(Debug)]
pub struct ProcessState {
}
