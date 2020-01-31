/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

//! tracee profiling data

use std::sync::atomic::AtomicUsize;

/// syscall statistic information
#[derive(Debug, Default)]
pub struct SyscallStats {
    /// number of syscalls traced
    pub nr_syscalls: AtomicUsize,
    /// number of syscalls ptraced (slow)
    pub nr_syscalls_ptraced: AtomicUsize,
    /// number of syscall sites patched (slow)
    pub nr_syscalls_patched: AtomicUsize,
    /// number of syscall routed to `captured_syscall`
    pub nr_syscalls_captured: AtomicUsize,
    /// number of read retris
    pub nr_read_retries: AtomicUsize,
    /// number of write retries
    pub nr_write_retries: AtomicUsize,
    /// number of get_random syscalls
    pub nr_getrandom: AtomicUsize,
    /// number of opens to /dev/urandom
    pub nr_urandom_opens: AtomicUsize,
    /// number of opens to /dev/random
    pub nr_random_opens: AtomicUsize,
    /// number of syscalls to VDSO time functions
    pub nr_time_calls: AtomicUsize,
    /// number of syscall replays
    pub nr_total_replays: AtomicUsize,
    /// number of blocking replays
    pub nr_blocking_replays: AtomicUsize,
    /// number of injected syscalls
    pub nr_injected_syscalls: AtomicUsize,
    /// number of rdtsc intercepted (slow)
    pub nr_rdtsc_events: AtomicUsize,
    /// number of rdtscp intercepted (slow)
    pub nr_rdtscp_events: AtomicUsize,
    /// number of tasks cloned
    pub nr_cloned: AtomicUsize,
    /// number of tasks forked
    pub nr_forked: AtomicUsize,
    /// number of trap exits
    /// note, due to untrappable signals like `SIGKILL`
    /// this could be imprecise
    pub nr_exited: AtomicUsize,
    /// number of processes spawned via `execve*` syscall
    pub nr_process_spawns: AtomicUsize,
}

impl SyscallStats {
    pub fn new() -> Self {
        let z: SyscallStats = unsafe { std::mem::zeroed() };
        z
    }
}

impl Clone for SyscallStats {
    fn clone(&self) -> Self {
        let mut z: SyscallStats = unsafe { std::mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                self,
                &mut z,
                std::mem::size_of::<SyscallStats>(),
            )
        }
        z
    }
}
