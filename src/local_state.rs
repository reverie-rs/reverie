/// systrace state/statistics shared between tracer and all tracees
/// NB: the stats are shared globally

use std::sync::atomic::AtomicUsize;

#[repr(C)]
#[derive(Debug)]
pub struct LocalState {
    pub nr_syscalls: AtomicUsize,
    pub nr_syscalls_ptraced: AtomicUsize,
    pub nr_syscalls_patched: AtomicUsize,
    pub nr_syscalls_captured: AtomicUsize,
    pub nr_read_retries: AtomicUsize,
    pub nr_write_retries: AtomicUsize,
    pub nr_getrandom: AtomicUsize,
    pub nr_urandom_opens: AtomicUsize,
    pub nr_random_opens: AtomicUsize,
    pub nr_time_calls: AtomicUsize,
    pub nr_total_replays: AtomicUsize,
    pub nr_blocking_replays: AtomicUsize,
    pub nr_injected_syscalls: AtomicUsize,
    pub nr_rdtsc_events: AtomicUsize,
    pub nr_rdtscp_events: AtomicUsize,
    pub nr_cloned: AtomicUsize,
    pub nr_forked: AtomicUsize,
    pub nr_exited: AtomicUsize,
    pub nr_process_spawns: AtomicUsize,
}

