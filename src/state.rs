//! reverie global state
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

#[repr(C)]
#[derive(Default, Debug)]
/// reverie global state
pub struct ReverieState {
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

impl ReverieState {
    pub fn new() -> Self {
        let z: ReverieState = unsafe {
            std::mem::zeroed()
        };
        z
    }
}

lazy_static! {
    static ref REVERIE_GLOBAL_STATE: Mutex<ReverieState> = Mutex::new(ReverieState::new());
}

/// get reverie global state, protected by mutex
pub fn reverie_global_state() -> &'static Mutex<ReverieState> {
    &REVERIE_GLOBAL_STATE
}
