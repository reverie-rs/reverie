//! reverie global state

use std::sync::Mutex;

use crate::profiling::*;

#[repr(C)]
#[derive(Default, Debug)]
/// reverie global state
pub struct ReverieState {
    pub stats: SyscallStats,
}

impl ReverieState {
    pub fn new() -> Self {
        ReverieState {
            stats: SyscallStats::new(),
        }
    }
}

lazy_static! {
    static ref REVERIE_GLOBAL_STATE: Mutex<ReverieState> = Mutex::new(ReverieState::new());
}

/// get reverie global state, protected by mutex
pub fn reverie_global_state() -> &'static Mutex<ReverieState> {
    &REVERIE_GLOBAL_STATE
}
