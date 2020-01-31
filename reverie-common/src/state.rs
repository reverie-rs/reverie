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

//! reverie global state

use lazy_static;
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
    static ref REVERIE_GLOBAL_STATE: Mutex<ReverieState> =
        Mutex::new(ReverieState::new());
}

/// get reverie global state, protected by mutex
pub fn reverie_global_state() -> &'static Mutex<ReverieState> {
    &REVERIE_GLOBAL_STATE
}
