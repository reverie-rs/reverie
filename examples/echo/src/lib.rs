/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * Copyright (c) 2020-, Facebook, Inc. and its affiliates.
 *
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![allow(unused_attributes)]

use reverie_helper::{common, counter, logger};

#[macro_use]
pub mod macros;
pub mod dpc;
pub mod entry;
pub mod show;

pub use common::local_state::{ProcessState, ThreadState};
pub use counter::{note_syscall, NoteInfo};

#[macro_use]
extern crate lazy_static;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern "C" fn() = {
    extern "C" fn echo_ctor() {
        let _ = logger::init();
    };
    echo_ctor
};
