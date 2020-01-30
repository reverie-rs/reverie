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
