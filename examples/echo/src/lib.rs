#![feature(format_args_nl, slice_internals)]
#![allow(unused_attributes)]

use reverie_tools_helper::{counter, common, logger};

#[macro_use]
pub mod macros;
pub mod entry;
pub mod dpc;
pub mod show;

pub use counter::{NoteInfo, note_syscall};
pub use common::local_state::{ProcessState, ThreadState};

use entry::captured_syscall;

#[macro_use]
extern crate lazy_static;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
	let _ = logger::init();
    };
    echo_ctor
};
