#![feature(format_args_nl, slice_internals)]
#![allow(unused_attributes)]

use tools_helper::*;

pub mod ffi;
pub mod consts;
pub mod entry;
pub mod dpc;

pub use counter::{NoteInfo, note_syscall};
pub use local_state::{ProcessState, ThreadState};

use entry::captured_syscall;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
	let _ = logger::init();
    };
    echo_ctor
};
