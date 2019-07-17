#![feature(format_args_nl, slice_internals, ptr_cast)]
#![allow(unused_attributes)]

use tools_helper::*;

#[macro_use]
pub mod macros;
pub mod ffi;
pub mod consts;
pub mod entry;
pub mod dpc;
pub mod show;

pub use counter::{NoteInfo, note_syscall};
pub use local_state::{ProcessState, ThreadState};

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
