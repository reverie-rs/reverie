#![feature(format_args_nl, slice_internals)]
#![allow(unused_attributes)]

#[macro_use]
pub mod macros;
pub mod consts;
pub mod entry;
pub mod show;
pub mod profiling;
pub mod local_state;
pub mod state;

use entry::captured_syscall;

#[macro_use]
extern crate lazy_static;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
    };
    echo_ctor
};
