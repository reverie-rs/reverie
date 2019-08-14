#![feature(format_args_nl, slice_internals)]
#![allow(unused_attributes)]

#[macro_use]
pub mod macros;
pub mod consts;
pub mod entry;
pub mod show;
pub mod state;

use core::ffi::c_void;

#[macro_use]
extern crate lazy_static;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
    };
    echo_ctor
};

const SYSCALL_UNTRACED: i64 = 0x7000_0000i64;

extern "C" {
    fn _raw_syscall(syscallno: i32,
                    arg0: i64,
                    arg1: i64,
                    arg2: i64,
                    arg3: i64,
                    arg4: i64,
                    arg5: i64,
                    syscall_insn: *mut c_void,
                    sp1: i64,
                    sp2: i64) -> i64;
}

#[no_mangle]
unsafe extern "C" fn untraced_syscall(
    syscallno: i32,
    arg0: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
    arg5: i64) -> i64 {
    _raw_syscall(syscallno, arg0, arg1, arg2, arg3, arg4, arg5,
                 SYSCALL_UNTRACED as *mut _, 0, 0)
}
