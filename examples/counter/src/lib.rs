#![feature(format_args_nl)]

#![allow(dead_code)]

use core::sync::atomic::Ordering;

#[allow(unused_imports)]
use std::ffi::CStr;

use tools_helper::*;
use syscalls::*;

mod consts;
mod state;
mod state_tracee;

use crate::state_tracee::*;

#[cfg_attr(target_os = "linux", link_section = ".ctors")]
pub static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
	let _ = logger::init();
    };
    echo_ctor
};


#[no_mangle]
pub extern "C" fn captured_syscall(
    _no: i32,
    _a0: i64,
    _a1: i64,
    _a2: i64,
    _a3: i64,
    _a4: i64,
    _a5: i64,
) -> i64 {
    let state = get_systrace_state();
    state.nr_syscalls.fetch_add(1, Ordering::SeqCst);
    state.nr_syscalls_captured.fetch_add(1, Ordering::SeqCst);
    let ret = unsafe { untraced_syscall(_no, _a0, _a1, _a2, _a3, _a4, _a5) };
    ret
}
