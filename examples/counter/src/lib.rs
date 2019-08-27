#![feature(format_args_nl)]

#![allow(dead_code)]
#![allow(unused_attributes)]

#[allow(unused_imports)]
use std::ffi::CStr;

use reverie_tools_helper::{ syscalls::*, counter::*, common::local_state::ProcessState, logger };

#[cfg_attr(target_os = "linux", link_section = ".ctors")]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
	let _ = logger::init();
    };
    echo_ctor
};

#[no_mangle]
pub extern "C" fn captured_syscall(
    p: &mut ProcessState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    note_syscall(p, no, NoteInfo::SyscallEntry);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    ret
}
