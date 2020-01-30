#![allow(dead_code)]
#![allow(unused_attributes)]

#[allow(unused_imports)]
use std::ffi::CStr;

use reverie_helper::{common::local_state::ProcessState, counter::*, logger};

#[cfg_attr(target_os = "linux", link_section = ".ctors")]
#[used]
static ECHO_DSO_CTORS: extern "C" fn() = {
    extern "C" fn echo_ctor() {
        let _ = logger::init();
    };
    echo_ctor
};

extern "C" {
    fn untraced_syscall(
        no: i32,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    ) -> i64;
}

#[no_mangle]
pub extern "C" fn captured_syscall(
    p: &mut ProcessState,
    no: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> i64 {
    note_syscall(p, no, NoteInfo::SyscallEntry);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    ret
}
