#![allow(unused_imports)]
#![allow(unused_attributes)]

use reverie_helper::{common::local_state::ProcessState, syscalls::*};

extern "C" {
    fn untraced_syscall(no: i32, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64;
}

#[no_mangle]
pub extern "C" fn captured_syscall(
    _p: &mut ProcessState,
    no: i32,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> i64 {
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    ret
}
