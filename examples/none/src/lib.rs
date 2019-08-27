#![allow(unused_imports)]
#![allow(unused_attributes)]

use reverie_helper::{ syscalls::*, common::local_state::ProcessState };

#[no_mangle]
pub extern "C" fn captured_syscall(
    _p: &mut ProcessState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    ret
}
