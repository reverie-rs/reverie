//! echo entrypoint who defines `captured_syscall`
//!
use syscalls::*;
use log::*;

use crate::counter::{note_syscall, NoteInfo};
use crate::local_state::{ProcessState, ThreadState};

use core::ffi::c_void;

#[no_mangle]
pub extern "C" fn captured_syscall(
    p: &mut ProcessState,
    t: &mut ThreadState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    note_syscall(p, t, no, NoteInfo::SyscallEntry);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    if ret as u64 >= -4096i64 as u64 {
        warn!("{:?} = {}", syscalls::SyscallNo::from(no), ret);
    } else {
        msg!("{:?} = {:x}", syscalls::SyscallNo::from(no), ret);
    }
    ret
}

#[no_mangle]
unsafe extern "C" fn set_thread_data(_p: &mut ProcessState, tid: i32, _thread_data: *const c_void) {
    msg!("{} called set_thread_data", tid);
}

