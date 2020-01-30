#![allow(unused_imports)]
#![allow(unused_attributes)]

use log::*;
use reverie_helper::{
    common::local_state::ProcessState, counter::*, logger, syscalls::*,
};

#[allow(unused_imports)]
use std::ffi::CStr;

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use libc;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern "C" fn() = {
    extern "C" fn echo_ctor() {
        let _ = logger::init();
    };
    echo_ctor
};

pub static LOGICAL_TIME: AtomicUsize = AtomicUsize::new(744847200);

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
    let sc = SyscallNo::from(no);
    #[allow(unused_assignments)]
    let mut res = -38; // ENOSYS

    match sc {
        SYS_gettimeofday => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            if let Some(mut tp) = unsafe { (a0 as *mut libc::timeval).as_mut() }
            {
                tp.tv_sec = tick;
                tp.tv_usec = 0;
            }
            res = 0;
        }
        SYS_clock_gettime => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            if let Some(mut tp) =
                unsafe { (a1 as *mut libc::timespec).as_mut() }
            {
                tp.tv_sec = tick;
                tp.tv_nsec = 0;
            }
            res = 0;
        }
        SYS_time => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            if let Some(tp) = unsafe { (a0 as *mut libc::time_t).as_mut() } {
                *tp = tick;
            }
            res = tick;
        }
        SYS_nanosleep => {
            // don't write arg0 as it is a const pointer
            // use our own instead.
            let t = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let tp = &t as *const libc::timespec;
            res = unsafe { untraced_syscall(no, tp as u64, a1, 0, 0, 0, 0) }
        }
        _ => {
            res = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
        }
    }
    res
}
