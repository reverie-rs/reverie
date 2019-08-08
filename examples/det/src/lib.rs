#![feature(format_args_nl)]
#![allow(unused_imports)]
#![allow(unused_attributes)]

use tools_helper::*;
use syscalls::*;
use log::*;

#[allow(unused_imports)]
use std::ffi::CStr;

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc;

pub mod ffi;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
	let _ = logger::init();
    };
    echo_ctor
};

pub static LOGICAL_TIME: AtomicUsize = AtomicUsize::new(744847200);

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
    let sc = syscalls::SyscallNo::from(no);
    #[allow(unused_assignments)]
    let mut res = -38; // ENOSYS
    
    match sc {
        SYS_gettimeofday => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            if let Some(mut tp) = unsafe {
                (a0 as *mut libc::timeval).as_mut()
            } {
                tp.tv_sec = tick;
                tp.tv_usec = 0;
            }
            res = 0;
        }
        SYS_clock_gettime => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            if let Some(mut tp) = unsafe {
                (a1 as *mut libc::timespec).as_mut()
            } {
                tp.tv_sec = tick;
                tp.tv_nsec = 0;
            }
            res = 0;
        }
        SYS_time => {
            let tick = LOGICAL_TIME.fetch_add(1, Ordering::SeqCst) as i64;
            if let Some(tp) = unsafe {
                (a0 as *mut libc::time_t).as_mut()
            } {
                *tp = tick;
            }
            res = tick;
        }
        SYS_nanosleep => {
            // don't write arg0 as it is a const pointer
            // use our own instead.
            let t = libc::timespec {
                tv_sec : 0,
                tv_nsec : 0,
            };
            let tp = &t as *const libc::timespec;
            res = unsafe {
                untraced_syscall(no, tp as i64, a1, 0, 0, 0, 0)
            }
        }
        _ => {
            res = unsafe {
                untraced_syscall(no, a0, a1, a2, a3, a4, a5)
            };
        }
    }
    res
}
