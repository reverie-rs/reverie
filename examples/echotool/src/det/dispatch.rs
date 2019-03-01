use crate::det::ffi::*;
use crate::io::*;
use crate::syscall::*;

use nix::sys::signal::*;
use libc;

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
    let pid = untraced_syscall(SYS_getpid as i32, 0, 0, 0, 0, 0, 0);
    raw_println!("[echotool] {} calling {:?}", pid, SyscallNo::from(_no));
    if _no == SYS_rt_sigaction as i32 {
        let signo = Signal::from_c_int(_a0 as libc::c_int);
        let sigaction = unsafe { std::slice::from_raw_parts(
            _a1 as *mut u64, 4)
        };
        let mask = unsafe { std::slice::from_raw_parts(
            sigaction[3] as *mut u64, 16)
        };
        raw_println!("[echotool] signo: {:?}, sa address {:x} {:x?} {:x?}", signo, _a1, sigaction, mask);
    }
    let ret = untraced_syscall(_no, _a0, _a1, _a2, _a3, _a4, _a5);
    ret
}
