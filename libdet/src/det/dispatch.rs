
use crate::syscall::*;
use crate::det::ffi::*;
use crate::io::*;

#[no_mangle]
pub extern "C" fn captured_syscall(_no: i32, _a0: i64, _a1: i64, _a2: i64, _a3: i64, _a4: i64, _a5: i64) -> i64 {
    if _no == SYS_openat as i32 {
        let s = unsafe { unsafe_pack_cstring(_a1 as *const i8) };
        // raw_println!("openat: {}", s);
    }

    let ret = untraced_syscall(_no, _a0, _a1, _a2, _a3, _a4, _a5);
    if _no == SYS_access as i32 {
        let s = unsafe { unsafe_pack_cstring(_a0 as *const i8) };
        // raw_println!("access: {} returned: {}", s, ret);
    }
    // raw_println!("captured_syscall: {:?}, returned: {:x}", SyscallNo::from(_no), ret);
    ret
}
