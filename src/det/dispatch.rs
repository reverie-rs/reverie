
use crate::io::*;
use crate::syscall::*;
use crate::det::ffi::*;

#[no_mangle]
pub extern "C" fn captured_syscall(_no: i32, _a0: i64, _a1: i64, _a2: i64, _a3: i64, _a4: i64, _a5: i64) -> i64 {
    if _no == OPENAT as i32 {
        // let s = unsafe { unsafe_pack_cstring(_a1 as *const i8) };
        let s = pack_cstring(_a1 as *const i8);
        println!("openat: {}", s);
    }
    if _no == OPEN as i32 {
        let s = unsafe { unsafe_pack_cstring(_a1 as *const i8) };
        println!("open: {}", s);
    }
    syscall::raw::untraced_syscall(_no, _a0, _a1, _a2, _a3, _a4, _a5)
}
