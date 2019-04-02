use syscalls::*;
use tools_helper::logger;
use log::{info};

#[allow(unused_imports)]
use std::ffi::CStr;

#[cfg_attr(target_os = "linux", link_section = ".ctors")]
pub static ECHO_DSO_CTORS: extern fn() = {
    extern fn echo_ctor() {
        let _ = logger::init();
    };
    echo_ctor
};

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
    let ret = unsafe { untraced_syscall(_no, _a0, _a1, _a2, _a3, _a4, _a5) };
    info!("{:?} = {:x?}", syscalls::SyscallNo::from(_no), ret);
    ret
}
