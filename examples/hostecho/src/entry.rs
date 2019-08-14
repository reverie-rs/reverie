//! echo entrypoint who defines `captured_syscall`
//!
use syscalls::*;

use api::task::*;

use crate::show::*;

#[no_mangle]
pub extern "C" fn captured_syscall(
    g: &mut dyn GlobalState,
    p: &mut dyn ProcessState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    println!("g: {:x?} p: {:x?} no: {}", g as *const _, p as *const _, no);
    let sc = syscalls::SyscallNo::from(no);

    let tid = 2;
    //let tid = syscall!(SYS_gettid).unwrap();

    let info = SyscallInfo::from(tid as i32, sc, a0, a1, a2, a3, a4, a5);
    eprint!("{}", info);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    let info = info.set_retval(ret);
    eprintln!("{}", info);
    ret
}
