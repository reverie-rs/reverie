//! echo entrypoint who defines `captured_syscall`
//!

use crate::show::*;
use reverie_helper::common::local_state::{ProcessState, ThreadState};
use reverie_helper::counter::{note_syscall, NoteInfo};
use reverie_helper::syscalls::*;

use reverie_helper::*;

#[macro_export(smsg)]
macro_rules! smsg {
    ($($arg:tt)*) => ({
        msg!("{}", format_args!($($arg)*))
    })
}

#[macro_export(smsgln)]
macro_rules! smsgln {
    ($($arg:tt)*) => ({
        msgln!("{}", format_args!($($arg)*))
    })
}

extern "C" {
    fn untraced_syscall(no: i32, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64;
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
    let sc = SyscallNo::from(no);
    note_syscall(p, no, NoteInfo::SyscallEntry);

    let tid = unsafe {
        syscall!(SYS_gettid).unwrap()
    };

    let info = SyscallInfo::from(tid as i32, sc, a0, a1, a2, a3, a4, a5);
    smsg!("{}", info);
    flush!();
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    smsgln!(
        "{}",
        SyscallRetInfo::from(
            tid as i32,
            sc,
            info.args_after_syscall(),
            ret,
            info.nargs_before == 0
        )
    );
    ret
}
