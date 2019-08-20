//! echo entrypoint who defines `captured_syscall`
//!
use syscalls::*;
use tools_helper::*;

use crate::show::*;
use tools_helper::counter::{note_syscall, NoteInfo};
use tools_helper::common::local_state::{ProcessState, ThreadState};

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
    let sc = syscalls::SyscallNo::from(no);
    note_syscall(p, no, NoteInfo::SyscallEntry);

    let tid = syscall!(SYS_gettid).unwrap();

    let info = SyscallInfo::from(tid as i32, sc, a0, a1, a2, a3, a4, a5);
    smsg!("{}", info);
    flush!();
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    smsgln!("{}", SyscallRetInfo::from(tid as i32, sc, info.args_after_syscall(), ret, info.nargs_before == 0));
    ret
}
