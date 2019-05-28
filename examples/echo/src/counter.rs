
use crate::local_state::*;

pub enum NoteInfo {
    SyscallEntry,
}

pub fn note_syscall(_p: &mut ProcessState, t: &mut ThreadState, _no: i32, note: NoteInfo) {
    match note {
        NoteInfo::SyscallEntry => {
            t.nr_syscalls += 1;
            t.nr_syscalls_captured += 1;
        }
    }
}
