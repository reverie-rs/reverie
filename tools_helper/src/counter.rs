//! counter syscall events
use crate::local_state::*;

/// syscall events
pub enum NoteInfo {
    SyscallEntry,
}

/// note a syscall event
pub fn note_syscall(_p: &mut ProcessState, t: &mut ThreadState, _no: i32, note: NoteInfo) {
    match note {
        NoteInfo::SyscallEntry => {
            t.nr_syscalls += 1;
            t.nr_syscalls_captured += 1;
        }
    }
}
