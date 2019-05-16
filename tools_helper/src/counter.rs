
use core::sync::atomic::Ordering;
use crate::local_state::LocalState;

pub enum NoteInfo {
    SyscallEntry,
}

pub fn note_syscall(state: &mut LocalState, _no: i32, note: NoteInfo) {
    match note {
        NoteInfo::SyscallEntry => {
            state.nr_syscalls.fetch_add(1, Ordering::SeqCst);
            state.nr_syscalls_captured.fetch_add(1, Ordering::SeqCst);
        }
    }
}
