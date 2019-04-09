
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use crate::consts;
use crate::state::SystraceState;

pub enum NoteInfo {
    SyscallEntry,
}

pub fn note_syscall(_no: i32, note: NoteInfo) {
    let state = get_systrace_state();
    match note {
        NoteInfo::SyscallEntry => {
            state.nr_syscalls.fetch_add(1, Ordering::SeqCst);
            state.nr_syscalls_captured.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn get_systrace_state() -> &'static mut SystraceState {
    unsafe {
        let ptr = NonNull::new(consts::SYSTRACE_GLOBAL_STATE_ADDR as *mut SystraceState).unwrap();
        let state = &mut *ptr.as_ptr();
        state
    }
}
