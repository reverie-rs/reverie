
use core::ptr::NonNull;
use crate::consts;
use crate::state::SystraceState;

pub fn get_systrace_state() -> &'static mut SystraceState {
    unsafe {
        let ptr = NonNull::new(consts::SYSTRACE_GLOBAL_STATE_ADDR as *mut SystraceState).unwrap();
        let state = &mut *ptr.as_ptr();
        state
    }
}
