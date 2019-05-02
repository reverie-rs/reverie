
use nix::sys::mman::{ProtFlags, MapFlags, mmap, munmap};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use nix::fcntl::{SealFlag, fcntl};
use nix::unistd;
use nix::Result;
use std::cell::UnsafeCell;
use std::sync::Once;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::ptr::NonNull;
use std::ffi::CString;
use crate::consts;
use crate::state::SystraceState;

fn init_shared_mmap(path: &str, raw_fd: i32, size: usize) -> Result<*mut SystraceState> {
    let raw_path = CString::new(path).expect("CString::new()");
    let fd0 = memfd_create(&raw_path, MemFdCreateFlag::empty())?;
    unistd::dup2(fd0, raw_fd)?;
    unistd::close(fd0)?;
    unistd::ftruncate(raw_fd, size as i64)?;
    let void_p = unsafe {
        mmap(0 as *mut _, size,
             ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
             MapFlags::MAP_SHARED,
             raw_fd, 0)
    }?;
    let res = void_p as *mut SystraceState;
    Ok(res)
}

fn systrace_state_allocate() -> *mut SystraceState {
    init_shared_mmap(consts::SYSTRACE_GLOBAL_STATE_FILE,
                     consts::SYSTRACE_GLOBAL_STATE_FD,
                     consts::SYSTRACE_GLOBAL_STATE_SIZE as usize)
        .expect("systrace_state_allocate failed")
}

static mut SYSTRACE_STATE: Option<NonNull<SystraceState>> = None;

#[cfg(not(test))]
#[link_section = ".init_array"]
#[used]
static INITIALIZER: extern "C" fn() = rust_state_ctor;

extern "C" fn rust_state_ctor() {
    unsafe {
        let ptr = systrace_state_allocate();
        SYSTRACE_STATE = Some(NonNull::new_unchecked(ptr));
    }
}

pub fn get_systrace_state() -> &'static mut SystraceState {
    unsafe {
        let ptr = SYSTRACE_STATE.expect("SYSTRACE_STATE not initialized");
        let state = &mut *ptr.as_ptr();
        state
    }
}
