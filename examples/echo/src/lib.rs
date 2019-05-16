#![feature(format_args_nl)]
#![allow(unused_attributes)]

use tools_helper::*;
use syscalls::*;
use log::*;

#[allow(unused_imports)]
use std::ffi::CStr;

pub mod ffi;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
	let _ = logger::init();
    };
    echo_ctor
};

#[no_mangle]
pub extern "C" fn captured_syscall(
    state: &mut LocalState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    note_syscall(state, no, NoteInfo::SyscallEntry);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    if ret as u64 >= -4096i64 as u64 {
        warn!("{:?} = {}", syscalls::SyscallNo::from(no), ret);
    } else {
        msg!("{:?} = {:x}", syscalls::SyscallNo::from(no), ret);
    }
    ret
}

extern "C" {
    #[no_mangle]
    pub fn syscall_patch_hooks();
}

