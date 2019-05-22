#![feature(lang_items, core_intrinsics, allocator_api, alloc_error_handler, format_args_nl, panic_info_message)]

#![allow(unused_attributes)]

use tools_helper::*;
use syscalls::*;
use log::*;

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
    p: &mut ProcessState,
    t: &mut ThreadState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    note_syscall(p, t, no, NoteInfo::SyscallEntry);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    if ret as u64 >= -4096i64 as u64 {
        warn!("{:?} = {}", syscalls::SyscallNo::from(no), ret);
    } else {
        msg!("{:?} = {:x}", syscalls::SyscallNo::from(no), ret);
    }
    ret
}

#[no_mangle]
pub extern "C" fn hello(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64) {
    println!("hello world! {} {} {} {} {} {}", a, b, c, d, e, f);
}

extern "C" {
    #[no_mangle]
    pub fn syscall_patch_hooks();
}
