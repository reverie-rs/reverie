
#![feature(lang_items, core_intrinsics)]
#![no_std]

use core::intrinsics;
use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn captured_syscall(no: i32, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    panic!("tests!");
    0
}

#[no_mangle]
pub extern "C" fn libdet_init()
{
    panic!("test");
}

#[lang = "eh_personality"] extern fn rust_eh_personality() {}
#[lang = "panic_impl"] extern fn rust_begin_panic(_info: &PanicInfo) -> ! { unsafe { intrinsics::abort() } }
#[lang = "eh_unwind_resume"] extern fn rust_eh_unwind_resume() {}

#[no_mangle] pub extern fn rust_eh_register_frames () {}
#[no_mangle] pub extern fn rust_eh_unregister_frames () {}
