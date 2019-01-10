
#![feature(lang_items, core_intrinsics, format_args_nl, fixed_size_array)]
#![no_std]

#[macro_use]
pub mod det;
pub mod io;
pub mod syscall;

use core::intrinsics;
use core::panic::PanicInfo;

#[lang = "eh_personality"] extern fn rust_eh_personality() {}
#[lang = "panic_impl"] extern fn rust_begin_panic(_info: &PanicInfo) -> ! { unsafe { intrinsics::abort() } }
#[lang = "eh_unwind_resume"] extern fn rust_eh_unwind_resume() {}

#[no_mangle] pub extern fn rust_eh_register_frames () {}
#[no_mangle] pub extern fn rust_eh_unregister_frames () {}
