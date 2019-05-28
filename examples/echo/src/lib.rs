#![feature(lang_items, core_intrinsics, allocator_api, alloc_error_handler, format_args_nl, panic_info_message, slice_internals)]

#![no_std]

#![allow(unused_attributes)]

extern crate alloc;

use core::intrinsics;
use core::panic::PanicInfo;
use core::alloc::{GlobalAlloc, Layout, Alloc};
use core::ptr::NonNull;

pub mod objalloc;
pub mod allocator;
pub mod ffi;
#[macro_use]
pub mod logger;
pub mod spinlock;
pub mod local_state;
pub mod consts;
pub mod counter;
pub mod entry;

pub use counter::{NoteInfo, note_syscall};
pub use local_state::{ProcessState, ThreadState};

use entry::captured_syscall;

use allocator::MapAlloc;

#[link_section = ".init_array"]
#[used]
static ECHO_DSO_CTORS: extern fn() = {
    extern "C" fn echo_ctor() {
	let _ = logger::init();
    };
    echo_ctor
};

#[lang = "eh_personality"] extern fn rust_eh_personality() {}

#[lang = "panic_impl"] extern fn rust_begin_panic(panic_info: &PanicInfo) -> ! {
    if let Some(loc) = panic_info.location() {
        msg!("panic detected at: {:?}", loc);
    }
    if let Some(msg) = panic_info.message() {
        msg!("{:?}", msg);
    }
    msg!("aborting ..");
    unsafe { intrinsics::abort() }
}

#[lang = "eh_unwind_resume"] extern fn rust_eh_unwind_resume() {}

#[no_mangle] pub extern fn rust_eh_register_frames () {}
#[no_mangle] pub extern fn rust_eh_unregister_frames () {}


struct MyAllocator;

unsafe impl GlobalAlloc for MyAllocator {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        MapAlloc::default().alloc(_layout).unwrap().as_mut()
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        MapAlloc::default().dealloc(NonNull::new(_ptr).unwrap(), _layout);
    }
}

#[global_allocator]
static A: MyAllocator = MyAllocator;

#[alloc_error_handler]
fn alloc_failed(layout: core::alloc::Layout) -> ! {
    panic!("alloc failed: {:?}", layout);
}

#[no_mangle]
extern "C" fn _Unwind_Resume() -> ! {
    unsafe { intrinsics::abort() };
}
