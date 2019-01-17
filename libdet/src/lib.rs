
#![feature(lang_items, core_intrinsics, alloc, allocator_api, alloc_error_handler, format_args_nl, fixed_size_array, toowned_clone_into, panic_info_message)]
#![no_std]
#[macro_use]

pub mod det;
pub mod io;
pub mod syscall;

extern crate alloc;

use core::intrinsics;
use core::panic::PanicInfo;

use core::alloc::{Alloc, GlobalAlloc, Layout};
use core::ptr::*;

use crate::det::allocator::{MapAllocBuilder, MapAlloc};

#[lang = "eh_personality"] extern fn rust_eh_personality() {}

#[lang = "panic_impl"] extern fn rust_begin_panic(panic_info: &PanicInfo) -> ! {
    if let Some(loc) = panic_info.location() {
        println!("panic detected at: {:?}", loc);
    }
    if let Some(msg) = panic_info.message() {
        println!("{:?}", msg);
    }
    println!("aborting ..");
    unsafe { intrinsics::abort() }
}

#[lang = "eh_unwind_resume"] extern fn rust_eh_unwind_resume() {}

#[no_mangle] pub extern fn rust_eh_register_frames () {}
#[no_mangle] pub extern fn rust_eh_unregister_frames () {}

pub struct MyAllocator;

unsafe impl GlobalAlloc for MyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut alloc = MapAllocBuilder::default().build();
        match <MapAlloc as Alloc>::alloc(&mut alloc, layout) {
            Ok(ptr) => ptr.as_ptr(),
            Err(_)  =>  panic!("MapAlloc::alloc failed for {:?}", layout),
        }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(new_ptr) = NonNull::new(ptr) {
            let mut alloc = MapAllocBuilder::default().build();
            <MapAlloc as Alloc>::dealloc(&mut alloc, new_ptr, layout);
        }
    }
}

#[global_allocator]
pub static A: MyAllocator = MyAllocator;

#[alloc_error_handler]
fn alloc_failed(layout: core::alloc::Layout) -> ! {
    panic!("alloc failed: {:?}", layout);
}

#[no_mangle]
extern "C" fn _Unwind_Resume() -> ! {
    unsafe { intrinsics::abort() };
}
