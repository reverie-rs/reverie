
use alloc::string::String;
use alloc::prelude::*;

extern "C" {
    fn c_strlen(s: *const i8) -> usize;
}

fn strlen(s: *const i8) -> usize {
    unsafe { c_strlen(s) }
}

pub fn unsafe_from_ptr(z: *const i8) -> String {
    let p = z as *const i8;
    let n = strlen(p);
    unsafe {
        String::from_raw_parts(p as *mut u8, n, n)
    }
}

pub fn from_ptr(z: *const i8) -> String {
    let mut res = String::new();
    unsafe_from_ptr(z).clone_into(&mut res);
    res
}
