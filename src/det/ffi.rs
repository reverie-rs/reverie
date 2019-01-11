
use alloc::string::String;
use alloc::prelude::*;

extern "C" {
    fn c_strlen(s: *const i8) -> usize;
}

fn strlen(s: *const i8) -> usize {
    unsafe { c_strlen(s) }
}

pub unsafe fn unsafe_pack_cstring(z: *const i8) -> String {
    let p = z as *const i8;
    let n = strlen(p);
    String::from_raw_parts(p as *mut u8, n, n)
}

pub fn pack_cstring(z: *const i8) -> String {
    let mut res = String::new();
    unsafe { unsafe_pack_cstring(z).clone_into(&mut res); };
    res
}
