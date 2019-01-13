
use alloc::string::String;
use alloc::prelude::*;

extern "C" {
    fn c_strlen(s: *const i8) -> usize;
}

fn strlen(s: *const i8) -> usize {
    unsafe { c_strlen(s) }
}

pub unsafe fn unsafe_pack_cstring(z: *const i8) -> &'static str {
    let p = z as *const u8;
    let n = strlen(z);
    let slice = core::slice::from_raw_parts(p, n);
    core::str::from_utf8_unchecked(slice)
}

pub fn pack_cstring(z: *const i8) -> String {
    let s = unsafe { unsafe_pack_cstring(z) };
    s.to_string()
}
