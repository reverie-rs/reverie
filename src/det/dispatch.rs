
#[macro_use]
use crate::io::*;

#[no_mangle]
pub extern "C" fn captured_syscall(_no: i32, _a0: i64, _a1: i64, _a2: i64, _a3: i64, _a4: i64, _a5: i64) -> i64 {
    -1
}
