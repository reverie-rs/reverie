const UNTRACED: i64 = 0x70000000 as i64;

extern "C" {
    fn _raw_syscall(
        no: i32,
        a0: i64,
        a1: i64,
        a2: i64,
        a3: i64,
        a4: i64,
        a5: i64,
        ip: i64,
        sp0: i64,
        sp1: i64,
    ) -> i64;
}

pub fn untraced_syscall(no: i32, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64 {
    unsafe { _raw_syscall(no, a0, a1, a2, a3, a4, a5, UNTRACED, 0, 0) }
}
