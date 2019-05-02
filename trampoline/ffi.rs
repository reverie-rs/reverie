use core::ffi::c_void;

use crate::consts;

static SYSCALL_UNTRACED: u64 = 0x7000_0000;
static SYSCALL_TRACED: u64 = 0x7000_0004;

extern "C" {
    fn _raw_syscall(syscallno: i32,
                    arg0: i64,
                    arg1: i64,
                    arg2: i64,
                    arg3: i64,
                    arg4: i64,
                    arg5: i64,
                    syscall_insn: *mut c_void,
                    sp1: i64,
                    sp2: i64) -> i64;
    fn _syscall_hook_trampoline();
    fn _syscall_hook_trampoline_48_3d_01_f0_ff_ff();
    fn _syscall_hook_trampoline_48_3d_00_f0_ff_ff();
    fn _syscall_hook_trampoline_48_8b_3c_24();
    fn _syscall_hook_trampoline_5a_5e_c3();
    fn _syscall_hook_trampoline_89_c2_f7_da();
    fn _syscall_hook_trampoline_90_90_90();
    fn _syscall_hook_trampoline_ba_01_00_00_00();
    fn _syscall_hook_trampoline_89_c1_31_d2();
    fn _syscall_hook_trampoline_c3_nop();
    fn _syscall_hook_trampoline_85_c0_0f_94_c2();

    #[used]
    fn captured_syscall(no: i32, a0: i64, a1: i64, a2: i64,
                        a3: i64, a4: i64, a5: i64) -> i64;
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline() {
    _syscall_hook_trampoline()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_48_3d_01_f0_ff_ff() {
    _syscall_hook_trampoline_48_3d_01_f0_ff_ff()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_48_3d_00_f0_ff_ff() {
    _syscall_hook_trampoline_48_3d_00_f0_ff_ff()
}
#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_48_8b_3c_24() {
    _syscall_hook_trampoline_48_8b_3c_24()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_5a_5e_c3() {
    _syscall_hook_trampoline_5a_5e_c3()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_89_c2_f7_da() {
    _syscall_hook_trampoline_89_c2_f7_da()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_90_90_90() {
    _syscall_hook_trampoline_90_90_90()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_ba_01_00_00_00() {
    _syscall_hook_trampoline_ba_01_00_00_00()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_89_c1_31_d2() {
    _syscall_hook_trampoline_89_c1_31_d2()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_c3_nop() {
    _syscall_hook_trampoline_c3_nop()
}

#[no_mangle]
unsafe extern "C" fn syscall_hook_trampoline_85_c0_0f_94_c2() {
    _syscall_hook_trampoline_85_c0_0f_94_c2()
}

#[no_mangle]
unsafe extern "C" fn traced_syscall(
    syscallno: i32,
    arg0: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
    arg5: i64) -> i64 {
    _raw_syscall(syscallno, arg0, arg1, arg2, arg3, arg4, arg5,
                 SYSCALL_TRACED as *mut _, 0, 0)
}

#[no_mangle]
unsafe extern "C" fn untraced_syscall(
    syscallno: i32,
    arg0: i64,
    arg1: i64,
    arg2: i64,
    arg3: i64,
    arg4: i64,
    arg5: i64) -> i64 {
    _raw_syscall(syscallno, arg0, arg1, arg2, arg3, arg4, arg5,
                 SYSCALL_UNTRACED as *mut _, 0, 0)
}

#[link_section = ".init_array"]
#[used]
static _NOTIFY_TOOL_DSO_LOADED: extern fn() = {
    extern "C" fn entry_ctor() {
        let ptr = consts::SYSTRACE_LOCAL_SYSCALL_TRAMPOLINE as *mut u64;
        unsafe {
            core::ptr::write(ptr, 1);
        };
    };
    entry_ctor
};
