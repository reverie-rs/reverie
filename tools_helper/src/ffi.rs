/// ffi.rs: re-exports trampoline symbols.
///
/// NB: rust (as of today's nightly) doesn't export symbols from .c/.S files,
/// also rust doesn't seem to have visibility controls such as
/// __attribute__((visibility("hidden"))), there's no good way to workaround
/// this, see rust issue ##36342 for more details.
/// As a result, we re-export all the needed C/ASM symbols to make sure our
/// cdylib is built correctly.

use core::ffi::c_void;
use common::consts;
use common::local_state::*;

use syscalls::*;

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
    fn _syscall_hook_trampoline_89_d0_87_07();
    fn _syscall_hook_trampoline_c3_nop();
    fn _syscall_hook_trampoline_85_c0_0f_94_c2();
    fn _remote_syscall_helper();
    fn _remote_funccall_helper();
    fn captured_syscall(
        _p: &mut ProcessState,
        no: i32,
        a0: i64,
        a1: i64,
        a2: i64,
        a3: i64,
        a4: i64,
        a5: i64) -> i64;
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline() {
    _syscall_hook_trampoline()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_48_3d_01_f0_ff_ff() {
    _syscall_hook_trampoline_48_3d_01_f0_ff_ff()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_48_3d_00_f0_ff_ff() {
    _syscall_hook_trampoline_48_3d_00_f0_ff_ff()
}
#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_48_8b_3c_24() {
    _syscall_hook_trampoline_48_8b_3c_24()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_5a_5e_c3() {
    _syscall_hook_trampoline_5a_5e_c3()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_89_c2_f7_da() {
    _syscall_hook_trampoline_89_c2_f7_da()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_90_90_90() {
    _syscall_hook_trampoline_90_90_90()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_ba_01_00_00_00() {
    _syscall_hook_trampoline_ba_01_00_00_00()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_89_c1_31_d2() {
    _syscall_hook_trampoline_89_c1_31_d2()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_89_d0_87_07() {
    _syscall_hook_trampoline_89_d0_87_07()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_c3_nop() {
    _syscall_hook_trampoline_c3_nop()
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook_trampoline_85_c0_0f_94_c2() {
    _syscall_hook_trampoline_85_c0_0f_94_c2()
}

#[no_mangle]
pub unsafe extern "C" fn traced_syscall(
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
pub unsafe extern "C" fn untraced_syscall(
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

#[no_mangle]
pub unsafe extern "C" fn remote_syscall_helper_do_not_call_me() {
    _remote_syscall_helper();
}

#[repr(C)]
pub struct syscall_info {
    no: u64,
    args: [u64; 6],
}

#[no_mangle]
pub unsafe extern "C" fn syscall_hook(info: *const syscall_info) -> i64 {
    if let Some(cell) = &PSTATE {
        let mut pstate = cell.get().as_mut().unwrap();
        let sc = info.as_ref().unwrap();
        let _no = SyscallNo::from(sc.no as i32);
        let _tid = syscall!(SYS_gettid).unwrap() as i32;
        let res = captured_syscall(&mut pstate, sc.no as i32,
                                   sc.args[0] as i64, sc.args[1] as i64,
                                   sc.args[2] as i64, sc.args[3] as i64,
                                   sc.args[4] as i64, sc.args[5] as i64);
        return res;
    }
    return -38;      // ENOSYS
}

#[link_section = ".init_array"]
#[used]
pub static EARLY_TRAMPOLINE_INIT: extern fn() = {
    extern "C" fn trampoline_ctor() {
        let syscall_hook_ptr = consts::REVERIE_LOCAL_SYSCALL_HOOK_ADDR as *mut u64;
        unsafe {
            core::ptr::write(syscall_hook_ptr, syscall_hook as u64);
        }
        let ready = consts::REVERIE_LOCAL_SYSCALL_TRAMPOLINE as *mut u64;
        unsafe {
            core::ptr::write(ready, 1);
        }
        let syscall_helper_ptr = consts::REVERIE_LOCAL_SYSCALL_HELPER as *mut u64;
        unsafe {
            core::ptr::write(syscall_helper_ptr, _remote_syscall_helper as u64);
        }
        let rpc_helper_ptr = consts::REVERIE_LOCAL_RPC_HELPER as *mut u64;
        unsafe {
            core::ptr::write(rpc_helper_ptr, _remote_funccall_helper as u64);
        }
    };
    trampoline_ctor
};
