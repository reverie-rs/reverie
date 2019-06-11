//! echo entrypoint who defines `captured_syscall`
//!
use syscalls::*;
use tools_helper::*;

use crate::counter::{note_syscall, NoteInfo};
use crate::local_state::{ProcessState, ThreadState};

fn from_cstr<'a>(ptr: i64) -> &'a str {
    let res = unsafe {
        std::ffi::CStr::from_ptr(ptr as *const i8)
            .to_str()
            .unwrap_or_else(|_| "<CStr::ERROR>")
    };
    res
}

fn to_string_atmost(ptr: i64, size: usize) -> String {
    let res = String::from(from_cstr(ptr));
    let len = std::cmp::min(res.len(), size);
    res[..len].to_string()
}

fn show_prot(prot: i32) -> String {
    let mut res: Vec<_> = Vec::new();

    if prot & libc::PROT_READ != 0 {
        res.push("PROT_READ");
    }

    if prot & libc::PROT_WRITE != 0{
        res.push("PROT_WRITE");
    }

    if prot & libc::PROT_EXEC != 0 {
        res.push("PROT_EXEC");
    }

    if res.len() == 0 {
        String::from("PROT_NONE")
    } else {
        res.join("|")
    }
}

#[no_mangle]
pub extern "C" fn captured_syscall(
    p: &mut ProcessState,
    t: &mut ThreadState,
    no: i32,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> i64 {
    note_syscall(p, t, no, NoteInfo::SyscallEntry);
    let ret = unsafe { untraced_syscall(no, a0, a1, a2, a3, a4, a5) };
    if no == SYS_munmap as i32 {
        msg!("munmap({:x?}, {:x?}) = {}", a0, a1, ret);
    } else if no == SYS_mmap as i32 {
        msg!("mmap({:#x?}, {:x?}, {}, {:x?}, {}, {:x?}) = {:x?}",
             a0, a1, show_prot(a2 as i32), a3, a4 as i32, a5, ret);
    } else if no == SYS_mprotect as i32 {
        msg!("mprotect({:x?}, {:x?}) = {}", a0, a1, ret);
    } else if no == SYS_openat as i32 {
        msg!("openat(.., {}, ..) = {}",
             from_cstr(a1),
             ret);
    } else if no == SYS_open as i32 {
        msg!("openat(.., {}, ..) = {}",
             from_cstr(a0),
             ret);
    } else if no == SYS_read as i32 {
        msg!("read({}, {:#x?}, {}) = {}", a0, a1, a2, ret);
    } else if no == SYS_write as i32 {
        msg!("write({}, {:#?}..., {}) = {}", a0, to_string_atmost(a1, 16), a2, ret);
    } else if no == SYS_close as i32 {
        msg!("close({}) = {}", a0, ret);
    } else if no == SYS_stat as i32 {
        msg!("stat({}, {:#x?}) = {}", from_cstr(a0), a1, ret);
    } else if no == SYS_lstat as i32 {
        msg!("lstat({}, {:#x?}) = {}", from_cstr(a0), a1, ret);
    } else if no == SYS_fstat as i32 {
        msg!("fstat({}, {:#x?}) = {}", a0, a1, ret);
    } else if no == SYS_readlink as i32 {
        msg!("readlink({}, {:#x?}, {}) = {}", from_cstr(a0), a1, a2, ret);
    } else if no == SYS_getpid as i32 {
        msg!("getpid() = {}", ret);
    } else if no == SYS_wait4 as i32 {
        msg!("wait4({}, {:#x?}, {:x}, {:#x?}) = {}", a0, a1, a2, a3, ret);
    } else {
        if ret as u64 >= -4096i64 as u64 {
            msg!("{:?} = {}", syscalls::SyscallNo::from(no), ret);
        } else {
            msg!("{:?} = {:x}", syscalls::SyscallNo::from(no), ret);
        }
    }
    ret
}
