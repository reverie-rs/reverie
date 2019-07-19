
use syscalls::*;
use core::fmt;
use core::fmt::Display;
use core::ptr::NonNull;
use core::ffi::c_void as void;
use std::borrow::Cow;

use crate::show::types::*;
use crate::show::fcntl::fmt_fcntl;
use crate::show::ioctl::fmt_ioctl;

macro_rules! ptr {
    ($ty: ty, $v: ident) => {
        NonNull::new($v as *mut $ty)
    }
}

fn arg_out(arg: &SyscallArg) -> bool {
    match arg {
        SyscallArg::PtrOut(Some(_)) => true,
        SyscallArg::SizedCStrOut(_, Some(_)) => true,
        SyscallArg::SizedU8VecOut(_, Some(_)) => true,
        SyscallArg::UnamePtr(Some(_)) => true,
        SyscallArg::Timeval(_) => true,
        SyscallArg::Timespec(_) => true,
        SyscallArg::Timezone(_) => true,
        _ => false,
    }
}

#[allow(unused)]
fn arg_in(arg: &SyscallArg) -> bool {
    !arg_out(arg)
}

impl SyscallInfo {
    pub fn from(tid: i32, no: SyscallNo, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> Self {
        let args = match no {
            SYS_open => {
                if a1 as i32 & libc::O_CREAT == libc::O_CREAT {
                    vec![ SyscallArg::CStr(ptr!(i8, a0)),
                          SyscallArg::FdFlags(a1 as i32),
                          SyscallArg::FdModes(a2 as i32)]
                } else {
                    vec![ SyscallArg::CStr(ptr!(i8, a0)),
                          SyscallArg::FdFlags(a1 as i32)]
                }
            }
            SYS_openat => {
                if a2 as i32 & libc::O_CREAT == libc::O_CREAT {
                    vec![ SyscallArg::DirFd(a0 as i32),
                          SyscallArg::CStr(ptr!(i8, a1)),
                          SyscallArg::FdFlags(a2 as i32),
                          SyscallArg::FdModes(a3 as i32)]
                } else {
                    vec![ SyscallArg::DirFd(a0 as i32),
                          SyscallArg::CStr(ptr!(i8, a1)),
                          SyscallArg::FdFlags(a2 as i32)]
                }
            }
            SYS_mmap => {
                vec![ SyscallArg::Ptr(ptr!(void, a0)),
                      SyscallArg::Hex(a1),
                      SyscallArg::MmapProt(a2 as i32),
                      SyscallArg::MmapFlags(a3 as i32),
                      SyscallArg::Fd(a4 as i32),
                      SyscallArg::Int(a5)]
            }
            SYS_munmap => {
                vec![ SyscallArg::Ptr(ptr!(void, a0)),
                      SyscallArg::Hex(a1)]
            }
            SYS_mprotect => {
                vec![ SyscallArg::Ptr(ptr!(void, a0)),
                      SyscallArg::Hex(a1),
                      SyscallArg::MmapProt(a2 as i32)]
            }
            SYS_madvise => {
                vec![ SyscallArg::Ptr(ptr!(void, a0)),
                      SyscallArg::Hex(a1),
                      SyscallArg::MAdvise(a2 as i32)]
            }
            SYS_close => {
                vec![ SyscallArg::Fd(a0 as i32) ]
            }
            SYS_read => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::SizedCStrOut(a2 as usize, ptr!(i8, a1)),
                      SyscallArg::Int(a2) ]
            }
            SYS_write => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::SizedCStr(a2 as usize, ptr!(i8, a1)),
                      SyscallArg::Int(a2) ]
            }
            SYS_pread64 => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::SizedCStrOut(a2 as usize, ptr!(i8, a1)),
                      SyscallArg::Int(a2),
                      SyscallArg::Int(a3)]
            }
            SYS_pwrite64 => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::SizedCStr(a2 as usize, ptr!(i8, a1)),
                      SyscallArg::Int(a2),
                      SyscallArg::Int(a3)]
            }
            SYS_exit | SYS_exit_group => {
                vec![ SyscallArg::I32(a0 as i32) ]
            }
            SYS_dup => {
                vec![ SyscallArg::Fd(a0 as i32) ]
            }
            SYS_dup2 => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::Fd(a1 as i32)]
            }
            SYS_dup3 => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::Fd(a1 as i32),
                      SyscallArg::FdFlags(a2 as i32)]
            }
            SYS_fstat => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::PtrOut(ptr!(void, a1))]
            }
            SYS_stat | SYS_lstat => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)),
                      SyscallArg::PtrOut(ptr!(void, a1))]
            }
            SYS_readlink => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)),
                      SyscallArg::SizedU8VecOut(a2 as usize, ptr!(u8, a1)),
                      SyscallArg::Int(a2)]
            }
            SYS_seccomp => {
                vec![ SyscallArg::SeccompOp(a0 as u32),
                      SyscallArg::SeccompFlags(a1 as u32),
                      SyscallArg::SeccompFprog(a2 as u64)]
            }
            SYS_getpid | SYS_gettid | SYS_getppid | SYS_getpgid | SYS_getpgrp => {
                Vec::new()
            }
            SYS_getrandom => {
                vec![ SyscallArg::SizedU8VecOut(a1 as usize, ptr!(u8, a0)),
                      SyscallArg::Int(a1),
                      SyscallArg::I32(a2 as i32)]
            }
            SYS_wait4 => {
                vec![ SyscallArg::I32(a0 as i32),
                      SyscallArg::Ptr(ptr!(void, a1)),
                      SyscallArg::WaitpidOptions(a2 as i32),
                      SyscallArg::Ptr(ptr!(void, a3))]
            }
            SYS_set_robust_list => {
                vec![ SyscallArg::Ptr(ptr!(void, a0)),
                      SyscallArg::Int(a1)]
            }
            SYS_get_robust_list => {
                vec![ SyscallArg::I32(a0 as i32),
                      SyscallArg::PtrOut(ptr!(void, a1)),
                      SyscallArg::PtrOut(ptr!(void, a2))]
            }
            SYS_uname => {
                vec![ SyscallArg::UnamePtr(ptr!(void, a0)) ]
            }
            SYS_access => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)),
                      SyscallArg::FdModes(a1 as i32)]
            }
            SYS_getuid | SYS_getgid | SYS_geteuid | SYS_getegid => {
                Vec::new()
            }
            SYS_time => {
                vec! [ SyscallArg::PtrOut(ptr!(void, a0)) ]
            }
            SYS_gettimeofday => {
                vec! [ SyscallArg::Timeval(a0 as u64),
                       SyscallArg::Timezone(a1 as u64) ]
            }
            SYS_settimeofday => {
                vec! [ SyscallArg::Timeval(a0 as u64),
                       SyscallArg::Timezone(a1 as u64) ]
            }
            SYS_clock_gettime => {
                vec! [ SyscallArg::ClockId(a0 as i32),
                       SyscallArg::Timespec(a1 as u64) ]
            }
            SYS_clock_settime => {
                vec! [ SyscallArg::ClockId(a0 as i32),
                       SyscallArg::Timespec(a1 as u64) ]
            }
            SYS_futex => {
                vec![ SyscallArg::Ptr(ptr!(void, a0)),
                      SyscallArg::FutexOp(a1 as i32),
                      SyscallArg::I32(a2 as i32),
                      SyscallArg::Timespec(a3 as u64),
                      SyscallArg::Ptr(ptr!(void, a4)),
                      SyscallArg::I32 (a5 as i32)]
            }
            SYS_rt_sigprocmask => {
                vec![ SyscallArg::RtSigHow(a0 as i32),
                      SyscallArg::RtSigSet(a1 as u64),
                      SyscallArg::RtSigSet(a2 as u64),
                      SyscallArg::I32(a3 as i32)]
            }
            SYS_rt_sigaction => {
                vec![ SyscallArg::RtSignal(a0 as i32),
                      SyscallArg::RtSigaction(a1 as u64),
                      SyscallArg::RtSigaction(a2 as u64),
                      SyscallArg::I32(a3 as i32)]
            }
            SYS_lseek => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::Int(a1),
                      SyscallArg::LseekWhence(a2 as i32)]
            }
            SYS_fcntl => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::Fcntl(a1 as i32, a2 as u64)]
            }
            SYS_ioctl => {
                vec![ SyscallArg::Fd(a0 as i32),
                      SyscallArg::Ioctl(a1 as i32, a2 as u64)]
            }
            SYS_sysinfo => {
                vec![ SyscallArg::Ptr(ptr!(void, a0)) ]
            }
            SYS_execve => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)),
                      SyscallArg::CStrArrayNulTerminated(ptr!(void, a1)),
                      SyscallArg::Envp(ptr!(void, a2))]
            }
            _ => {
                vec![ SyscallArg::Int(a0),
                      SyscallArg::Int(a1),
                      SyscallArg::Int(a2),
                      SyscallArg::Int(a3),
                      SyscallArg::Int(a4),
                      SyscallArg::Int(a5) ]
            }
        };

        let k = args.iter().take_while(|a| {
            !arg_out(a)
        }).count();
        SyscallInfo {
            tid,
            no,
            args,
            nargs_before: k,
        }
    }
    pub fn args_after_syscall(&self) -> Vec<SyscallArg> {
        self.args.iter().skip(self.nargs_before).cloned().collect()
    }
}

impl fmt::Display for SyscallRet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SyscallRet::RetInt(val) => {
                if *val as u64 >= 0xfffffffffffff000 {
                    write!(f, "{} ({})", val, std::io::Error::from_raw_os_error(-val as i32))
                } else {
                    write!(f, "{}", val)
                }
            }
            SyscallRet::RetPtr(val) => write!(f, "{:#x}", val),
            SyscallRet::RetVoid => write!(f, ""),
            SyscallRet::NoReturn => write!(f, "?"),
        }
    }
}

impl fmt::Display for SyscallInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let suffix = if self.args.len() == self.nargs_before {
            ") = "
        } else {
            ""
        };
        write!(f, "[pid {:>4}] {:?}({}{}", self.tid, self.no,
               self.args.iter()
               .take(self.nargs_before)
               .map(|arg|arg.to_string())
               .collect::<Vec<_>>()
               .join(", "),
               suffix)
    }
}

impl SyscallRet {
    pub fn from(no: SyscallNo, retval: i64) -> Self {
        match no {
            SYS_mmap => SyscallRet::RetPtr(retval as u64),
            _        => SyscallRet::RetInt(retval),
        }
    }
}

impl SyscallRetInfo {
    pub fn from(tid: i32, no: SyscallNo, args: Vec<SyscallArg>, retval: i64, first_arg_is_outp: bool) -> Self {
        let ret = match no {
            SYS_mmap => SyscallRet::RetPtr(retval as u64),
            SYS_execve => SyscallRet::NoReturn,
            SYS_exit_group => SyscallRet::NoReturn,
            SYS_exit => SyscallRet::NoReturn,
            _        => SyscallRet::RetInt(retval),
        };
        SyscallRetInfo {
            tid,
            no,
            args,
            retval: ret,
            first_arg_is_outp
        }
    }
}

impl Display for SyscallRetInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let prefix = if self.first_arg_is_outp  {
            ""
        } else {
            ", "
        };
        if self.args.len() != 0 {
            write!(f, "{}{}) = ", prefix,
                   self.args.iter()
                   .map(|arg|arg.to_string())
                   .collect::<Vec<_>>()
                   .join(", "))?;
        }
        write!(f, "{}", self.retval)
    }
}

macro_rules! fmt_nullptr {
    ($f: ident) => {
        write!($f, "NULL")
    }
}

impl fmt::Display for SyscallArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SyscallArg::Int(val) => write!(f, "{}", val),
            SyscallArg::UInt(val) => write!(f, "{}", val),
            SyscallArg::I32(val) => write!(f, "{}", val),
            SyscallArg::Fd(val) => write!(f, "{}", val),
            SyscallArg::Hex(val) => write!(f, "{:#x}", val),
            SyscallArg::Ptr(Some(val)) | SyscallArg::PtrOut(Some(val)) => {
                write!(f, "{:x?}", val)
            }
            SyscallArg::Ptr(None)
                | SyscallArg::PtrOut(None)
                | SyscallArg::CStr(None)
                | SyscallArg::SizedCStr(_, None)
                | SyscallArg::SizedCStrOut(_, None)
                | SyscallArg::SizedU8Vec(_, None)
                | SyscallArg::SizedU8VecOut(_, None) => {
                fmt_nullptr!(f)
            }
            SyscallArg::CStr(Some(ptr)) => {
                fmt_cstr(f, ptr)
            }
            SyscallArg::SizedCStr(size, Some(ptr))
                | SyscallArg::SizedCStrOut(size, Some(ptr)) => {
                fmt_cstr_sized_atmost(f, ptr, size, 32)
            }
            SyscallArg::SizedU8Vec(size, Some(ptr))
                | SyscallArg::SizedU8VecOut(size, Some(ptr)) => {
                fmt_u8vec_atmost(f, ptr, size, 16)
            }
            SyscallArg::FdFlags(flags) => write!(f, "{}", show_fdflags(flags)),
            SyscallArg::FdModes(modes) => write!(f, "0{:o}", modes),
            SyscallArg::DirFd(dirfd) => {
                match dirfd {
                    libc::AT_FDCWD => write!(f, "{}", "AT_FDCWD"),
                    _               => write!(f, "{}", dirfd),
                }
            }
            SyscallArg::MmapProt(prot) => {
                write!(f, "{}", show_mmap_prot(prot))
            }
            SyscallArg::MmapFlags(flags) => {
                write!(f, "{}", show_mmap_flags(flags))
            }
            SyscallArg::SeccompOp(op) => {
                write!(f, "{}", show_seccomp_op(op))
            }
            SyscallArg::SeccompFlags(flags) => {
                write!(f, "{}", show_seccomp_flags(flags))
            }
            SyscallArg::SeccompFprog(prog) => {
                write!(f, "{}", show_seccomp_fprog(prog))
            }
            SyscallArg::WaitpidOptions(options) => {
                write!(f, "{}", show_waitpid_options(options))
            }
            SyscallArg::Timeval(tp) => {
                fmt_timeval(f, tp)
            }

            SyscallArg::Timespec(tp) => {
                fmt_timespec(f, tp)
            }
            SyscallArg::Timezone(tp) => {
                fmt_timezone(f, tp)
            }
            SyscallArg::ClockId(id) => {
                write!(f, "{}", show_clock_id(id))
            }
            SyscallArg::FutexOp(op) => {
                write!(f, "{}", show_futex_op(op))
            }
            SyscallArg::RtSigHow(how) => {
                write!(f, "{}", libc_match_value!(how, SIG_BLOCK)
                       .or_else(|| libc_match_value!(how, SIG_UNBLOCK))
                       .or_else(|| libc_match_value!(how, SIG_SETMASK))
                       .unwrap_or_else(|| ""))
            }
            SyscallArg::RtSigSet(set) => {
                fmt_rt_sigset_p(f, set)
            }
            SyscallArg::RtSignal(sig) => {
                fmt_rt_signal(f, sig)
            }
            SyscallArg::RtSigaction(act) => {
                fmt_rt_sigaction(f, act)
            }
            SyscallArg::LseekWhence(whence) => {
                write!(f, "{}", libc_match_value!(whence, SEEK_SET)
                       .or_else(|| libc_match_value!(whence, SEEK_CUR))
                       .or_else(|| libc_match_value!(whence, SEEK_END))
                       .unwrap_or_else(|| "<whence: BAD_VALUE>"))
            }
            SyscallArg::Fcntl(cmd, arg) => {
                fmt_fcntl(cmd, arg, f)
            }
            SyscallArg::Ioctl(cmd, arg) => {
                fmt_ioctl(cmd, arg, f)
            }
            SyscallArg::UnamePtr(ptr) => {
                fmt_uname_ptr(f, ptr)
            }
            SyscallArg::CStrArrayNulTerminated(ptr) => {
                unsafe {
                    fmt_cstr_null_terminated(f, ptr)
                }
            }
            SyscallArg::Envp(ptr) => {
                unsafe {
                    fmt_envp(f, ptr)
                }
            }
            SyscallArg::MAdvise(advise) => {
                fmt_madvise(f, advise)
            }
        }
    }
}

fn escape<'a>(s: &str) -> String {
    let mut res = String::new();
    s.chars().for_each(|c| {
        match c {
            '\n' => {
                res.push_str("\\n");
            }
            '\t' => {
                res.push_str("\\t");
            }
            _ => {
                res.push(c);
            }
        }
    });
    res
}

fn from_cstr<'a>(ptr: NonNull<i8>) -> Cow<'a, str> {
    unsafe {
        std::ffi::CStr::from_ptr(ptr.as_ptr())
            .to_string_lossy()
    }
}

fn fmt_cstr(f: &mut fmt::Formatter, ptr: NonNull<i8>) -> fmt::Result {
    write!(f, "\"{}\"", escape(&from_cstr(ptr)))
}

fn from_cstr_sized<'a>(ptr: NonNull<i8>, size: usize) -> &'a str {
    unsafe {
        let slice = std::slice::from_raw_parts(ptr.as_ptr() as *const u8, size);
        std::str::from_utf8_unchecked(slice)
    }
}

#[allow(unused)]
fn fmt_cstr_sized(f: &mut fmt::Formatter, ptr: NonNull<i8>, size: usize) -> fmt::Result {
    write!(f, "\"{}\"", escape(from_cstr_sized(ptr, size)))
}

#[allow(unused)]
fn from_cstr_sized_atmost<'a>(ptr: NonNull<i8>, size: usize, max_size: usize) -> &'a str {
    unsafe {
        let slice = std::slice::from_raw_parts(
            ptr.as_ptr() as *const u8,
            std::cmp::min(size, max_size));
        std::str::from_utf8_unchecked(slice)
    }
}

#[allow(unused)]
fn fmt_cstr_sized_atmost(f: &mut fmt::Formatter, ptr: NonNull<i8>, size: usize, max_size: usize) -> fmt::Result {
    write!(f, "\"{}\"", escape(from_cstr_sized_atmost(ptr, size, max_size)))
}

#[allow(unused)]
fn fmt_u8vec(f: &mut fmt::Formatter, ptr: NonNull<u8>, size: usize) ->  fmt::Result {
    let slice = unsafe {
        std::slice::from_raw_parts(ptr.as_ptr(), size)
    };
    write!(f, "{:x?}", slice)
}

fn fmt_u8vec_atmost(f: &mut fmt::Formatter, ptr: NonNull<u8>, size: usize, max_size: usize) ->  fmt::Result {
    let slice = unsafe {
        std::slice::from_raw_parts(ptr.as_ptr(), size)
    };
    if size <= max_size {
        write!(f, "{:x?}", slice.iter().take(max_size).collect::<Vec<_>>())
    } else {
        write!(f, "{:x?}...", slice.iter().take(max_size).collect::<Vec<_>>())
    }
}

fn show_mmap_prot(prot: i32) -> String {
    vec![
        if prot == 0 {
            Some("PROT_NONE")
        } else {
            None
        },
        libc_bit_field!(prot, PROT_READ),
        libc_bit_field!(prot, PROT_WRITE),
        libc_bit_field!(prot, PROT_EXEC),
    ].iter().filter_map(|x|*x).collect::<Vec<_>>().join("|")
}

fn show_mmap_flags(flags: i32) -> String {
    vec![
        libc_bit_field!(flags, MAP_PRIVATE),
        libc_bit_field!(flags, MAP_SHARED),
        libc_bit_field!(flags, MAP_FIXED),
        libc_bit_field!(flags, MAP_ANONYMOUS),
        libc_bit_field!(flags, MAP_STACK),
    ].iter().filter_map(|x|*x).collect::<Vec<_>>().join("|")
}

fn show_fdflags(flags: i32) -> String {
    vec![
        if flags == 0 {
            libc_bit_field!(flags, O_RDONLY)
        } else {
            None
        },
        libc_bit_field!(flags, O_WRONLY),
        libc_bit_field!(flags, O_CREAT),
        libc_bit_field!(flags, O_EXCL),
        libc_bit_field!(flags, O_NOCTTY),
        libc_bit_field!(flags, O_TRUNC),
        libc_bit_field!(flags, O_APPEND),
        libc_bit_field!(flags, O_NONBLOCK),
        libc_bit_field!(flags, O_SYNC),
        libc_bit_field!(flags, O_DIRECT),
        libc_bit_field!(flags, O_NOFOLLOW),
        libc_bit_field!(flags, O_NOATIME),
        libc_bit_field!(flags, O_CLOEXEC),
    ].iter().filter_map(|x|*x).collect::<Vec<_>>().join("|")
}

fn show_seccomp_op(op: u32) -> String {
    vec![
        libc_bit_field!(op, SECCOMP_MODE_STRICT),
        libc_bit_field!(op, SECCOMP_MODE_FILTER),
    ].iter().filter_map(|x|*x).collect::<Vec<_>>().join("|")
}

fn show_seccomp_flags(flags: u32) -> String {
    format!("{:#x}", flags)
}

/*
#[repr(C)]
struct sock_fprog {
    len: u16,
    filters: *const u64,
}
*/
fn show_seccomp_fprog(ptr: u64) -> String {
    let len = unsafe {
        core::ptr::read(ptr as *const u16)
    };
    let fptr = unsafe {
        let pp = (ptr as *const u64).offset(1);
        core::ptr::read(pp as *const u64)
    };
    let v = unsafe {
        core::slice::from_raw_parts(fptr as *const u64, len as usize)
    };
    format!("sock_fprog {{len = {}, filters = {:x?}...}}", len, v.iter().take(4).collect::<Vec<_>>())
}

fn show_waitpid_options(options: i32) -> String {
    if options == 0 {
        String::from("0")
    }  else {
        vec![
            libc_bit_field!(options, WNOHANG),
            libc_bit_field!(options, WUNTRACED),
            libc_bit_field!(options, WCONTINUED),
            libc_bit_field!(options, WNOWAIT),
        ].iter().filter_map(|x|*x).collect::<Vec<_>>().join("|")
    }
}

#[repr(C)]
#[derive(Debug)]
struct timeval {
    tv_sec: u64,
    tv_usec: u64,
}

#[repr(C)]
#[derive(Debug)]
struct timespec {
    tv_sec: u64,
    tv_nsec: u64,
}

fn fmt_timeval(f: &mut fmt::Formatter, tp: u64) -> fmt::Result {
    if tp == 0 {
        write!(f, "NULL")
    } else {
        let tv = unsafe {
            core::ptr::read(tp as *const timeval)
        };
        write!(f, "{{tv.sec: {}, tv.tv_usec: {}}}", tv.tv_sec, tv.tv_usec)
    }
}

fn fmt_timespec(f: &mut fmt::Formatter, tp: u64) -> fmt::Result {
    if tp == 0 {
        write!(f, "NULL")
    } else {
        let tp = unsafe {
            core::ptr::read(tp as *const timespec)
        };
        write!(f, "{{tv.sec: {}, tv.tv_nsec: {}}}", tp.tv_sec, tp.tv_nsec)
    }
}

#[repr(C)]
#[derive(Debug)]
struct timezone {
    tz_minuteswest: i32,
    tz_dsttime: i32,
}

fn fmt_timezone(f: &mut fmt::Formatter, tp: u64) -> fmt::Result {
    if tp == 0 {
        write!(f, "NULL")
    } else {
        let tz = unsafe {
            core::ptr::read(tp as *const timezone)
        };
        write!(f, "{{tz_minuteswest: {}, tz_dsttime: {}}}", tz.tz_minuteswest, tz.tz_dsttime)
    }
}

fn show_clock_id(id: i32) -> String {
    match id {
        libc::CLOCK_REALTIME => String::from("CLOCK_REALTIME"),
        libc::CLOCK_REALTIME_COARSE => String::from("CLOCK_REALTIME_COARSE"),
        libc::CLOCK_MONOTONIC => String::from("CLOCK_MONOTONIC"),
        libc::CLOCK_MONOTONIC_COARSE => String::from("CLOCK_MONOTONIC_COARSE"),
        libc::CLOCK_MONOTONIC_RAW => String::from("CLOCK_MONOTONIC_RAW"),
        libc::CLOCK_BOOTTIME => String::from("CLOCK_BOOTTIME"),
        libc::CLOCK_PROCESS_CPUTIME_ID => String::from("CLOCK_PROCESS_CPUTIME_ID"),
        libc::CLOCK_THREAD_CPUTIME_ID => String::from("CLOCK_THREAD_CPUTIME_ID"),
        _ => format!("BAD_CLOCK_ID ({})", id),
    }
}

fn show_futex_op(op_: i32) -> String {
    let op = op_ & !libc::FUTEX_PRIVATE_FLAG;
    if let Some(found) = libc_match_value!(op, FUTEX_WAIT)
        .or_else(|| libc_match_value!(op, FUTEX_WAKE))
        .or_else(|| libc_match_value!(op, FUTEX_FD))
        .or_else(|| libc_match_value!(op, FUTEX_REQUEUE))
        .or_else(|| libc_match_value!(op, FUTEX_CMP_REQUEUE))
        .or_else(|| libc_match_value!(op, FUTEX_WAKE_OP))
        .or_else(|| libc_match_value!(op, FUTEX_LOCK_PI))
        .or_else(|| libc_match_value!(op, FUTEX_UNLOCK_PI))
        .or_else(|| libc_match_value!(op, FUTEX_TRYLOCK_PI))
        .or_else(|| libc_match_value!(op, FUTEX_WAIT_BITSET))
        .or_else(|| libc_match_value!(op, FUTEX_WAKE_BITSET))
        .or_else(|| libc_match_value!(op, FUTEX_WAIT_REQUEUE_PI))
        .or_else(|| libc_match_value!(op, FUTEX_CMP_REQUEUE_PI))
    {
        if op_ & libc::FUTEX_PRIVATE_FLAG == libc::FUTEX_PRIVATE_FLAG {
            String::from(found) + "_PRIVATE"
        } else {
            String::from(found)
        }
    } else {
        op.to_string()
    }
}

macro_rules! libc_signal_bit {
    ($flags:ident, $bit: ident, $f: ident) => {
        if ($flags as u64) & (1u64.wrapping_shl((libc::$bit-1) as u32)) == (1u64.wrapping_shl((libc::$bit-1) as u32)) {
            Some(stringify!($f))
        } else {
            None
        }
    }
}

struct RtSigset {
    set: u64,
}

impl RtSigset {
    pub fn new(val: u64) -> Self {
        RtSigset {
            set: val
        }
    }
}

impl fmt::Display for RtSigset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let set = self.set;
        let s = [ libc_signal_bit!(set, SIGHUP, HUP),
                  libc_signal_bit!(set, SIGINT, INT),
                  libc_signal_bit!(set, SIGQUIT, QUIT),
                  libc_signal_bit!(set, SIGILL, ILL),
                  libc_signal_bit!(set, SIGTRAP, TRAP),
                  libc_signal_bit!(set, SIGABRT, ABRT),
                  libc_signal_bit!(set, SIGBUS, BUS),
                  libc_signal_bit!(set, SIGFPE, FPE),
                  libc_signal_bit!(set, SIGKILL, ILL),
                  libc_signal_bit!(set, SIGUSR1, USR1),
                  libc_signal_bit!(set, SIGSEGV, SEGV),
                  libc_signal_bit!(set, SIGUSR2, USR2),
                  libc_signal_bit!(set, SIGPIPE, PIPE),
                  libc_signal_bit!(set, SIGALRM, ALRM),
                  libc_signal_bit!(set, SIGTERM, TERM),
                  libc_signal_bit!(set, SIGSTKFLT, STKFLT),
                  libc_signal_bit!(set, SIGCHLD, CHLD),
                  libc_signal_bit!(set, SIGCONT, CONT),
                  libc_signal_bit!(set, SIGSTOP, STOP),
                  libc_signal_bit!(set, SIGTSTP, TSTP),
                  libc_signal_bit!(set, SIGTTIN, TTIN),
                  libc_signal_bit!(set, SIGTTOU, TTOU),
                  libc_signal_bit!(set, SIGURG, URG),
                  libc_signal_bit!(set, SIGXCPU, XCPU),
                  libc_signal_bit!(set, SIGXFSZ, XFSZ),
                  libc_signal_bit!(set, SIGVTALRM, VTALRM),
                  libc_signal_bit!(set, SIGPROF, PROF),
                  libc_signal_bit!(set, SIGWINCH, WINCH),
                  libc_signal_bit!(set, SIGIO, IO),
                  libc_signal_bit!(set, SIGPWR, PWR),
                  libc_signal_bit!(set, SIGSYS, SYS),
        ].iter().filter_map(|x|*x).collect::<Vec<_>>().join("|");
        let rtsigs = set.wrapping_shr(32);
        if rtsigs != 0 {
            write!(f, "[{:#x}|{}]", rtsigs.wrapping_shl(32), s)
        } else {
            write!(f, "[{}]", s)
        }
    }
}

fn fmt_rt_sigset_p(f: &mut fmt::Formatter, ptr: u64) -> fmt::Result {
    if ptr == 0 {
        return write!(f, "NULL");
    }
    let set = unsafe {
        core::ptr::read(ptr as *const u64)
    };
    if set == 0 {
        write!(f, "[]")
    } else {
        write!(f, "{}", RtSigset::new(set))
    }
}

fn fmt_rt_signal(f: &mut fmt::Formatter, sig: i32) -> fmt::Result {
    write!(f, "{}", libc_match_value!(sig, SIGHUP)
           .or_else(|| libc_match_value!(sig, SIGHUP))
           .or_else(|| libc_match_value!(sig, SIGINT))
           .or_else(|| libc_match_value!(sig, SIGQUIT))
           .or_else(|| libc_match_value!(sig, SIGILL))
           .or_else(|| libc_match_value!(sig, SIGTRAP))
           .or_else(|| libc_match_value!(sig, SIGABRT))
           .or_else(|| libc_match_value!(sig, SIGBUS))
           .or_else(|| libc_match_value!(sig, SIGFPE))
           .or_else(|| libc_match_value!(sig, SIGKILL))
           .or_else(|| libc_match_value!(sig, SIGUSR1))
           .or_else(|| libc_match_value!(sig, SIGSEGV))
           .or_else(|| libc_match_value!(sig, SIGUSR2))
           .or_else(|| libc_match_value!(sig, SIGPIPE))
           .or_else(|| libc_match_value!(sig, SIGALRM))
           .or_else(|| libc_match_value!(sig, SIGTERM))
           .or_else(|| libc_match_value!(sig, SIGSTKFLT))
           .or_else(|| libc_match_value!(sig, SIGCHLD))
           .or_else(|| libc_match_value!(sig, SIGCONT))
           .or_else(|| libc_match_value!(sig, SIGSTOP))
           .or_else(|| libc_match_value!(sig, SIGTSTP))
           .or_else(|| libc_match_value!(sig, SIGTTIN))
           .or_else(|| libc_match_value!(sig, SIGTTOU))
           .or_else(|| libc_match_value!(sig, SIGURG))
           .or_else(|| libc_match_value!(sig, SIGXCPU))
           .or_else(|| libc_match_value!(sig, SIGXFSZ))
           .or_else(|| libc_match_value!(sig, SIGVTALRM))
           .or_else(|| libc_match_value!(sig, SIGPROF))
           .or_else(|| libc_match_value!(sig, SIGWINCH))
           .or_else(|| libc_match_value!(sig, SIGIO))
           .or_else(|| libc_match_value!(sig, SIGPWR))
           .or_else(|| libc_match_value!(sig, SIGSYS))
           .map(|s| String::from(s))
           .unwrap_or_else(|| sig.to_string()))
}

#[repr(C)]
struct kernel_sigaction {
    sa_handler: u64,
    sa_flags: u64,
    sa_restorer: u64,
    sa_mask: u64,
}

impl Display for kernel_sigaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{sa_handler={}, sa_mask={}, sa_flags={}, sa_restorer={:#x}}}",
               match self.sa_handler as usize {
                   libc::SIG_DFL => String::from("SIG_DFL"),
                   libc::SIG_IGN => String::from("SIG_IGN"),
                   _ => format!("{:#x}", self.sa_handler),
               },
               self.sa_mask,
               {
                   let flags = self.sa_flags as i32;
                   let mut v: Vec<_> = 
                   [ libc_bit_field!(flags, SA_NOCLDSTOP),
                     libc_bit_field!(flags, SA_NOCLDWAIT),
                     libc_bit_field!(flags, SA_SIGINFO),
                     libc_bit_field!(flags, SA_ONSTACK),
                     libc_bit_field!(flags, SA_RESTART),
                     libc_bit_field!(flags, SA_NODEFER),
                     libc_bit_field!(flags, SA_RESETHAND)].iter().filter_map(|x|*x).collect();
                   if flags & 0x4_000_000 == 0x4_000_000 {
                       v.push("SA_RESTORER");
                   }
                   v.join("|")
               },
               self.sa_restorer)
    }
}

fn fmt_rt_sigaction(f: &mut fmt::Formatter, act_p: u64) -> fmt::Result {
    if act_p == 0 {
        write!(f, "NULL")
    } else {
        let act = unsafe {
            core::ptr::read(act_p as *const kernel_sigaction)
        };
        write!(f, "{}", act)
    }
}

const UTSNAME_LENGTH: usize = 65; /* sys/utsname.h */

fn fmt_uname_ptr(f: &mut fmt::Formatter, ptr__: Option<NonNull<void>>) -> fmt::Result {
    match ptr__ {
        None => write!(f, "NULL"),
        Some(ptr) => {
            let uts = ptr.as_ptr() as *const i8;
            let ptr_2 = UTSNAME_LENGTH + uts as usize;
            let sysname_p = ptr!(i8, uts);
            let nodename_p = ptr!(i8, ptr_2);
            write!(f, "{{sysname={:x?}, nodename={:x?}, ...}}",
                   sysname_p.map(from_cstr).unwrap_or_else(|| Cow::from("NULL")),
                   nodename_p.map(from_cstr).unwrap_or_else(|| Cow::from("NULL")))
        }
    }
}

unsafe fn fmt_cstr_null_terminated(f: &mut fmt::Formatter, ptr__: Option<NonNull<void>>) -> fmt::Result {
    let mut cnt = 0;
    let mut res = Vec::new();
    if let Some(pptr_) = ptr__ {
        while let Some(ptr) = NonNull::new(core::ptr::read(pptr_.as_ptr().cast::<*mut u64>().offset(cnt)) as *mut i8) {
            res.push("\"".to_owned() + &escape(&from_cstr(ptr)) + "\"");
            cnt = 1 + cnt;
        }
        write!(f, "[{}]", res.join(", "))?;
    }
    Ok(())
}

unsafe fn fmt_envp(f: &mut fmt::Formatter, ptr__: Option<NonNull<void>>) -> fmt::Result {
    let mut cnt = 0;
    if let Some(pptr_) = ptr__ {
        while let Some(_ptr) = NonNull::new(core::ptr::read(pptr_.as_ptr().cast::<*mut u64>().offset(cnt)) as *mut i8) {
            cnt = 1 + cnt;
        }
        let unit = if cnt == 1 {
            "var"
        } else {
            "vars"
        };
        write!(f, "{:#x?} /* {} {} */", pptr_, cnt, unit)?;
    }
    Ok(())
}

fn fmt_madvise(f: &mut fmt::Formatter, advise: i32) -> fmt::Result {
    let msg = match advise {
        0  => "MADV_NORMAL",
        1  => "MADV_RANDOM",
        2  => "MADV_SEQUENTIAL",
        3  => "MADV_WILLNEED",
        4  => "MADV_DONTNEED",
        8  => "MADV_FREE",
        9  => "MADV_REMOVE",
        10 => "MADV_DONTFORK",
        11 => "MADV_DOFORK",
        12 => "MADV_MERGEABLE",
        13 => "MADV_UNMERGEABLE",
        14 => "MADV_HUGEPAGE",
        15 => "MADV_NOHUGEPAGE",
        16 => "MADV_DONTDUMP",
        17 => "MADV_DODUMP",
        18 => "MADV_WIPEONFORK",
        19 => "MADV_KEEPONFORK",
        100 => "MADV_HWPOISON",
        _ => "<unknown>",
    };
    write!(f, "{}", msg)
}
