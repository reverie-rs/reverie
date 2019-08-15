//! pretty print syscalls
use syscalls::*;
use core::fmt;
use core::fmt::Display;
use core::ptr::NonNull;
use std::io::Result;
use std::ffi::{CStr, CString};

use api::remote::{Remoteable, GuestMemoryAccess};
use api::remote::*;
use itertools::Itertools;
use nix::unistd::Pid;

use crate::show::types::*;
use crate::show::fcntl::fmt_fcntl;
use crate::show::ioctl::fmt_ioctl;

macro_rules! ptr {
    ($ty: ty, $v: ident) => {
        Remoteable::remote($v as *mut $ty)
    }
}

fn arg_out(arg: &SyscallArg) -> bool {
    match arg {
        SyscallArg::PtrOut(_) => true,
        SyscallArg::SizedCStrOut(_, _) => true,
        SyscallArg::SizedU8VecOut(_, _) => true,
        SyscallArg::UnamePtr(_) => true,
        SyscallArg::TimevalPtr(_) => true,
        SyscallArg::TimespecPtr(_) => true,
        SyscallArg::TimezonePtr(_) => true,
        SyscallArg::DirentPtr(_) => true,
        SyscallArg::Dirent64Ptr(_) => true,
        _ => false,
    }
}

#[allow(unused)]
fn arg_in(arg: &SyscallArg) -> bool {
    !arg_out(arg)
}

impl SyscallInfo {
    pub fn from(tid: Pid, no: SyscallNo, args: &SyscallArgs) -> Self {
        let (a0, a1, a2, a3, a4, a5) = (args.arg0 as i64,
                                        args.arg1 as i64,
                                        args.arg2 as i64,
                                        args.arg3 as i64,
                                        args.arg4 as i64,
                                        args.arg5 as i64);
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
            SYS_unlink => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)) ]
            }
            SYS_unlinkat => {
                vec![ SyscallArg::DirFd(a0 as i32),
                      SyscallArg::CStr(ptr!(i8, a1)),
                      SyscallArg::DirFd(a2 as i32) ]
            }
            SYS_getdents => {
                vec![ SyscallArg::DirFd(a0 as i32),
                      SyscallArg::DirentPtr(ptr!(u64, a1)),
                      SyscallArg::Int(a2 as i64) ]
            }
            SYS_getdents64 => {
                vec![ SyscallArg::DirFd(a0 as i32),
                      SyscallArg::Dirent64Ptr(ptr!(u64, a1)),
                      SyscallArg::Int(a2 as i64) ]
            }
            SYS_brk => {
                vec![ SyscallArg::Ptr(ptr!(u64, a0)) ]
            }
            SYS_mmap => {
                vec![ SyscallArg::Ptr(ptr!(u64, a0)),
                      SyscallArg::Hex(a1),
                      SyscallArg::MmapProt(a2 as i32),
                      SyscallArg::MmapFlags(a3 as i32),
                      SyscallArg::Fd(a4 as i32),
                      SyscallArg::Int(a5)]
            }
            SYS_munmap => {
                vec![ SyscallArg::Ptr(ptr!(u64, a0)),
                      SyscallArg::Hex(a1)]
            }
            SYS_mprotect => {
                vec![ SyscallArg::Ptr(ptr!(u64, a0)),
                      SyscallArg::Hex(a1),
                      SyscallArg::MmapProt(a2 as i32)]
            }
            SYS_madvise => {
                vec![ SyscallArg::Ptr(ptr!(u64, a0)),
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
                      SyscallArg::PtrOut(ptr!(u64, a1))]
            }
            SYS_stat | SYS_lstat => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)),
                      SyscallArg::PtrOut(ptr!(u64, a1))]
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
                      SyscallArg::Ptr(ptr!(u64, a1)),
                      SyscallArg::WaitpidOptions(a2 as i32),
                      SyscallArg::Ptr(ptr!(u64, a3))]
            }
            SYS_set_robust_list => {
                vec![ SyscallArg::Ptr(ptr!(u64, a0)),
                      SyscallArg::Int(a1)]
            }
            SYS_get_robust_list => {
                vec![ SyscallArg::I32(a0 as i32),
                      SyscallArg::PtrOut(ptr!(u64, a1)),
                      SyscallArg::PtrOut(ptr!(u64, a2))]
            }
            SYS_uname => {
                vec![ SyscallArg::UnamePtr(ptr!(u64, a0)) ]
            }
            SYS_access => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)),
                      SyscallArg::FdModes(a1 as i32)]
            }
            SYS_getuid | SYS_getgid | SYS_geteuid | SYS_getegid => {
                Vec::new()
            }
            SYS_time => {
                vec! [ SyscallArg::PtrOut(ptr!(u64, a0)) ]
            }
            SYS_gettimeofday => {
                vec! [ SyscallArg::TimevalPtr(ptr!(u64, a0)),
                       SyscallArg::TimezonePtr(ptr!(u64, a1)) ]
            }
            SYS_settimeofday => {
                vec! [ SyscallArg::TimevalPtr(ptr!(u64, a0)),
                       SyscallArg::TimezonePtr(ptr!(u64, a1)) ]
            }
            SYS_clock_gettime => {
                vec! [ SyscallArg::ClockId(a0 as i32),
                       SyscallArg::TimespecPtr(ptr!(u64, a1)) ]
            }
            SYS_clock_settime => {
                vec! [ SyscallArg::ClockId(a0 as i32),
                       SyscallArg::TimespecPtr(ptr!(u64, a1)) ]
            }
            SYS_futex => {
                vec![ SyscallArg::Ptr(ptr!(u64, a0)),
                      SyscallArg::FutexOp(a1 as i32),
                      SyscallArg::I32(a2 as i32),
                      SyscallArg::TimespecPtr(ptr!(u64, a3)),
                      SyscallArg::Ptr(ptr!(u64, a4)),
                      SyscallArg::I32 (a5 as i32)]
            }
            SYS_nanosleep => {
                vec! [ SyscallArg::TimespecPtr(ptr!(u64, a0)),
                       SyscallArg::TimespecPtr(ptr!(u64, a1)) ]
            }
            SYS_clock_nanosleep => {
                vec! [ SyscallArg::TimespecPtr(ptr!(u64, a0)),
                       SyscallArg::TimespecPtr(ptr!(u64, a1)) ]
            }
            SYS_rt_sigprocmask => {
                vec![ SyscallArg::RtSigHow(a0 as i32),
                      SyscallArg::RtSigSetPtr(ptr!(u64, a1)),
                      SyscallArg::RtSigSetPtr(ptr!(u64, a2)),
                      SyscallArg::I32(a3 as i32)]
            }
            SYS_rt_sigaction => {
                vec![ SyscallArg::RtSignal(a0 as i32),
                      SyscallArg::RtSigactionPtr(ptr!(u64, a1)),
                      SyscallArg::RtSigactionPtr(ptr!(u64, a2)),
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
                vec![ SyscallArg::Ptr(ptr!(u64, a0)) ]
            }
            SYS_execve => {
                vec![ SyscallArg::CStr(ptr!(i8, a0)),
                      SyscallArg::CStrArrayNulTerminated(ptr!(i8, a1)),
                      SyscallArg::Envp(ptr!(u64, a2))]
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
            pid: tid,
            no,
            args: args.iter().map(|a| InferiorSyscallArg::from(tid, *a)).collect(),
            nargs_before: k,
            retval: None,
        }
    }
    pub fn args_after_syscall(&self) -> Vec<InferiorSyscallArg> {
        self.args.iter().skip(self.nargs_before).cloned().collect()
    }
    pub fn set_retval(self, retval: i64) -> Self {
        let ret = match self.no {
            SYS_mmap => SyscallRet::RetPtr(retval as u64),
            SYS_brk => SyscallRet::RetPtr(retval as u64),
            SYS_execve => SyscallRet::NoReturn,
            SYS_exit_group => SyscallRet::NoReturn,
            SYS_exit => SyscallRet::NoReturn,
            _        => SyscallRet::RetInt(retval),
        };
        SyscallInfo {
            pid: self.pid,
            no: self.no,
            args: self.args.iter().cloned().map(|x| InferiorSyscallArg {
                pid: x.pid,
                arg: x.arg,
                retval: Some(retval)
            }).collect(),
            nargs_before: self.nargs_before,
            retval: Some(ret),
        }
    }
}

impl Display for SyscallRet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SyscallRet::RetInt(val) => {
                if *val as u64 >= 0xfffffffffffff000 {
                    write!(f, "{} ({})", -1, std::io::Error::from_raw_os_error(-val as i32))
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

impl GuestMemoryAccess for InferiorSyscallArg {
    fn peek_bytes(&self, addr: Remoteable<u8>, size: usize) -> Result<Vec<u8>> {
        match addr {
            Remoteable::Local(lptr) => {
                let mut dest = Vec::with_capacity(size);
                unsafe {
                    std::ptr::copy_nonoverlapping(lptr.as_ptr() as *const u8,
                                                  dest.as_mut_ptr(),
                                                  size)
                };
                Ok(dest)
            }
            Remoteable::Remote(rptr) => {
                ptrace_peek_bytes(self.pid, rptr, size)
            }
        }
    }
    fn poke_bytes(&self, addr: Remoteable<u8>, bytes: &[u8]) -> Result<()> {
        match addr {
            Remoteable::Local(lptr) => {
                unsafe {
                    std::ptr::copy_nonoverlapping
                        (bytes.as_ptr(), lptr.as_ptr(), bytes.len())
                };
                Ok(())
            }
            Remoteable::Remote(rptr) => {
                ptrace_poke_bytes(self.pid, rptr, bytes)
            }
        }
    }
}

impl InferiorSyscallArg {
    #[allow(unused)]
    fn from_cstr(&self, ptr: Remoteable<i8>) -> CString {
        self.peek_cstring(ptr).unwrap_or_else(|_| CString::new("").unwrap())
    }
    #[allow(unused)]
    fn from_cstr_sized<'a>(&self, ptr: Remoteable<i8>, size: usize) -> CString {
        let slice: Vec<u8> = self.peek_bytes(ptr.cast(), size).unwrap_or_else(|_|Vec::new());
        unsafe {
            CString::from_vec_unchecked(slice)
        }
    }
    #[allow(unused)]
    fn from_cstr_sized_atmost(&self, ptr: Remoteable<i8>, size: usize, max_size: usize) -> CString {
        let slice: Vec<u8> = self.peek_bytes(ptr.cast(), size).unwrap_or_else(|_|Vec::new()).iter().take(max_size).cloned().collect();
        unsafe {
            CString::from_vec_unchecked(slice)
        }
    }
    #[allow(unused)]
    fn fmt_cstr(&self, f: &mut fmt::Formatter, ptr: Remoteable<i8>) -> fmt::Result {
        write!(f, "\"{}\"", escape(self.from_cstr(ptr)))
    }
    #[allow(unused)]
    fn fmt_cstr_sized(&self, f: &mut fmt::Formatter, ptr: Remoteable<i8>, size: usize) -> fmt::Result {
        write!(f, "\"{}\"", escape(self.from_cstr_sized(ptr, size)))
    }
    #[allow(unused)]
    fn fmt_cstr_sized_atmost(&self, f: &mut fmt::Formatter, ptr: Remoteable<i8>, size: usize, max_size: usize) -> fmt::Result {
        let suffix = if max_size < size {
            "..."
        } else {
            ""
        };
        write!(f, "\"{}\"{}", escape(self.from_cstr_sized_atmost(ptr, size, max_size)), suffix)
    }
    #[allow(unused)]
    fn fmt_u8vec_atmost(&self, f: &mut fmt::Formatter, ptr: Remoteable<u8>, size: usize, max_size: usize) ->  fmt::Result {
        let slice :Vec<u8> = self.peek_bytes(ptr, size).unwrap_or_else(|_|Vec::new()).iter().take(max_size).cloned().collect();
        if size <= max_size {
            write!(f, "{:x?}", slice)
        } else {
            write!(f, "{:x?}...", slice)
        }
    }
    fn fmt_uname_ptr(&self, f: &mut fmt::Formatter, ptr: Remoteable<u64>) -> fmt::Result {
        let uts = self.peek_cstring(ptr.cast()).unwrap_or_else(|_| CString::new("").unwrap());
        let node = unsafe {
            self.peek_cstring(ptr.cast().offset(UTSNAME_LENGTH as isize))
                .unwrap_or_else(|_| CString::new("").unwrap())
        };
        write!(f, "{{sysname={:x?}, nodename={:x?}, ...}}", uts, node)
    }
    #[allow(unused)]
    pub unsafe fn fmt_cstr_null_terminated(&self, f: &mut fmt::Formatter, pptr: Remoteable<u64>) -> fmt::Result {
        let mut cnt = 0;
        let mut res = Vec::new();
        loop {
            let addr = self.peek::<u64>(pptr.offset(cnt)).unwrap_or(0);
            if addr == 0 {
                break;
            }
            let z = match pptr {
                Remoteable::Local(_)  => Remoteable::local(addr as *mut i8).unwrap(),
                Remoteable::Remote(_) => Remoteable::remote(addr as *mut i8).unwrap(),
            };
            res.push("\"".to_owned() + &escape(self.from_cstr(z)) + "\"");
            cnt = 1 + cnt;
        }
        write!(f, "[{}]", res.join(", "))
    }
    pub unsafe fn fmt_envp(&self, f: &mut fmt::Formatter, pptr: Remoteable<u64>) -> fmt::Result {
        let mut cnt = 0;
        loop {
            let addr = self.peek::<u64>(pptr.offset(cnt)).unwrap_or(0);
            if addr == 0 {
                break;
            }
            cnt += 1;
        }
        let unit = if cnt == 1 {
            "var"
        } else {
            "vars"
        };
        write!(f, "{:#x?} /* {} {} */", pptr, cnt, unit)
    }
    fn fmt_dirent_ptr(&self,
                      f: &mut fmt::Formatter,
                      ptr: Remoteable<linux_dirent_partial>)
                      -> fmt::Result {
	let mut count = 0;
	let mut curr = ptr;
        let mut left = self.retval.unwrap_or(0);

	while left > 0 {
            let ent = self.peek(curr).unwrap();
	    if ent.d_reclen == 0 {
	        break;
	    }
	    count += 1;
            left -= ent.d_reclen as i64;
            curr = Remoteable::remote(
                (curr.as_ptr() as u64 + ent.d_reclen as u64) as
                    *mut linux_dirent_partial).unwrap();
	}
	write!(f, "/* {} entries */", count)
    }
    fn fmt_dirent64_ptr(&self,
                        f: &mut fmt::Formatter,
                        ptr: Remoteable<linux_dirent_partial>)
                        -> fmt::Result {
        self.fmt_dirent_ptr(f, ptr)
    }
    fn fmt_rt_sigset_p(&self, f: &mut fmt::Formatter,
                           ptr: Remoteable<u64>) -> fmt::Result {
        let set = self.peek(ptr).unwrap_or(0);
        if set == 0 {
            write!(f, "[]")
        } else {
            write!(f, "{}", RtSigset::new(set))
        }
    }
    fn fmt_rt_sigaction_p(&self, f: &mut fmt::Formatter,
                        ptr: Remoteable<kernel_sigaction>) -> fmt::Result {
        let act =  self.peek(ptr).unwrap();
        write!(f, "{}", act)
    }
    fn fmt_timeval_p(&self, f: &mut fmt::Formatter, tp: Remoteable<timeval>) -> fmt::Result {
        let tv = self.peek(tp).unwrap();
        write!(f, "{{tv_sec: {}, tv_usec: {}}}", tv.tv_sec, tv.tv_usec)
    }

    fn fmt_timespec_p(&self, f: &mut fmt::Formatter, tp: Remoteable<timespec>) -> fmt::Result {
        let tp = self.peek(tp).unwrap();
        write!(f, "{{tv_sec: {}, tv_nsec: {}}}", tp.tv_sec, tp.tv_nsec)
    }

    fn fmt_timezone_p(&self, f: &mut fmt::Formatter, tp: Remoteable<timezone>) -> fmt::Result {
        let tz = self.peek(tp).unwrap();
        write!(f, "{{tz_minuteswest: {}, tz_dsttime: {}}}", tz.tz_minuteswest, tz.tz_dsttime)

    }
}

impl Display for InferiorSyscallArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.arg {
            SyscallArg::Int(val) => write!(f, "{}", val),
            SyscallArg::UInt(val) => write!(f, "{}", val),
            SyscallArg::I32(val) => write!(f, "{}", val),
            SyscallArg::Fd(val) => write!(f, "{}", val),
            SyscallArg::Hex(val) => write!(f, "{:#x}", val),
            SyscallArg::Ptr(p_) | SyscallArg::PtrOut(p_) => {
                match p_ {
                    None => write!(f, "NULL"),
                    Some(p) => write!(f, "{:x?}", p),
                }
            }
            SyscallArg::CStr(None) |
            SyscallArg::SizedCStr(_, None) |
            SyscallArg::SizedU8Vec(_, None) |
            SyscallArg::SizedU8VecOut(_, None) |
            SyscallArg::UnamePtr(None) |
            SyscallArg::SizedCStrOut(_, None) |
            SyscallArg::Envp(None) |
            SyscallArg::DirentPtr(None) |
            SyscallArg::Dirent64Ptr(None) |
            SyscallArg::CStrArrayNulTerminated(None) => {
                write!(f, "NULL")
            }
            SyscallArg::CStr(Some(ptr)) => {
                self.fmt_cstr(f, ptr)
            }
            SyscallArg::SizedCStr(size, Some(ptr))
                | SyscallArg::SizedCStrOut(size, Some(ptr)) => {
                self.fmt_cstr_sized_atmost(f, ptr, size, 32)
            }
            SyscallArg::SizedU8Vec(size, Some(ptr))
                | SyscallArg::SizedU8VecOut(size, Some(ptr)) => {
                self.fmt_u8vec_atmost(f, ptr, size, 16)
            }
            SyscallArg::FdFlags(flags) => write!(f, "{}", show_fdflags(flags)),
            SyscallArg::FdModes(modes) => write!(f, "0{:o}", modes),
            SyscallArg::DirFd(dirfd) => {
                match dirfd {
                    libc::AT_FDCWD => write!(f, "{}", "AT_FDCWD"),
                    libc::AT_SYMLINK_NOFOLLOW => write!(f, "{}", "AT_SYMLINK_NOFOLLOW"),
                    libc::AT_REMOVEDIR => write!(f, "{}", "AT_REMOVEDIR"),
                    libc::AT_SYMLINK_FOLLOW => write!(f, "{}", "AT_SYMLINK_FOLLOW"),
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
            SyscallArg::TimevalPtr(tv_) => {
                match tv_ {
                    None     => write!(f, "NULL"),
                    Some(tv) => self.fmt_timeval_p(f, tv.cast())
                }
            }

            SyscallArg::TimespecPtr(tp_) => {
                match tp_ {
                    None     => write!(f, "NULL"),
                    Some(tp) => self.fmt_timespec_p(f, tp.cast())
                }
            }
            SyscallArg::TimezonePtr(tz_) => {
                match tz_ {
                    None     => write!(f, "NULL"),
                    Some(tz) => self.fmt_timezone_p(f, tz.cast())
                }
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
            SyscallArg::RtSigSetPtr(set) => {
                match set {
                    None => write!(f, "NULL"),
                    Some(ptr) => self.fmt_rt_sigset_p(f, ptr.cast()),
                }
            }
            SyscallArg::RtSignal(sig) => {
                fmt_rt_signal(f, sig)
            }
            SyscallArg::RtSigactionPtr(act) => {
                match act {
                    None => write!(f, "NULL"),
                    Some(ptr) => self.fmt_rt_sigaction_p(f, ptr.cast()),
                }
            }
            SyscallArg::LseekWhence(whence) => {
                write!(f, "{}", libc_match_value!(whence, SEEK_SET)
                       .or_else(|| libc_match_value!(whence, SEEK_CUR))
                       .or_else(|| libc_match_value!(whence, SEEK_END))
                       .unwrap_or_else(|| "<whence: BAD_VALUE>"))
            }
            SyscallArg::Fcntl(cmd, arg) => {
                fmt_fcntl(self.pid, cmd, arg, f)
            }
            SyscallArg::Ioctl(cmd, arg) => {
                fmt_ioctl(self.pid, cmd, arg, f)
            }
            SyscallArg::UnamePtr(Some(ptr)) => {
                self.fmt_uname_ptr(f, ptr)
            }
            SyscallArg::CStrArrayNulTerminated(Some(ptr)) => {
                unsafe {
                    self.fmt_cstr_null_terminated(f, ptr.cast())
                }
            }
            SyscallArg::Envp(Some(ptr)) => {
                unsafe {
                    self.fmt_envp(f, ptr)
                }
            }
            SyscallArg::MAdvise(advise) => {
                fmt_madvise(f, advise)
            }
            SyscallArg::DirentPtr(Some(ptr)) => {
                self.fmt_dirent_ptr(f, ptr.cast())
            }
            SyscallArg::Dirent64Ptr(Some(ptr)) => {
                self.fmt_dirent64_ptr(f, ptr.cast())
            }
        }
    }
}

fn fmt_pre_syscall(info: &SyscallInfo, f: &mut fmt::Formatter) -> fmt::Result {
    let suffix = if info.args.len() == info.nargs_before {
        ") = "
    } else {
        ""
    };
    let args_to_format = info.args.iter()
        .take(info.nargs_before)
        .format(", ");
    write!(f, "[pid {:>4}] {:?}({}{}",
           info.pid, info.no, args_to_format, suffix)
}

fn fmt_post_syscall(info: &SyscallInfo, f: &mut fmt::Formatter) -> fmt::Result {
    let prefix = if info.nargs_before == 0 || info.nargs_before == info.args.len() {
        ""
    } else {
        ","
    };
    let suffix = if info.args.len() != info.nargs_before {
        ") = "
    } else {
        ""
    };
    let args_to_format = info.args.iter()
        .skip(info.nargs_before)
        .format(", ");
    write!(f, "{}{}{} {}", prefix,
           args_to_format, suffix, info.retval.unwrap_or(SyscallRet::NoReturn))
}

impl Display for SyscallInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.retval {
            Some(_) => fmt_post_syscall(self, f),
            None    => fmt_pre_syscall(self, f),
        }
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

fn escape<T: AsRef<CStr>>(s: T) -> String {
    let mut res = String::new();
    s.as_ref().to_bytes().iter().for_each(|c| {
        match c {
            b'\n' => {
                res.push_str("\\n");
            }
            b'\t' => {
                res.push_str("\\t");
            }
            _ => {
                if *c >= 0x20 && *c < 0x7f {
                    res.push(*c as char);
                } else {
                    res.push_str(&format!("\\{:o}", c));
                }
            }
        }
    });
    res
}

#[allow(unused)]
fn fmt_u8vec(f: &mut fmt::Formatter, ptr: NonNull<u8>, size: usize) ->  fmt::Result {
    let slice = unsafe {
        std::slice::from_raw_parts(ptr.as_ptr(), size)
    };
    write!(f, "{:x?}", slice)
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

#[repr(C)]
#[derive(Debug)]
struct timezone {
    tz_minuteswest: i32,
    tz_dsttime: i32,
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

const UTSNAME_LENGTH: usize = 65; /* sys/utsname.h */

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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct linux_dirent_partial {
    d_ino: u64,
    d_off: u64,
    d_reclen: u16,
}
