

use syscalls::*;
use core::fmt;
use core::fmt::Display;

use crate::show::types::*;
use crate::show::fcntl::fmt_fcntl;
use crate::show::ioctl::fmt_ioctl;

impl SyscallInfo {
    pub fn from(tid: i32, no: SyscallNo, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> Self {
        let args = match no {
            SYS_open => {
                if a1 as i32 & libc::O_CREAT == libc::O_CREAT {
                    vec![ SyscallArg::ArgCStr(a0 as u64),
                          SyscallArg::ArgFdFlags(a1 as i32),
                          SyscallArg::ArgFdModes(a2 as i32)]
                } else {
                    vec![ SyscallArg::ArgCStr(a0 as u64),
                          SyscallArg::ArgFdFlags(a1 as i32)]
                }
            }
            SYS_openat => {
                if a2 as i32 & libc::O_CREAT == libc::O_CREAT {
                    vec![ SyscallArg::ArgDirFd(a0 as i32),
                          SyscallArg::ArgCStr(a1 as u64),
                          SyscallArg::ArgFdFlags(a2 as i32),
                          SyscallArg::ArgFdModes(a3 as i32)]
                } else {
                    vec![ SyscallArg::ArgDirFd(a0 as i32),
                          SyscallArg::ArgCStr(a1 as u64),
                          SyscallArg::ArgFdFlags(a2 as i32)]
                }
            }
            SYS_mmap => {
                vec![ SyscallArg::ArgPtr(a0 as u64),
                      SyscallArg::ArgHex(a1),
                      SyscallArg::ArgMmapProt(a2 as i32),
                      SyscallArg::ArgMmapFlags(a3 as i32),
                      SyscallArg::ArgFd(a4 as i32),
                      SyscallArg::ArgInt(a5)]
            }
            SYS_munmap => {
                vec![ SyscallArg::ArgPtr(a0 as u64),
                      SyscallArg::ArgHex(a1)]
            }
            SYS_mprotect => {
                vec![ SyscallArg::ArgPtr(a0 as u64),
                      SyscallArg::ArgHex(a1),
                      SyscallArg::ArgMmapProt(a2 as i32)]
            }
            SYS_close => {
                vec![ SyscallArg::ArgFd(a0 as i32) ]
            }
            SYS_read | SYS_write => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgSizedU8Vec(a2 as usize, a1 as u64),
                      SyscallArg::ArgInt(a2) ]
            }
            SYS_pread64 | SYS_pwrite64 => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgSizedU8Vec(a2 as usize, a1 as u64),
                      SyscallArg::ArgInt(a2),
                      SyscallArg::ArgInt(a3)]
            }
            SYS_exit | SYS_exit_group => {
                vec![ SyscallArg::ArgI32(a0 as i32) ]
            }
            SYS_dup => {
                vec![ SyscallArg::ArgFd(a0 as i32) ]
            }
            SYS_dup2 => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgFd(a1 as i32)]
            }
            SYS_dup3 => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgFd(a1 as i32),
                      SyscallArg::ArgFdFlags(a2 as i32)]
            }
            SYS_fstat => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgPtr(a1 as u64)]
            }
            SYS_stat | SYS_lstat => {
                vec![ SyscallArg::ArgCStr(a0 as u64),
                      SyscallArg::ArgPtr(a1 as u64)]
            }
            SYS_readlink => {
                vec![ SyscallArg::ArgCStr(a0 as u64),
                      SyscallArg::ArgSizedU8Vec(a2 as usize, a1 as u64),
                      SyscallArg::ArgInt(a2)]
            }
            SYS_seccomp => {
                vec![ SyscallArg::ArgSeccompOp(a0 as u32),
                      SyscallArg::ArgSeccompFlags(a1 as u32),
                      SyscallArg::ArgSeccompFprog(a2 as u64)]
            }
            SYS_getpid | SYS_gettid | SYS_getppid | SYS_getpgid | SYS_getpgrp => {
                Vec::new()
            }
            SYS_getrandom => {
                vec![ SyscallArg::ArgSizedU8Vec(a1 as usize, a0 as u64),
                      SyscallArg::ArgInt(a1),
                      SyscallArg::ArgI32(a2 as i32)]
            }
            SYS_wait4 => {
                vec![ SyscallArg::ArgI32(a0 as i32),
                      SyscallArg::ArgPtr(a1 as u64),
                      SyscallArg::ArgWaitpidOptions(a2 as i32),
                      SyscallArg::ArgPtr(a3 as u64)]
            }
            SYS_set_robust_list => {
                vec![ SyscallArg::ArgPtr(a0 as u64),
                      SyscallArg::ArgInt(a1)]
            }
            SYS_get_robust_list => {
                vec![ SyscallArg::ArgI32(a0 as i32),
                      SyscallArg::ArgPtr(a1 as u64),
                      SyscallArg::ArgPtr(a2 as u64)]
            }
            SYS_uname => {
                vec![ SyscallArg::ArgPtr(a0 as u64) ]
            }
            SYS_access => {
                vec![ SyscallArg::ArgCStr(a0 as u64),
                      SyscallArg::ArgFdModes(a1 as i32)]
            }
            SYS_getuid | SYS_getgid | SYS_geteuid | SYS_getegid => {
                Vec::new()
            }
            SYS_time => {
                vec! [ SyscallArg::ArgPtr(a0 as u64) ]
            }
            SYS_gettimeofday => {
                vec! [ SyscallArg::ArgTimeval(a0 as u64),
                       SyscallArg::ArgTimezone(a1 as u64) ]
            }
            SYS_settimeofday => {
                vec! [ SyscallArg::ArgTimeval(a0 as u64),
                       SyscallArg::ArgTimezone(a1 as u64) ]
            }
            SYS_clock_gettime => {
                vec! [ SyscallArg::ArgClockId(a0 as i32),
                       SyscallArg::ArgTimespec(a1 as u64) ]
            }
            SYS_clock_settime => {
                vec! [ SyscallArg::ArgClockId(a0 as i32),
                       SyscallArg::ArgTimespec(a1 as u64) ]
            }
            SYS_futex => {
                vec![ SyscallArg::ArgPtr(a0 as u64),
                      SyscallArg::ArgFutexOp(a1 as i32),
                      SyscallArg::ArgI32(a2 as i32),
                      SyscallArg::ArgTimespec(a3 as u64),
                      SyscallArg::ArgPtr(a4 as u64),
                      SyscallArg::ArgI32 (a5 as i32)]
            }
            SYS_rt_sigprocmask => {
                vec![ SyscallArg::ArgRtSigHow(a0 as i32),
                      SyscallArg::ArgRtSigSet(a1 as u64),
                      SyscallArg::ArgRtSigSet(a2 as u64),
                      SyscallArg::ArgI32(a3 as i32)]
            }
            SYS_rt_sigaction => {
                vec![ SyscallArg::ArgRtSignal(a0 as i32),
                      SyscallArg::ArgRtSigaction(a1 as u64),
                      SyscallArg::ArgRtSigaction(a2 as u64),
                      SyscallArg::ArgI32(a3 as i32)]
            }
            SYS_lseek => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgInt(a1),
                      SyscallArg::ArgLseekWhence(a2 as i32)]
            }
            SYS_fcntl => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgFcntl(a1 as i32, a2 as u64)]
            }
            SYS_ioctl => {
                vec![ SyscallArg::ArgFd(a0 as i32),
                      SyscallArg::ArgIoctl(a1 as i32, a2 as u64)]
            }
            _ => {
                vec![ SyscallArg::ArgInt(a0),
                      SyscallArg::ArgInt(a1),
                      SyscallArg::ArgInt(a2),
                      SyscallArg::ArgInt(a3),
                      SyscallArg::ArgInt(a4),
                      SyscallArg::ArgInt(a5) ]
            }
        };
        SyscallInfo {
            tid,
            no,
            args,
        }
    }
}

impl fmt::Display for SyscallRet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SyscallRet::RetInt(val) => write!(f, "{}", val),
            SyscallRet::RetPtr(val) => write!(f, "{:#x}", val),
            SyscallRet::RetVoid => Ok(()),
        }
    }
}

impl fmt::Display for SyscallInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[pid {:>5}] {:?}", self.tid, self.no)?;
        let t = match self.args.len() {
            0 => write!(f, "()"),
            1 => write!(f, "({})", self.args[0]),
            2 => write!(f, "({}, {})", self.args[0], self.args[1]),
            3 => write!(f, "({}, {}, {})", self.args[0], self.args[1], self.args[2]),
            4 => write!(f, "({}, {}, {}, {})", self.args[0], self.args[1], self.args[2], self.args[3]),
            5 => write!(f, "({}, {}, {}, {}, {})", self.args[0], self.args[1], self.args[2], self.args[3], self.args[4]),
            6 => write!(f, "({}, {}, {}, {}, {}, {})", self.args[0], self.args[1], self.args[2], self.args[3], self.args[4], self.args[5]),
            _ => {
                unreachable!("syscall can take six arguments maximum");
            }
        }?;
        Ok(t)
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

impl fmt::Display for SyscallArg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SyscallArg::ArgInt(val) => write!(f, "{}", val),
            SyscallArg::ArgUInt(val) => write!(f, "{}", val),
            SyscallArg::ArgHex(val) => write!(f, "{:#x}", val),
            SyscallArg::ArgPtr(val) => write!(f, "{:#x}", val),
            SyscallArg::ArgCStr(val) => write!(f, "\"{}\"", from_cstr(val as i64)),
            SyscallArg::ArgSizedCStr(size, val) => {
                write!(f, "\"{}\"", from_sized_cstr(val as i64, size))
            }
            SyscallArg::ArgSizedU8Vec(size, val) => {
                from_u8vec_atmost(val as i64, size, 16, f)
            }
            SyscallArg::ArgI32(val) => write!(f, "{}", val),
            SyscallArg::ArgFd(fd) => write!(f, "{}", fd),
            SyscallArg::ArgFdFlags(flags) => write!(f, "{}", show_fdflags(flags)),
            SyscallArg::ArgFdModes(modes) => write!(f, "0{:o}", modes),
            SyscallArg::ArgDirFd(dirfd) => {
                match dirfd {
                    libc::AT_FDCWD => write!(f, "{}", "AT_FDCWD"),
                    _               => write!(f, "{}", dirfd),
                }
            }
            SyscallArg::ArgMmapProt(prot) => {
                write!(f, "{}", show_mmap_prot(prot))
            }
            SyscallArg::ArgMmapFlags(flags) => {
                write!(f, "{}", show_mmap_flags(flags))
            }
            SyscallArg::ArgSeccompOp(op) => {
                write!(f, "{}", show_seccomp_op(op))
            }
            SyscallArg::ArgSeccompFlags(flags) => {
                write!(f, "{}", show_seccomp_flags(flags))
            }
            SyscallArg::ArgSeccompFprog(prog) => {
                write!(f, "{}", show_seccomp_fprog(prog))
            }
            SyscallArg::ArgWaitpidOptions(options) => {
                write!(f, "{}", show_waitpid_options(options))
            }
            SyscallArg::ArgTimeval(tp) => {
                write!(f, "{}", show_timeval(tp))
            }

            SyscallArg::ArgTimespec(tp) => {
                write!(f, "{}", show_timespec(tp))
            }
            SyscallArg::ArgTimezone(tp) => {
                write!(f, "{}", show_timezone(tp))
            }
            SyscallArg::ArgClockId(id) => {
                write!(f, "{}", show_clock_id(id))
            }
            SyscallArg::ArgFutexOp(op) => {
                write!(f, "{}", show_futex_op(op))
            }
            SyscallArg::ArgRtSigHow(how) => {
                write!(f, "{}", libc_match_value!(how, SIG_BLOCK)
                       .or_else(|| libc_match_value!(how, SIG_UNBLOCK))
                       .or_else(|| libc_match_value!(how, SIG_SETMASK))
                       .unwrap_or_else(|| ""))
            }
            SyscallArg::ArgRtSigSet(set) => {
                write!(f, "{}", show_rt_sigset(set))
            }
            SyscallArg::ArgRtSignal(sig) => {
                write!(f, "{}", show_rt_signal(sig))
            }
            SyscallArg::ArgRtSigaction(act) => {
                write!(f, "{}", show_rt_sigaction(act))
            }
            SyscallArg::ArgLseekWhence(whence) => {
                write!(f, "{}", libc_match_value!(whence, SEEK_SET)
                       .or_else(|| libc_match_value!(whence, SEEK_CUR))
                       .or_else(|| libc_match_value!(whence, SEEK_END))
                       .unwrap_or_else(|| "<whence: BAD_VALUE>"))
            }
            SyscallArg::ArgFcntl(cmd, arg) => {
                fmt_fcntl(cmd, arg, f)
            }
            SyscallArg::ArgIoctl(cmd, arg) => {
                fmt_ioctl(cmd, arg, f)
            }
        }
    }
}

fn from_cstr<'a>(ptr: i64) -> &'a str {
    let res = unsafe {
        std::ffi::CStr::from_ptr(ptr as *const i8)
            .to_str()
            .unwrap_or_else(|_| "<CStr::ERROR>")
    };
    res
}

fn from_sized_cstr(ptr: i64, size: usize) -> String {
    let res = String::from(from_cstr(ptr));
    let len = std::cmp::min(res.len(), size);
    res[..len].to_string()
}

#[allow(unused)]
fn from_u8vec(ptr: i64, size: usize, f: &mut fmt::Formatter) ->  fmt::Result {
    let slice = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, size)
    };
    write!(f, "{:x?}", slice)
}

fn from_u8vec_atmost(ptr: i64, size: usize, max_size: usize, f: &mut fmt::Formatter) ->  fmt::Result {
    let slice = unsafe {
        std::slice::from_raw_parts(ptr as *const u8, size)
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

fn show_timeval(tp: u64) -> String {
    if tp == 0 {
        String::from("NULL")
    } else {
        let val = unsafe {
            core::ptr::read(tp as *const timeval)
        };
        format!("{:?}", val)
    }
}

fn show_timespec(tp: u64) -> String {
    if tp == 0 {
        String::from("NULL")
    } else {
        let val = unsafe {
            core::ptr::read(tp as *const timespec)
        };
        format!("{:?}", val)
    }
}

#[repr(C)]
#[derive(Debug)]
struct timezone {
    tz_minuteswest: i32,
    tz_dsttime: i32,
}

fn show_timezone(tp: u64) -> String {
    if tp == 0 {
        String::from("NULL")
    } else {
        let val = unsafe {
            core::ptr::read(tp as *const timezone)
        };
        format!("{:?}", val)
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

fn show_rt_sigset(ptr: u64) -> String {
    if ptr == 0 {
        return String::from("NULL");
    }
    let set = unsafe {
        core::ptr::read(ptr as *const u64)
    };
    if set == 0 {
        String::from("[]")
    } else {
        let f = [ libc_signal_bit!(set, SIGHUP, HUP),
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
            format!("[{:#x}|{}]", rtsigs.wrapping_shl(32), f)
        } else {
            format!("[{}]", f)
        }

    }
}

fn show_rt_signal(sig: i32) -> String {
    libc_match_value!(sig, SIGHUP)
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
        .unwrap_or_else(|| sig.to_string())
}

#[repr(C)]
struct kernel_sigaction {
    sa_handler: u64,
    sa_flags: u64,
    sa_restorer: u64,
    sa_mask: u64,
}

// {sa_handler=SIG_DFL, sa_mask=[], sa_flags=SA_RESTORER|SA_RESTART, sa_restorer=0x7f9dd58cbf20}
impl Display for kernel_sigaction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{sa_handler={}, sa_mask={}, sa_flags={}, sa_restorer={:#x}}}",
               match self.sa_handler as usize {
                   libc::SIG_DFL => String::from("SIG_DFL"),
                   libc::SIG_IGN => String::from("SIG_IGN"),
                   _ => format!("{:#x}", self.sa_handler),
               },
               {
                   let mask_p: *const u64 = &self.sa_mask;
                   show_rt_sigset(mask_p as u64)
               },
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

fn show_rt_sigaction(act_p: u64) -> String {
    if act_p == 0 {
        String::from("NULL")
    } else {
        let act = unsafe {
            core::ptr::read(act_p as *const kernel_sigaction)
        };
        format!("{}", act)
    }
}
