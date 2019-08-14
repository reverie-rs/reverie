
use syscalls::SyscallNo;
use api::remote::*;

use nix::unistd::Pid;

/// tracee's syscall arg
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InferiorSyscallArg {
    pub pid: Pid,
    pub arg: SyscallArg,
}

impl InferiorSyscallArg {
    pub fn from(pid: Pid, arg: SyscallArg) -> Self {
        InferiorSyscallArg {
            pid,
            arg,
        }
    }
}

/// syscall return vaules for formatting purpose
#[derive(Clone, Copy)]
pub enum SyscallRet {
    /// returned long
    RetInt(i64),
    /// returned pointer
    RetPtr(u64),
    /// no return value
    RetVoid,
    /// syscall does not return, like exit_group
    NoReturn,
}

/// syscall argument ADT for formatting args
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SyscallArg {
    Int(i64),
    UInt(u64),
    Hex(i64),
    Ptr(Remoteable<u64>),
    PtrOut(Remoteable<u64>),
    CStr(Remoteable<i8>),
    SizedCStr(usize, Remoteable<i8>),
    SizedU8Vec(usize, Remoteable<u8>),
    SizedCStrOut(usize, Remoteable<i8>),
    SizedU8VecOut(usize, Remoteable<u8>),
    CStrArrayNulTerminated(Remoteable<i8>),
    Envp(Remoteable<u64>),
    I32(i32),
    Fd(i32),
    FdFlags(i32),
    FdModes(i32),
    DirFd(i32),
    MmapProt(i32),
    MmapFlags(i32),
    SeccompOp(u32),
    SeccompFlags(u32),
    SeccompFprog(u64),
    WaitpidOptions(i32),
    Timeval(u64),
    Timespec(u64),
    Timezone(u64),
    ClockId(i32),
    FutexOp(i32),
    RtSigHow(i32),
    RtSigSet(u64),
    RtSigaction(u64),
    RtSignal(i32),
    LseekWhence(i32),
    // Fcntl(i32, u64),
    // Ioctl(i32, u64),
    UnamePtr(Remoteable<u64>),
    MAdvise(i32),
    DirentPtr(Remoteable<u64>),
    Dirent64Ptr(Remoteable<u64>),
}

/// syscall info with syscall no and arguments
#[derive(Clone)]
pub struct SyscallInfo {
    /// pid (tid) of the syscall
    pub pid: Pid,
    /// syscall number
    pub no: SyscallNo,
    /// args
    pub args: Vec<InferiorSyscallArg>,
    /// args known before syscall return
    pub nargs_before: usize,
    /// syscall return value, None if syscall is not returned
    pub retval: Option<SyscallRet>,
}
