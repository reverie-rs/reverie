
use core::ptr::NonNull;
use core::ffi::c_void as void;
use syscalls::SyscallNo;

/// syscall return vaules for formatting purpose
#[derive(Clone, Copy)]
pub enum SyscallRet {
    RetInt(i64),
    RetPtr(u64),
    RetVoid,
}

/// syscall argument ADT for formatting args
#[derive(Clone, Copy)]
pub enum SyscallArg {
    Int(i64),
    UInt(u64),
    Hex(i64),
    Ptr(Option<NonNull<void>>),
    PtrOut(Option<NonNull<void>>),
    CStr(Option<NonNull<i8>>),
    SizedCStr(usize, Option<NonNull<i8>>),
    SizedU8Vec(usize, Option<NonNull<u8>>),
    SizedCStrOut(usize, Option<NonNull<i8>>),
    SizedU8VecOut(usize, Option<NonNull<u8>>),
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
    Fcntl(i32, u64),
    Ioctl(i32, u64),
    UnamePtr(Option<NonNull<void>>),
}

/// syscall info with syscall no and arguments
#[derive(Clone)]
pub struct SyscallInfo {
    pub tid: i32,
    pub no: SyscallNo,
    pub args: Vec<SyscallArg>,
    pub nargs_before: usize,
}

/// syscall info with syscall no and arguments
#[derive(Clone)]
pub struct SyscallRetInfo {
    pub tid: i32,
    pub no: SyscallNo,
    pub args: Vec<SyscallArg>,
    pub retval: SyscallRet,
    pub first_arg_is_outp: bool,
}
