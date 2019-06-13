
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
    ArgInt(i64),
    ArgUInt(u64),
    ArgHex(i64),
    ArgPtr(u64),
    ArgCStr(u64),
    ArgSizedCStr(usize, u64),
    ArgSizedU8Vec(usize, u64),
    ArgI32(i32),
    ArgFd(i32),
    ArgFdFlags(i32),
    ArgFdModes(i32),
    ArgDirFd(i32),
    ArgMmapProt(i32),
    ArgMmapFlags(i32),
    ArgSeccompOp(u32),
    ArgSeccompFlags(u32),
    ArgSeccompFprog(u64),
    ArgWaitpidOptions(i32),
    ArgTimeval(u64),
    ArgTimespec(u64),
    ArgTimezone(u64),
    ArgClockId(i32),
    ArgFutexOp(i32),
    ArgRtSigHow(i32),
    ArgRtSigSet(u64),
    ArgRtSigaction(u64),
    ArgRtSignal(i32),
    ArgLseekWhence(i32),
    ArgFcntl(i32, u64),
    ArgIoctl(i32, u64),
}

/// syscall info with syscall no and arguments
#[derive(Clone)]
pub struct SyscallInfo {
    pub tid: i32,
    pub no: SyscallNo,
    pub args: Vec<SyscallArg>,
}

