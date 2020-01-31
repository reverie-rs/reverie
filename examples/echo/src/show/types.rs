/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 * 
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

use core::ffi::c_void as void;
use core::ptr::NonNull;
use reverie_helper::syscalls::SyscallNo;

/// syscall return vaules for formatting purpose
#[derive(Clone, Copy)]
pub enum SyscallRet {
    RetInt(i64),
    RetPtr(u64),
    RetVoid,
    NoReturn,
}

/// syscall argument ADT for formatting args
#[derive(Clone, Copy)]
pub enum SyscallArg {
    Int(i64),
    UInt(u64),
    Hex(u64),
    Ptr(Option<NonNull<void>>),
    PtrOut(Option<NonNull<void>>),
    CStr(Option<NonNull<i8>>),
    SizedCStr(usize, Option<NonNull<i8>>),
    SizedU8Vec(usize, Option<NonNull<u8>>),
    SizedCStrOut(usize, Option<NonNull<i8>>),
    SizedU8VecOut(usize, Option<NonNull<u8>>),
    CStrArrayNulTerminated(Option<NonNull<void>>),
    Envp(Option<NonNull<void>>),
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
    MAdvise(i32),
    DirentPtr(Option<NonNull<void>>),
    Dirent64Ptr(Option<NonNull<void>>),
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
