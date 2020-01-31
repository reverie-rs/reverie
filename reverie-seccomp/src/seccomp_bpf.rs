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

//! seccomp bpf helpers
//!

#[allow(unused_imports)]
use syscalls::*;

use libc;
use std::io;

#[repr(C)]
struct range {
    begin: u64,
    end: u64,
}

#[repr(C)]
struct sock_filter {
    opcode: u64, // opaque as long as size is 64bit
}

#[repr(C)]
struct sock_fprog {
    len: u32,
    filter: *const sock_filter,
}

extern "C" {
    fn bpf_ll_whitelist_ips(
        filter: *mut sock_filter,
        ranges: *const range,
        nranges: usize,
    ) -> isize;
    fn bpf_ll_blacklist_ips(
        filter: *mut sock_filter,
        ranges: *const range,
        nranges: usize,
    ) -> isize;
}

/// NB: max insn allowed is 4096
const SOCK_FILTER_MAX: usize = 4096;

pub fn bpf_whitelist_ips(ips: &[(u64, u64)]) -> Vec<u64> {
    let mut res: [u64; SOCK_FILTER_MAX] = unsafe { std::mem::zeroed() };
    let ranges: Vec<_> = ips
        .iter()
        .map(|(x, y)| range { begin: *x, end: *y })
        .collect();

    let nb = unsafe {
        bpf_ll_whitelist_ips(
            res.as_mut_ptr() as *mut sock_filter,
            ranges.as_ptr(),
            ranges.len(),
        )
    };
    let mut v = res.to_vec();
    v.truncate(nb as usize);
    v
}

pub fn bpf_blacklist_ips(ips: &[(u64, u64)]) -> Vec<u64> {
    let mut res: [u64; SOCK_FILTER_MAX] = unsafe { std::mem::zeroed() };
    let ranges: Vec<_> = ips
        .iter()
        .map(|(x, y)| range { begin: *x, end: *y })
        .collect();

    let nb = unsafe {
        bpf_ll_blacklist_ips(
            res.as_mut_ptr() as *mut sock_filter,
            ranges.as_ptr(),
            ranges.len(),
        )
    };
    let mut v = res.to_vec();
    v.truncate(nb as usize);
    v
}

pub fn seccomp(bytecode: &[u64]) -> io::Result<()> {
    let prog = sock_fprog {
        len: bytecode.len() as u32,
        filter: bytecode.as_ptr() as *const sock_filter,
    };
    let ptr = &prog as *const sock_fprog;
    let r =
        unsafe { libc::syscall(SYS_seccomp as i64, 1, 0, ptr as i64, 0, 0, 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
