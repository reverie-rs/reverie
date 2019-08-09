//! seccomp for whitelist/blacklist syscalls
//!

use libc;
use syscalls::*;
use std::io::Result;

#[repr(C)]
struct range {
    begin: u64,
    end: u64,
}

#[repr(C)]
struct sock_filter {
    opcode: u64,     // opaque as long as size is 64bit
}

#[repr(C)]
struct sock_fprog {
    len: u32,
    filter: *const sock_filter,
}

extern "C" {
    fn bpf_ll_whitelist_ips(filter: *mut sock_filter, ranges: *const range, nranges: usize) -> isize;
    fn bpf_ll_blacklist_ips(filter: *mut sock_filter, ranges: *const range, nranges: usize) -> isize;
}

/// NB: max insn allowed is 4096
const SOCK_FILTER_MAX: usize = 4096;

fn seccomp_install_filter(filter: &[u64]) -> Result<()> {
    let prog = sock_fprog {
        len: filter.len() as u32,
        filter: filter.as_ptr() as *const sock_filter,
    };
    let ptr = &prog as *const sock_fprog;
    let r = unsafe {
        libc::syscall(SYS_seccomp as i64,
                      1,
                      0,
                      ptr as i64,
                      0, 0, 0)
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// filter syscalls unless the ones within whitelist range
pub fn seccomp_whitelist_ips(ips: &[(u64, u64)]) -> Result<()> {
    let mut res: [u64; SOCK_FILTER_MAX] = unsafe {
        std::mem::zeroed()
    };
    let ranges: Vec<_> = ips.iter().map(|(x, y)| range{begin: *x, end: *y}).collect();

    let nb = unsafe {
        bpf_ll_whitelist_ips(res.as_mut_ptr() as *mut sock_filter,
                             ranges.as_ptr(), ranges.len())
    };
    let mut v = res.to_vec();
    v.truncate(nb as usize);
    seccomp_install_filter(&v)
}

/// allow syscalls through unless the ones within blacklisted range, which are traced
pub fn seccomp_blacklist_ips(ips: &[(u64, u64)]) -> Result<()> {
    let mut res: [u64; SOCK_FILTER_MAX] = unsafe {
        std::mem::zeroed()
    };
    let ranges: Vec<_> = ips.iter().map(|(x, y)| range{begin: *x, end: *y}).collect();

    let nb = unsafe {
        bpf_ll_blacklist_ips(res.as_mut_ptr() as *mut sock_filter,
                             ranges.as_ptr(), ranges.len())
    };
    let mut v = res.to_vec();
    v.truncate(nb as usize);
    seccomp_install_filter(&v)
}
