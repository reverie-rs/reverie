//! seccomp bpf helpers
//!

#[repr(C)]
struct range {
    begin: u64,
    end: u64,
}

#[repr(C)]
struct sock_filter {
    opcode: u64,     // opaque as long as size is 64bit
}

extern "C" {
    fn bpf_ll_whitelist_ips(filter: *mut sock_filter, ranges: *const range, nranges: usize) -> isize;
    fn bpf_ll_blacklist_ips(filter: *mut sock_filter, ranges: *const range, nranges: usize) -> isize;
}

/// NB: max insn allowed is 4096
const SOCK_FILTER_MAX: usize = 256;

pub fn bpf_whitelist_ips(ips: &[(u64, u64)]) -> Vec<u64> {
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
    v
}

pub fn bpf_blacklist_ips(ips: &[(u64, u64)]) -> Vec<u64> {
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
    v
}
