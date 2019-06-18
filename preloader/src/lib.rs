//! preloader

use std::io::Result;

pub mod consts;
pub mod relink;
pub mod seccomp_bpf;

use syscalls::*;

#[link_section = ".init_array"]
#[used]
static PRELOADER_CTORS: extern fn() = {
    extern "C" fn preloader_ctor() {
        preload_dl_ns().unwrap();
    };
    preloader_ctor
};

#[repr(C)]
struct sock_filter {
    opaque: u64,
}

#[repr(C)]
struct sock_fprog {
    len: u32,
    filter: *const sock_filter,
}

fn preload_dl_ns() -> Result<()>{
    if let Ok(dso) = std::env::var(consts::SYSTRACE_TRACEE_PRELOAD) {
        let linkmap = relink::dl_open_ns(&dso);
        let mut whitelist: Vec<_> = vec![(0x7000_0002, 0x7000_0002)];
        linkmap.iter().for_each(|lm| {
            lm.ranges.iter().for_each(|e| {
                let perms = e.perms.as_bytes();
                if perms[2] == 'x' as u8 {
                    whitelist.push(e.address);
                }
            });
        });
        // println!("whitelist: {:#x?}", whitelist);
        let bytes = seccomp_bpf::bpf_whitelist_ips(whitelist.as_mut());
        let prog = sock_fprog {
            len: bytes.len() as u32,
            filter: bytes.as_ptr() as *const sock_filter,
        };
        let ptr = &prog as *const sock_fprog;
        let r = unsafe {
            libc::syscall(SYS_seccomp as i64,
                          1,
                          0,
                          ptr as i64,
                          0, 0, 0)
        };
        assert_eq!(r, 0);
    }
    Ok(())
}
