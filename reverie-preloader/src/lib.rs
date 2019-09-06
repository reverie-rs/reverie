//! preloader

use std::io::Result;

pub mod relink;
pub mod seccomp_bpf;

use reverie_common::consts;
use syscalls::*;

#[link_section = ".init_array"]
#[used]
static PRELOADER_CTORS: extern "C" fn() = {
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

fn preload_dl_ns() -> Result<()> {
    if let Ok(dso) = std::env::var(consts::REVERIE_TRACEE_PRELOAD) {
        let linkmap = relink::dl_open_ns(dso);

        /*
                   struct sock_filter filter[] = {
                       /* [0] Load architecture from 'seccomp_data' buffer into
                              accumulator */
                       BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                (offsetof(struct seccomp_data, arch))),

                       /* [1] Jump forward 5 instructions if architecture does not
                              match 't_arch' */
                       BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_arch, 0, 1),

                       /* [2] Destination of system call number mismatch: allow other
                              system calls */
                       BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

                       /* [3] Destination of architecture mismatch: kill task */
                       BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
               };
        */
        let filter = vec![
            0x400000020u64,
            0xc000003e01000015u64,
            0x7fff000000000006u64,
            0x6u64,
        ];
        let prog = sock_fprog {
            len: 4,
            filter: filter.as_ptr() as *const sock_filter,
        };
        let ptr = &prog as *const sock_fprog;
        let r = unsafe {
            libc::syscall(SYS_seccomp as i64, 1, 0, ptr as i64, 0, 0, 0)
        };
        assert_eq!(r, 0);
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
            libc::syscall(SYS_seccomp as i64, 1, 1 << 4, ptr as i64, 0, 0, 0)
        };
        if r == -1 {
            eprintln!("\n\n\t### seccomp doesn't support SECCOMP_FILTER_FLAG_CLOEXEC, execve may not work ###\n\n");
            let r = unsafe {
                libc::syscall(SYS_seccomp as i64, 1, 0, ptr as i64, 0, 0, 0)
            };
            assert_eq!(r, 0);
        }
    }
    Ok(())
}
