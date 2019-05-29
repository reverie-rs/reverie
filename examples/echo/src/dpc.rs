//! deferred precedure calls
//!

use syscalls::syscall;
use alloc::string::*;

use crate::consts;

const DPC_PREFIX: &'static str = "dpctask";

const PF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;

#[no_mangle]
pub extern "C" fn dpc_entry(_arg: i64) -> i32 {
    msg!("starting dpc task..");
    dpc_main();
    0
}

#[repr(C)]
struct sockaddr {
    sa_family: u16,
    sa_data: [u8; 14],
}

fn dpc_main () {
    let pid = syscall!(SYS_getpid).unwrap();
    let mut path = String::from(DPC_PREFIX) + ".";
    path.push_str(&pid.to_string());

    let _ = syscall!(SYS_unlink, path.as_ptr());

    let _tempfd = syscall!(SYS_socket, PF_UNIX, SOCK_STREAM, 0).unwrap();
    let sockfd = consts::SYSTRACE_DPC_SOCKFD;
    let _ = syscall!(SYS_dup2, _tempfd, sockfd).unwrap();
    let _ = syscall!(SYS_close, _tempfd).unwrap();

    let mut sa = sockaddr {
        sa_family: PF_UNIX as u16,
        sa_data: unsafe {
            core::mem::uninitialized()
        },
    };
    loop {
        if path.len() == 14 {
            break;
        }
        path.push('\0');
    }

    let sa_ref = &sa as *const sockaddr;
    sa.sa_data.copy_from_slice(path.as_bytes());
    let _ = syscall!(SYS_bind, sockfd, sa_ref, 16).unwrap();
    let _ = syscall!(SYS_listen, sockfd, 10).unwrap();

    loop {
        let mut client = unsafe {
            core::mem::zeroed()
        };
        let client_ref = &mut client as *mut sockaddr;
        let fd = syscall!(SYS_accept, sockfd, client_ref, 16).unwrap();

        incoming_connection(fd as i32);
    }
}

fn incoming_connection(fd: i32) {
    let mut request: [u8; 512] = unsafe {
        core::mem::uninitialized()
    };
    let ptr = request.as_mut_ptr();
    let n = syscall!(SYS_read, fd, ptr, core::mem::size_of_val(&request)).unwrap();
    let _ = syscall!(SYS_write, fd, ptr, n).unwrap();
}
