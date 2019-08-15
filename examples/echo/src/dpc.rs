//! deferred precedure calls
//!

use syscalls::syscall;
use log::debug;

use crate::consts;
use crate::logger;

const DPC_PREFIX: &'static str = "/tmp/dpc-task.";

const PF_UNIX: i32 = 1;
const SOCK_STREAM: i32 = 1;

#[no_mangle]
pub extern "C" fn dpc_entry_disabled(_arg: i64) -> i32 {
    let _ = logger::init();
    debug!("starting dpc task..");
    unsafe {
        dpc_main()
    }
    0
}

const HEX_DIGITS: [u8; 16] = [ '0' as u8, '1' as u8, '2' as u8, '3' as u8,
                               '4' as u8, '5' as u8, '6' as u8, '7' as u8,
                               '8' as u8, '9' as u8, 'a' as u8, 'b' as u8,
                               'c' as u8, 'd' as u8, 'e' as u8, 'f' as u8];

fn dpc_get_unp(pid: i32) -> [u8; 108] {
    let mut unp: [u8; 108] = unsafe {
        core::mem::zeroed()
    };

    let k = DPC_PREFIX.len();
    unsafe {
        core::ptr::copy_nonoverlapping(
            DPC_PREFIX.as_ptr() as *const u8,
            unp.as_mut_ptr() as *mut u8,
            k)
    };
    unp[k]   = HEX_DIGITS[(pid as usize & 0xf000) >> 12];
    unp[k+1] = HEX_DIGITS[(pid as usize & 0x0f00) >> 8];
    unp[k+2] = HEX_DIGITS[(pid as usize & 0x00f0) >> 4];
    unp[k+3] = HEX_DIGITS[(pid as usize & 0x000f) >> 0];

    unp
}

#[link_section = ".fini_array"]
#[used]
static DPC_DSO_DTORS: extern fn() = {
    extern "C" fn dpc_dtor() {
        debug!("exiting dpc task..");
        let pid = unsafe {
            syscall!(SYS_getpid) as i32
        };
        let _ = unsafe {
            syscall!(SYS_close, consts::REVERIE_DPC_SOCKFD)
        };
        let path = dpc_get_unp(pid);
        let _ = unsafe {
            syscall!(SYS_unlink, path.as_ptr())
        };
    };
    dpc_dtor
};

#[repr(C)]
struct sockaddr {
    sa_family: u16,
    sa_data: [u8; 108],
}

unsafe fn dpc_main () {
    let pid = syscall!(SYS_getpid) as i32;
    let path = dpc_get_unp(pid);

    let _ = syscall!(SYS_unlink, path.as_ptr());

    let _tempfd = syscall!(SYS_socket, PF_UNIX, SOCK_STREAM, 0) as i32;
    let sockfd = consts::REVERIE_DPC_SOCKFD;
    let sockfd_len = core::mem::size_of::<sockaddr>();
    let _ = syscall!(SYS_dup2, _tempfd, sockfd);
    let _ = syscall!(SYS_close, _tempfd);

    let _ = syscall!(SYS_unlink, path.as_ptr());

    let sa = sockaddr {
        sa_family: PF_UNIX as u16,
        sa_data: path,
    };

    let sa_ref = &sa as *const sockaddr;
    let _ = syscall!(SYS_bind, sockfd, sa_ref, sockfd_len);
    let _ = syscall!(SYS_listen, sockfd, 10);

    loop {
        let mut client = unsafe {
            core::mem::zeroed()
        };
        let client_ref = &mut client as *mut sockaddr;
        let fd = syscall!(SYS_accept, sockfd, client_ref, sockfd_len);

        incoming_connection(fd as i32);
    }
}

fn incoming_connection(fd: i32) {
    let mut request: [u8; 512] = unsafe {
        core::mem::uninitialized()
    };
    let ptr = request.as_mut_ptr();
    let n = unsafe {
        syscall!(SYS_read, fd, ptr, core::mem::size_of_val(&request))
    };
    let _ = unsafe {
        syscall!(SYS_write, fd, ptr, n)
    };
}
