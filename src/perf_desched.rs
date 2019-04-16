/// linux perf sw context switch event interface
/// enable/disable is called by the tracer, but used for tracees
/// events are reported (from the tracess) to the tracer

use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::io::Read;
use libc;
use nix::fcntl;

#[no_mangle]
pub extern "C" fn desched_event_signal_handler(
    signo: libc::c_int,
    _p_siginfo: *mut libc::siginfo_t,
    _p_ucontext: *mut libc::c_void) {
    println!("### received: {:?}", signo);

    let si = unsafe {
        _p_siginfo.as_ref().unwrap()
    };
    println!("{} {} {}", si.si_signo, si.si_errno, si.si_code);

    let mut contents = String::new();
    let fd: File = unsafe { FromRawFd::from_raw_fd(si._pad[3]) };

    println!("{:x?}", fd);
}
