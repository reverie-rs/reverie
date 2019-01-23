#![feature(async_await, futures_api)]

#![allow(unused_imports)]
#![allow(dead_code)]

#![allow(unreachable_code)]
#![allow(unused_variables)]

#[macro_use]
extern crate lazy_static;

use std::env::{current_exe};
use clap::{Arg, App, SubCommand};
use std::io::{Result, Error, ErrorKind};
use std::path::PathBuf;
use std::ffi::CString;
use std::collections::HashMap;
use nix::unistd::{ForkResult};
use nix::unistd;
use nix::sys::{wait, signal, ptrace};
use nix::sys::wait::{WaitStatus};
use libc;
mod hooks;
mod nr;
mod ns;
mod patch;
mod consts;

// install seccomp-bpf filters
extern {
    fn bpf_install();
}

#[test]
fn can_resolve_syscall_hooks () -> Result<()>{
    let parsed = hooks::resolve_syscall_hooks_from(PathBuf::from(consts::LIB_PATH).join(consts::SYSTRACE_SO))?;
    assert_ne!(parsed.len(), 0);
    Ok(())
}

#[test]
fn libsystrace_trampoline_within_first_page() -> Result<()> {
    let parsed = hooks::resolve_syscall_hooks_from(PathBuf::from(consts::LIB_PATH).join(consts::SYSTRACE_SO))?;
    let filtered: Vec<_> = parsed.iter().filter(|hook| hook.offset < 0x1000).collect();
    assert_eq!(parsed.len(), filtered.len());
    Ok(())
}

lazy_static! {
    static ref SYSCALL_HOOKS: Vec<hooks::SyscallHook> = {
        hooks::resolve_syscall_hooks_from(PathBuf::from(consts::LIB_PATH).join(consts::SYSTRACE_SO)).unwrap()
    };
}

struct Arguments<'a> {
    debug_level: i32,
    program: &'a str,
    program_args: Vec<&'a str>,
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(ErrorKind::Other, err)
}

fn just_continue(pid: unistd::Pid, sig: Option<signal::Signal>) -> Result<()> {
    ptrace::cont(pid, sig).map_err(from_nix_error)
}

fn do_ptrace_vfork_done(pid: unistd::Pid) -> Result<()> {
    just_continue(pid, None)
}

fn do_ptrace_fork(pid: unistd::Pid) -> Result<()> {
    let child = ptrace::getevent(pid).map_err(from_nix_error)?;
    println!("{} has a new child {}", pid, child);
    just_continue(pid, None)
}

fn libsystrace_load_address(pid: unistd::Pid) -> Option<u64> {
    match ptrace::read(pid, consts::DET_TLS_SYSCALL_TRAMPOLINE as ptrace::AddressType) {
        Ok(addr) if addr != 0 => Some(addr as u64 & !0xfff),
        _otherwise => None,
    }
}

fn do_ptrace_seccomp(pid: unistd::Pid) -> Result<()> {
    let ev = ptrace::getevent(pid).map_err(from_nix_error)?;
    let regs = ptrace::getregs(pid).map_err(from_nix_error)?;
    let syscall = nr::SyscallNo::from(regs.orig_rax as i32);
    if ev == 0x7fff {
        panic!("unfiltered syscall: {:?}", syscall);
    }
    match libsystrace_load_address(pid) {
        None => just_continue(pid, None),
        Some(la) => {
            patch::may_patch_syscall_from(pid, syscall, regs , &SYSCALL_HOOKS, la)?;
            just_continue(pid, None)
        },
    }
}

fn tracee_preinit(pid: unistd::Pid) -> nix::Result<()> {
    let mut regs = ptrace::getregs(pid)?;
    let mut saved_regs = regs.clone();
    let page_addr = consts::DET_PAGE_OFFSET;
    let page_size = consts::DET_PAGE_SIZE;

    regs.orig_rax = nr::SYS_mmap as u64;
    regs.rax      = nr::SYS_mmap as u64;
    regs.rdi      = page_addr;
    regs.rsi      = page_size;
    regs.rdx      = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    regs.r10      = (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as u64;
    regs.r8       = -1 as i64 as u64;
    regs.r9       = 0 as u64;

    ptrace::setregs(pid, regs)?;
    ptrace::cont(pid, None)?;

    // second breakpoint after syscall hit
    assert!(wait::waitpid(pid, None) == Ok(wait::WaitStatus::Stopped(pid, signal::SIGTRAP)));
    let regs = ptrace::getregs(pid)
        .and_then(|r| {
            if (r.rax as i64) < 0 {
                let errno = -(r.rax as i64) as i32;
                Err(nix::Error::from_errno(nix::errno::from_i32(errno)))
            } else {
                Ok(r)
            }
        })?;

    let syscall_stub: u64 = 0x90c3050f90c3050f;
    ptrace::write(pid, page_addr as ptrace::AddressType, syscall_stub as *mut libc::c_void)?;
    ptrace::write(pid, (page_addr as usize + std::mem::size_of::<u64>()) as ptrace::AddressType, syscall_stub as *mut libc::c_void)?;

    saved_regs.rip = saved_regs.rip - 1; // bp size
    ptrace::setregs(pid, saved_regs)?;

    Ok(())
}

fn do_ptrace_exec(pid: unistd::Pid) -> nix::Result<()> {
    let bp_syscall_bp: i64 = 0xcc050fcc;
    let regs = ptrace::getregs(pid)?;
    assert!(regs.rip & 7 == 0);
    let saved: i64 = ptrace::read(pid, regs.rip as ptrace::AddressType)?;
    ptrace::write(pid, regs.rip as ptrace::AddressType, ((saved & !(0xffffffff as i64)) | bp_syscall_bp) as *mut libc::c_void)?;
    ptrace::cont(pid, None)?;
    let wait_status = wait::waitpid(pid, None)?;
    assert!(wait_status == wait::WaitStatus::Stopped(pid, signal::SIGTRAP));
    tracee_preinit(pid)?;
    ptrace::write(pid, regs.rip as ptrace::AddressType, saved as *mut libc::c_void)?;
    ptrace::cont(pid, None)?;
    Ok(())
}

fn handle_ptrace_event(pid: unistd::Pid, raw_event: i32) -> Result<()>{
    if raw_event == ptrace::Event::PTRACE_EVENT_FORK as i32
        || raw_event == ptrace::Event::PTRACE_EVENT_VFORK as i32
        || raw_event == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
            do_ptrace_fork(pid)?;
        } else if raw_event == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
            do_ptrace_exec(pid).map_err(from_nix_error)?;
        } else if raw_event == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i32 {
            do_ptrace_vfork_done(pid)?;
        } else if raw_event == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
            just_continue(pid, None)?;
        } else if raw_event == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
            do_ptrace_seccomp(pid)?;
        } else {
            panic!("unknown ptrace event: {:x}", raw_event);
        }
    Ok(())
}

fn handle_ptrace_syscall(pid: unistd::Pid) -> Result<()>{
    panic!("handle_ptrace_syscall, pid: {}", pid);
}

fn wait_sigstop(pid: unistd::Pid) -> Result<()> {
    match wait::waitpid(Some(pid), None).expect("waitpid failed") {
        WaitStatus::Stopped(new_pid, signal) if signal == signal::SIGSTOP && new_pid == pid =>
            Ok(()),
        _ => Err(Error::new(ErrorKind::Other, "expect SIGSTOP")),
    }
}

fn run_tracer_main(pid: unistd::Pid) -> Result<i32> {
    // wait for sigstop
    wait_sigstop(pid)?;
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACEEXEC
                       | ptrace::Options::PTRACE_O_EXITKILL
                       | ptrace::Options::PTRACE_O_TRACECLONE
                       | ptrace::Options::PTRACE_O_TRACEFORK
                       | ptrace::Options::PTRACE_O_TRACEVFORK
                       | ptrace::Options::PTRACE_O_TRACEVFORKDONE
                       | ptrace::Options::PTRACE_O_TRACEEXIT
                       | ptrace::Options::PTRACE_O_TRACESECCOMP
                       | ptrace::Options::PTRACE_O_TRACESYSGOOD).map_err(|e|Error::new(ErrorKind::Other, e))?;
    ptrace::cont(pid, None).map_err(|e|Error::new(ErrorKind::Other, e))?;
    loop {
        match wait::waitpid(None, None) {
            Err(failure) => {
                return Err(Error::new(ErrorKind::Other, failure));
            },
            Ok(WaitStatus::Exited(_newpid, exit_code)) => {
                return Ok(exit_code);
            },
            Ok(WaitStatus::Signaled(_newpid, signal, _core)) => {
                return Ok(0x80 | signal as i32);
            },
            Ok(WaitStatus::Continued(_newpid)) => (),
            Ok(WaitStatus::PtraceEvent(pid, signal, event)) if signal == signal::SIGTRAP =>
                handle_ptrace_event(pid, event)?,
            Ok(WaitStatus::PtraceSyscall(pid)) =>
                handle_ptrace_syscall(pid)?,
            Ok(WaitStatus::Stopped(pid, sig)) => {
                just_continue(pid, Some(sig))?;
            }
            otherwise => panic!("unknown status: {:?}", otherwise),
        }
    }
    unreachable!("unreachable: ptrace main loop")
}

// hardcoded because `libc` does not export
const ADDR_NO_RANDOMIZE: u64 = 0x0040000;

fn run_tracee(argv: &Arguments) -> Result<i32> {
    unsafe {
        assert!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        assert!(libc::personality(ADDR_NO_RANDOMIZE) == 0);
    };

    ptrace::traceme()
        .and_then(|_|signal::raise(signal::SIGSTOP))
        .map_err(from_nix_error)?;

    // println!("launching program: {} {:?}", &argv.program, &argv.program_args);

    // install seccomp-bpf filters
    // NB: the only syscall beyond this point should be
    // execvpe only.
    unsafe { bpf_install() };

    let envs = vec![ "PATH=/bin/:/usr/bin",
                      "LD_PRELOAD=libdet.so libsystrace.so",
                      "LD_LIBRARY_PATH=lib",
    ];

    let program = CString::new(argv.program)?;
    let mut args: Vec<CString> = Vec::new();
    CString::new(argv.program).map(|s|args.push(s))?;
    for v in argv.program_args.clone() {
        CString::new(v).map(|s|args.push(s))?;
    }
    let envp: Vec<CString> = (envs).into_iter().map(|s|CString::new(s).unwrap()).collect();

    unistd::execvpe(&program,
                    args.as_slice(),
                    envp.as_slice())
        .map_err(from_nix_error)?;
    unreachable!("exec failed: {} {:?}", &argv.program, &argv.program_args);
}

fn run_tracer(starting_pid: unistd::Pid, starting_uid: unistd::Uid, starting_gid: unistd::Gid, argv: &Arguments) -> Result<i32> {
    ns::init_ns(starting_pid, starting_uid, starting_gid)?;

    // tracer is the 1st process in the new namespace.
    assert!(unistd::getpid() == unistd::Pid::from_raw(1));

    match unistd::fork().expect("fork failed") {
        ForkResult::Child => {
            return run_tracee(argv);
        },
        ForkResult::Parent{child} => run_tracer_main(child),
    }
}

fn run_app(argv: &Arguments) -> Result<i32> {
    let (starting_pid, starting_uid, starting_gid) = (unistd::getpid(), unistd::getuid(), unistd::getgid());
    unsafe {
        assert!(libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWUTS) == 0);
    };

    match unistd::fork().expect("fork failed") {
        ForkResult::Child => {
            run_tracer(starting_pid, starting_uid, starting_gid, argv)
        },
        ForkResult::Parent{child} => {
            match wait::waitpid(Some(child), None) {
                Ok(wait::WaitStatus::Exited(_, exit_code)) =>
                    Ok(exit_code),
                otherwise => panic!("unexpected status from waitpid: {:?}",
                                    otherwise),
            }
        }
    }
}

fn main() {
    let matches = App::new("systrace - a fast syscall tracer and interceper")
        .version("0.0.1")
        .arg(Arg::with_name("debug")
             .long("debug")
             .value_name("DEBUG_LEVEL")
             .help("Set debug level [0..5]")
             .takes_value(true))
        .arg(Arg::with_name("program")
             .value_name("PROGRAM")
             .required(true)
             .help("PROGRAM")
             .takes_value(true))
        .arg(Arg::with_name("program_args")
             .value_name("PROGRAM_ARGS")
             .allow_hyphen_values(true)
             .multiple(true)
             .help("[PROGRAM_ARGUMENTS..]"))
        .get_matches();

    let argv = Arguments {
        debug_level: matches.value_of("debug").and_then(|x|x.parse::<i32>().ok()).unwrap_or(0),
        program: matches.value_of("program").unwrap_or(""),
        program_args: matches.values_of("program_args").map(|v|v.collect()).unwrap_or(Vec::new()),
    };

    run_app(&argv).expect("run_app returned error result");
}
