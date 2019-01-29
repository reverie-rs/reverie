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
mod consts;
mod stubs;
mod remote;
mod tasks;
mod proc;

use remote::*;

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

fn do_ptrace_vfork_done(task: &mut TracedTask) -> Result<()> {
    task.cont()
}

fn do_ptrace_clone(task: &mut TracedTask) -> Result<TracedTask> {
    let pid_raw = ptrace::getevent(task.pid).map_err(from_nix_error)?;
    just_continue(task.pid, None)?;
    let child = unistd::Pid::from_raw(pid_raw as libc::pid_t);
    let new_task = task.cloned();
    Ok(new_task)
}

fn do_ptrace_fork(task: &mut TracedTask) -> Result<TracedTask> {
    let pid_raw = ptrace::getevent(task.pid).map_err(from_nix_error)?;
    just_continue(task.pid, None)?;
    let child = unistd::Pid::from_raw(pid_raw as libc::pid_t);
    let new_task = task.forked(child);
    Ok(new_task)
}

fn do_ptrace_vfork(task: &mut TracedTask) -> Result<TracedTask> {
    let pid_raw = ptrace::getevent(task.pid).map_err(from_nix_error)?;
    just_continue(task.pid, None)?;
    let child = unistd::Pid::from_raw(pid_raw as libc::pid_t);
    let new_task = task.vforked(child);
    Ok(new_task)
}

fn do_ptrace_seccomp(task: &mut TracedTask) -> Result<()> {
    let ev = ptrace::getevent(task.pid).map_err(from_nix_error)?;
    let regs = ptrace::getregs(task.pid).map_err(from_nix_error)?;
    let syscall = nr::SyscallNo::from(regs.orig_rax as i32);
    if ev == 0x7fff {
        panic!("unfiltered syscall: {:?}", syscall);
    }
    // println!("seccomp syscall {:?}", syscall);
    match task.patch_syscall(regs.rip) {
        Ok(_) => {
            just_continue(task.pid, None)
        },
        _ => just_continue(task.pid, None),
    }
}

fn tracee_preinit(task: &mut TracedTask) -> nix::Result<()> {
    let mut regs = ptrace::getregs(task.pid)?;
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

    ptrace::setregs(task.pid, regs)?;
    ptrace::cont(task.pid, None)?;

    // second breakpoint after syscall hit
    assert!(wait::waitpid(task.pid, None) ==
            Ok(wait::WaitStatus::Stopped(task.pid, signal::SIGTRAP)));
    let regs = ptrace::getregs(task.pid)
        .and_then(|r| {
            if r.rax > (-4096i64 as u64) {
                let errno = -(r.rax as i64) as i32;
                Err(nix::Error::from_errno(nix::errno::from_i32(errno)))
            } else {
                Ok(r)
            }
        })?;

    remote::gen_syscall_sequences_at(task.pid, page_addr)?;

    saved_regs.rip = saved_regs.rip - 1; // bp size
    ptrace::setregs(task.pid, saved_regs)?;

    Ok(())
}

fn do_ptrace_exec(task: &mut TracedTask) -> nix::Result<()> {
    let bp_syscall_bp: i64 = 0xcc050fcc;
    let regs = ptrace::getregs(task.pid)?;
    assert!(regs.rip & 7 == 0);
    let saved: i64 = ptrace::read(task.pid, regs.rip as ptrace::AddressType)?;
    ptrace::write(task.pid, regs.rip as ptrace::AddressType, ((saved & !(0xffffffff as i64)) | bp_syscall_bp) as *mut libc::c_void)?;
    ptrace::cont(task.pid, None)?;
    let wait_status = wait::waitpid(task.pid, None)?;
    assert!(wait_status == wait::WaitStatus::Stopped(task.pid, signal::SIGTRAP));
    tracee_preinit(task)?;
    ptrace::write(task.pid, regs.rip as ptrace::AddressType, saved as *mut libc::c_void)?;
    ptrace::cont(task.pid, None)?;
    task.reset();
    Ok(())
}

fn handle_ptrace_signal(task: &mut TracedTask) -> Result<()> {
    task.cont()
}

fn handle_ptrace_event(tasks: &mut tasks::TracedTasks, pid: unistd::Pid, raw_event: i32) -> Result<(bool, i64)>{
    let mut task = tasks.get_mut(pid);
    if raw_event == ptrace::Event::PTRACE_EVENT_FORK as i32 {
        let child = do_ptrace_fork(&mut task)?;
        tasks.add(child)?;
    } else if raw_event == ptrace::Event::PTRACE_EVENT_VFORK as i32 {
        let child = do_ptrace_vfork(&mut task)?;
        tasks.add(child)?;
    } else if raw_event == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
        let child = do_ptrace_clone(&mut task)?;
        tasks.add(child)?;
    } else if raw_event == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
        do_ptrace_exec(&mut task).map_err(from_nix_error)?;
    } else if raw_event == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i32 {
        do_ptrace_vfork_done(&mut task)?;
    } else if raw_event == ptrace::Event::PTRACE_EVENT_EXIT as i32 {
        let sig = task.signal_to_deliver;
        task.reset();
        tasks.remove(pid)?;
        let retval = ptrace::getevent(pid).expect("ptrace getevent");
        ptrace::step(pid, sig).expect("ptrace cont");
        assert_eq!(wait::waitpid(Some(pid), None), Ok(WaitStatus::Exited(pid, 0)));
        if tasks.len() == 0 {
            return Ok((true, retval as i64));
        }
    } else if raw_event == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
        do_ptrace_seccomp(&mut task)?;
    } else {
        panic!("unknown ptrace event: {:x}", raw_event);
    }
    Ok((false, 0))
}

fn handle_ptrace_syscall(task: &mut TracedTask) -> Result<()>{
    panic!("handle_ptrace_syscall, pid: {}", task.pid);
}

fn wait_sigstop(pid: unistd::Pid) -> Result<()> {
    match wait::waitpid(Some(pid), None).expect("waitpid failed") {
        WaitStatus::Stopped(new_pid, signal) if signal == signal::SIGSTOP && new_pid == pid =>
            Ok(()),
        _ => Err(Error::new(ErrorKind::Other, "expect SIGSTOP")),
    }
}

fn run_tracer_main(tasks: &mut tasks::TracedTasks) -> Result<i32> {
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
            Ok(WaitStatus::PtraceEvent(pid, signal, event)) if signal == signal::SIGTRAP => {
                let (exit_loop, exit_code) = handle_ptrace_event(tasks, pid, event)?;
                if exit_loop {
                    return Ok(exit_code as i32);
                }
            },
            Ok(WaitStatus::PtraceSyscall(pid)) =>
                handle_ptrace_syscall(tasks.get_mut(pid))?,
            Ok(WaitStatus::Stopped(pid, sig)) => {
                let mut task = tasks.get_mut(pid);
                if sig == signal::SIGSTOP {
                    task.cont()?;
                } else {
                    task.signal_to_deliver = Some(sig);
                    handle_ptrace_signal(&mut task)?;
                }
            },
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
        ForkResult::Parent{child} => {
            // wait for sigstop
            wait_sigstop(child)?;
            ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACEEXEC
                               | ptrace::Options::PTRACE_O_EXITKILL
                               | ptrace::Options::PTRACE_O_TRACECLONE
                               | ptrace::Options::PTRACE_O_TRACEFORK
                               | ptrace::Options::PTRACE_O_TRACEVFORK
                               | ptrace::Options::PTRACE_O_TRACEVFORKDONE
                               | ptrace::Options::PTRACE_O_TRACEEXIT
                               | ptrace::Options::PTRACE_O_TRACESECCOMP
                               | ptrace::Options::PTRACE_O_TRACESYSGOOD)
                .map_err(|e|Error::new(ErrorKind::Other, e))?;
            ptrace::cont(child, None).map_err(|e|Error::new(ErrorKind::Other, e))?;
            let tracee = remote::TracedTask::new(child);
            let mut tasks = tasks::TracedTasks::new();
            tasks.add(tracee)?;
            run_tracer_main(&mut tasks)
        },
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
                Ok(wait::WaitStatus::Signaled(_, sig, _)) =>
                    Ok(0x80 | sig as i32),
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
