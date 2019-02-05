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
mod proc;
mod task;
mod sched;
mod traced_task;
mod sched_wait;

use remote::*;
use task::{Task, RunTask};
use traced_task::{TracedTask};
use sched_wait::SchedWait;
use sched::Scheduler;

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

fn run_tracer_main(sched: &mut SchedWait) -> Result<i32> {
    let mut exit_code = 0i32;
    while let Some(task) = sched.next() {
        let run_result = task.run()?;
        match run_result {
            RunTask::Exited(_code) => exit_code = _code,
            RunTask::Runnable(task1) => sched.add(task1),
            RunTask::Forked(run_first, run_second) => {
                sched.add(run_first);
                sched.add(run_second);
            },
        }
    };
    Ok(exit_code)
}

fn wait_sigstop(pid: unistd::Pid) -> Result<()> {
    match wait::waitpid(Some(pid), None).expect("waitpid failed") {
        WaitStatus::Stopped(new_pid, signal) if signal == signal::SIGSTOP && new_pid == pid =>
            Ok(()),
        _ => Err(Error::new(ErrorKind::Other, "expect SIGSTOP")),
    }
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(ErrorKind::Other, err)
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
                      "TERM=linux",
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
            let tracee = task::Task::new(child);
            let mut sched: SchedWait = Scheduler::new();
            sched.add(tracee);
            run_tracer_main(&mut sched)
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
