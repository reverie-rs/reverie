#![allow(unused_imports)]
#![allow(dead_code)]

#![allow(unreachable_code)]
#![allow(unused_variables)]

use std::env::{current_exe};
use clap::{Arg, App, SubCommand};
use std::io::{Result, Error, ErrorKind};
use std::path::PathBuf;
use std::ffi::CString;
use nix::unistd::{ForkResult};
use nix::unistd;
use nix::sys::{wait, signal, ptrace};
use nix::sys::wait::{WaitStatus};
use libc;
mod hooks;
mod nr;
mod ns;

// install seccomp-bpf filters
extern {
    fn bpf_install();
}

const SYSTRACE_SO: &'static str = "libsystrace.so";
const DET_SO: &'static str = "libdet.so";

#[test]
fn can_resolve_syscall_hooks () -> Result<()>{
    let parsed = hooks::resolve_syscall_hooks_from(PathBuf::from("src").join(SYSTRACE_SO))?;
    assert_ne!(parsed.len(), 0);
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
    ptrace::cont(pid, sig).map_err(|e| from_nix_error(e))
}

fn do_ptrace_vfork_done(pid: unistd::Pid) -> Result<()> {
    just_continue(pid, None)
}

fn do_ptrace_fork(pid: unistd::Pid) -> Result<()> {
    let child = ptrace::getevent(pid).map_err(|e| from_nix_error(e))?;
    println!("{} has a new child {}", pid, child);
    just_continue(pid, None)
}

fn do_ptrace_seccomp(pid: unistd::Pid) -> Result<()> {
    Ok(())
}

fn handle_ptrace_event(pid: unistd::Pid, raw_event: i32) -> Result<()>{
    if raw_event == ptrace::Event::PTRACE_EVENT_FORK as i32
        || raw_event == ptrace::Event::PTRACE_EVENT_VFORK as i32
        || raw_event == ptrace::Event::PTRACE_EVENT_CLONE as i32 {
            do_ptrace_fork(pid)?;
        } else if raw_event == ptrace::Event::PTRACE_EVENT_EXEC as i32 {
            just_continue(pid, None)?;
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
        .map_err(|e| from_nix_error(e))?;

    // install seccomp-bpf filters
    unsafe { bpf_install() };

    let envp = vec![ "PATH=/bin/:/usr/bin",
    ];

    let program = CString::new(argv.program)?;
    let args: Vec<CString> = argv.program_args.clone().into_iter().map(|s|CString::new(s).unwrap()).collect();
    let envp: Vec<CString> = (vec![ "PATH=/bin:/usr/bin" ]).into_iter().map(|s|CString::new(s).unwrap()).collect();
    println!("launching program: {} {:?}", &argv.program, &argv.program_args);
    unistd::execvpe(&program,
                    args.as_slice(),
                    envp.as_slice())
        .map_err(|e| from_nix_error(e))?;
    unreachable!("exec failed: {} {:?}", &argv.program, &argv.program_args);
    Ok(0)
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
