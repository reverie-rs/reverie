#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

use clap::{App, Arg};
use fern;
use libc;
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, wait};
use nix::unistd;
use nix::unistd::ForkResult;
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::env;

mod consts;
mod hooks;
mod nr;
mod ns;
mod proc;
mod remote;
mod remote_rwlock;
mod sched;
mod sched_wait;
mod stubs;
mod vdso;
mod task;
mod traced_task;

use sched::Scheduler;
use sched_wait::SchedWait;
use task::{RunTask, Task};

// install seccomp-bpf filters
extern "C" {
    fn bpf_install();
}

#[test]
fn can_resolve_syscall_hooks() -> Result<()> {
    let library_path = PathBuf::from("target").join("debug");
    let parsed = hooks::resolve_syscall_hooks_from(library_path.join(consts::LIBTRAMPOLINE_SO))?;
    assert_ne!(parsed.len(), 0);
    Ok(())
}

#[test]
fn libtrampoline_trampoline_within_first_page() -> Result<()> {
    let library_path = PathBuf::from("target").join("debug");
    let parsed = hooks::resolve_syscall_hooks_from(library_path.join(consts::LIBTRAMPOLINE_SO))?;
    let filtered: Vec<_> = parsed.iter().filter(|hook| hook.offset < 0x1000).collect();
    assert_eq!(parsed.len(), filtered.len());
    Ok(())
}

struct Arguments<'a> {
    debug_level: i32,
    library_path: PathBuf,
    tool_name: &'a str,
    host_envs: bool,
    envs: HashMap<String, String>,
    namespaces: bool,
    output: Option<&'a str>,
    program: &'a str,
    program_args: Vec<&'a str>,
}

fn run_tracer_main(sched: &mut SchedWait) -> Result<i32> {
    let mut exit_code = 0i32;
    while let Some(task) = sched.next() {
        let run_result = task.run()?;
        match run_result {
            RunTask::Exited(_code) => exit_code = _code,
            RunTask::Blocked(task1) => {
                sched.add_blocked(task1);
            }
            RunTask::Runnable(task1) => {
                sched.add_and_schedule(task1);
            }
            RunTask::Forked(parent, child) => {
                sched.add(child);
                sched.add_and_schedule(parent);
            }
        }
    }
    Ok(exit_code)
}

fn wait_sigstop(pid: unistd::Pid) -> Result<()> {
    match wait::waitpid(Some(pid), None).expect("waitpid failed") {
        WaitStatus::Stopped(new_pid, signal) if signal == signal::SIGSTOP && new_pid == pid => {
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::Other, "expect SIGSTOP")),
    }
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(ErrorKind::Other, err)
}

// hardcoded because `libc` does not export
const ADDR_NO_RANDOMIZE: u64 = 0x0040000;

fn tracee_init_signals() {
    unsafe {
        let _ = signal::sigaction(signal::SIGTTIN, &signal::SigAction::new(
            signal::SigHandler::SigIgn,
            signal::SaFlags::SA_RESTART,
            signal::SigSet::empty()));
        let _ = signal::sigaction(signal::SIGTTOU, &signal::SigAction::new(
            signal::SigHandler::SigIgn,
            signal::SaFlags::SA_RESTART,
            signal::SigSet::empty()));
    };
}

fn run_tracee(argv: &Arguments) -> Result<i32> {
    let library_path = &argv.library_path;
    let tool = library_path.join(&argv.tool_name);
    let so = library_path.join(consts::LIBTRAMPOLINE_SO);
    let libs: Vec<PathBuf> = vec![tool, so];
    let ldpreload = String::from("LD_PRELOAD=")
        + &libs
            .iter()
            .map(|p| p.to_str().unwrap())
            .collect::<Vec<_>>()
            .join(":");

    unsafe {
        assert!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        assert!(libc::personality(ADDR_NO_RANDOMIZE) != -1);
    };

    ptrace::traceme()
        .and_then(|_| signal::raise(signal::SIGSTOP))
        .map_err(from_nix_error)?;

    tracee_init_signals();
    // println!("launching program: {} {:?}", &argv.program, &argv.program_args);

    // install seccomp-bpf filters
    // NB: the only syscall beyond this point should be
    // execvpe only.
    unsafe { bpf_install() };

    let mut envs: Vec<String> = Vec::new();

    if argv.host_envs {
        std::env::vars().for_each(|(k, v)| {
            envs.push(format!("{}={}", k, v));
        });
    } else {
        envs.push(String::from("PATH=/bin/:/usr/bin"));
    }

    argv.envs.iter().for_each(|(k, v)| {
        if v.len() == 0 {
            envs.push(k.to_string())
        } else {
            envs.push(format!("{}={}", k, v));
        }
    });

    envs.push(ldpreload);
    let program = CString::new(argv.program)?;
    let mut args: Vec<CString> = Vec::new();
    CString::new(argv.program).map(|s| args.push(s))?;
    for v in argv.program_args.clone() {
        CString::new(v).map(|s| args.push(s))?;
    }
    let envp: Vec<CString> = envs
        .into_iter()
        .map(|s| CString::new(s.as_bytes()).unwrap())
        .collect();
    unistd::execvpe(&program, args.as_slice(), envp.as_slice()).map_err(from_nix_error)?;
    panic!("exec failed: {} {:?}", &argv.program, &argv.program_args);
}

fn run_tracer(
    starting_pid: unistd::Pid,
    starting_uid: unistd::Uid,
    starting_gid: unistd::Gid,
    argv: &Arguments,
) -> Result<i32> {
    // tracer is the 1st process in the new namespace.
    if argv.namespaces {
        ns::init_ns(starting_pid, starting_uid, starting_gid)?;
        debug_assert!(unistd::getpid() == unistd::Pid::from_raw(1));
    }

    match unistd::fork().expect("fork failed") {
        ForkResult::Child => {
            return run_tracee(argv);
        }
        ForkResult::Parent { child } => {
            // wait for sigstop
            wait_sigstop(child)?;
            ptrace::setoptions(
                child,
                ptrace::Options::PTRACE_O_TRACEEXEC
                    | ptrace::Options::PTRACE_O_EXITKILL
                    | ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORK
                    | ptrace::Options::PTRACE_O_TRACEVFORKDONE
                    | ptrace::Options::PTRACE_O_TRACEEXIT
                    | ptrace::Options::PTRACE_O_TRACESECCOMP
                    | ptrace::Options::PTRACE_O_TRACESYSGOOD,
            )
            .map_err(|e| Error::new(ErrorKind::Other, e))?;
            ptrace::cont(child, None).map_err(|e| Error::new(ErrorKind::Other, e))?;
            let tracee = task::Task::new(child);
            let mut sched: SchedWait = Scheduler::new();
            sched.add(tracee);
            run_tracer_main(&mut sched)
        }
    }
}

fn run_app(argv: &Arguments) -> Result<i32> {
    let (starting_pid, starting_uid, starting_gid) =
        (unistd::getpid(), unistd::getuid(), unistd::getgid());

    if argv.namespaces {
        unsafe {
            assert!(
                libc::unshare(
                    libc::CLONE_NEWUSER
                        | libc::CLONE_NEWPID
                        | libc::CLONE_NEWNS
                        | libc::CLONE_NEWUTS
                ) == 0
            );
        };

        match unistd::fork().expect("fork failed") {
            ForkResult::Child => run_tracer(starting_pid, starting_uid, starting_gid, argv),
            ForkResult::Parent { child } => match wait::waitpid(Some(child), None) {
                Ok(wait::WaitStatus::Exited(_, exit_code)) => Ok(exit_code),
                Ok(wait::WaitStatus::Signaled(_, sig, _)) => Ok(0x80 | sig as i32),
                otherwise => panic!("unexpected status from waitpid: {:?}", otherwise),
            },
        }
    } else {
        run_tracer(starting_pid, starting_uid, starting_gid, argv)
    }
}

fn main() {
    let matches = App::new("systrace - a fast syscall tracer and interceper")
        .version("0.0.1")
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .value_name("DEBUG_LEVEL")
                .help("Set debug level [0..5]")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("library-path")
                .long("library-path")
                .value_name("LIBRARY_PATH")
                .help("set library search path for libtrampoline.so, libTOOL.so")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tool")
                .long("tool")
                .value_name("TOOL")
                .help("choose which tool (libTOOL.so) to run")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("no-host-envs")
                .long("no-host-envs")
                .help("do not pass-through host's environment variables")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("env")
                .long("env")
                .value_name("ENV=VALUE")
                .multiple(true)
                .help("set environment variables, allow using multiple times")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("with-namespace")
                .long("with-namespace")
                .help("enable namespaces, including PID, USER, MOUNT.. default is false")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("with-log")
                .long("with-log")
                .value_name("OUTPUT")
                .help("with-log=[filename|stdout|stderr], default is stdout")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("program")
                .value_name("PROGRAM")
                .required(true)
                .help("PROGRAM")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("program_args")
                .value_name("PROGRAM_ARGS")
                .allow_hyphen_values(true)
                .multiple(true)
                .help("[PROGRAM_ARGUMENTS..]"),
        )
        .get_matches();

    let rpath = match matches.value_of("library-path") {
        Some(path) => PathBuf::from(path).canonicalize(),
        None => PathBuf::from("lib")
            .canonicalize()
            .or_else(|_| PathBuf::from(".").canonicalize()),
    }.expect("invalid library-path");

    let argv = Arguments {
        debug_level: matches
            .value_of("debug")
            .and_then(|x| x.parse::<i32>().ok())
            .unwrap_or(0),
        tool_name: matches.value_of("tool").unwrap(),
        library_path: rpath,
        host_envs: !matches.is_present("-no-host-envs"),
        envs: matches
            .values_of("env")
            .unwrap_or_default()
            .map(|s| {
                let t: Vec<&str> = s.clone().split('=').collect();
                debug_assert!(t.len() > 0);
                (t[0].to_string(), t[1..].join("="))
            })
            .collect(),
        namespaces: matches.is_present("with-namespace"),
        output: matches.value_of("with-log"),
        program: matches.value_of("program").unwrap_or(""),
        program_args: matches
            .values_of("program_args")
            .map(|v| v.collect())
            .unwrap_or_else(|| Vec::new()),
    };

    setup_logger(argv.debug_level, argv.output).expect("set log level");
    std::env::set_var(consts::LIBTRAMPOLINE_LIBRARY_PATH, &argv.library_path);
    match run_app(&argv) {
        Ok(exit_code) => std::process::exit(exit_code),
        err => panic!("run app failed with error: {:?}", err),
    }
}

fn fern_with_output<'a>(output: Option<&'a str>) -> Result<fern::Dispatch> {
    match output {
        None => {
                Ok(fern::Dispatch::new()
                    .chain(std::io::stdout()))
        }
        Some(s) => match s {
            "stdout" => {
                Ok(fern::Dispatch::new()
                    .chain(std::io::stdout()))
            }
            "stderr" => {
                Ok(fern::Dispatch::new()
                    .chain(std::io::stderr()))

            }
            output   => {
                let f = fern::log_file(output)?;
                Ok(fern::Dispatch::new()
                   .chain(f))
            }
        }
    }
}

fn setup_logger<'a>(level: i32, output: Option<&'a str>) -> Result<()> {
    let log_level = match level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        5 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Trace,
    };

    fern_with_output(output)?
        .level(log_level)
        .format(|out, message, _record| out.finish(format_args!("{}", message)))
        .apply()
        .map_err(|e| Error::new(ErrorKind::Other, e))
}
