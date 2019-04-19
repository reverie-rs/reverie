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
use nix::sys::mman;
use nix::sys::stat::Mode;
use nix::fcntl::{OFlag};
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::sync::atomic::{Ordering, AtomicUsize};
use std::env;

use systrace::{ns, consts, task, hooks};
use systrace::sched::Scheduler;
use systrace::sched_wait::SchedWait;
use systrace::task::{RunTask, Task};
use systrace::state::SystraceState;
use systrace::state_tracer::*;

// install seccomp-bpf filters
extern "C" {
    fn bpf_install();
}

#[test]
fn can_resolve_syscall_hooks() -> Result<()> {
    let so = PathBuf::from("target").join("debug").join("libecho.so").canonicalize()?;
    let parsed = hooks::resolve_syscall_hooks_from(so)?;
    assert_ne!(parsed.len(), 0);
    Ok(())
}

#[test]
fn libtrampoline_trampoline_within_first_page() -> Result<()> {
    let so = PathBuf::from("target").join("debug").join("libecho.so").canonicalize()?;
    let parsed = hooks::resolve_syscall_hooks_from(so)?;
    let filtered: Vec<_> = parsed.iter().filter(|hook| hook.offset < 0x10000).collect();
    assert_eq!(parsed.len(), filtered.len());
    Ok(())
}

struct Arguments<'a> {
    debug_level: i32,
    tool_path: PathBuf,
    host_envs: bool,
    envs: HashMap<String, String>,
    namespaces: bool,
    output: Option<&'a str>,
    disable_monkey_patcher: bool,
    show_perf_stats: bool,
    program: &'a str,
    program_args: Vec<&'a str>,
}

fn run_tracer_main(sched: &mut SchedWait) -> i32 {
    sched.event_loop()
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
    let tool = &argv.tool_path;
    let libs: Vec<_> = vec![tool];
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

    log::info!("[main] launching: {} {:?}", &argv.program, &argv.program_args);
    // install seccomp-bpf filters
    // NB: the only syscall beyond this point should be
    // execvpe only.
    unsafe { bpf_install() };

    unistd::execvpe(&program, args.as_slice(), envp.as_slice()).map_err(from_nix_error)?;
    panic!("exec failed: {} {:?}", &argv.program, &argv.program_args);
}

fn show_perf_stats(state: &SystraceState) {
    log::info!("Systrace global statistics (tracer + tracees):");
    let lines: Vec<String> = format!("{:#?}", state)
        .lines()
        .map(|s| String::from(s))
        .collect();
    for i in 1..lines.len()-1 {
        log::info!("{}", lines[i]);
    }

    let syscalls = state.nr_syscalls.load(Ordering::SeqCst);
    let syscalls_ptraced = state.nr_syscalls_ptraced.load(Ordering::SeqCst);
    let syscalls_captured = state.nr_syscalls_captured.load(Ordering::SeqCst);
    let syscalls_patched = state.nr_syscalls_patched.load(Ordering::SeqCst);

    log::info!("syscalls ptraced (slow): {:.2}%",
               100.0 * syscalls_ptraced as f64 / syscalls as f64);
    log::info!("syscalls captured(w/ patching): {:.2}%",
               100.0 * syscalls_captured as f64 / syscalls as f64);
    log::info!("syscalls captured(wo/ patching): {:.2}%",
               100.0 * (syscalls_captured - syscalls_patched) as f64
               / syscalls as f64);
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
            ).map_err(|e| Error::new(ErrorKind::Other, e))?;
            ptrace::cont(child, None).map_err(|e| Error::new(ErrorKind::Other, e))?;
            let tracee = task::Task::new(child);
            let mut sched: SchedWait = Scheduler::new();
            sched.add(tracee);
            let res = run_tracer_main(&mut sched);
            if argv.show_perf_stats {
                let state = get_systrace_state();
                show_perf_stats(state);
            }
            Ok(res)
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

fn populate_rpath(hint: Option<&str>, so: &str) -> Result<PathBuf> {
    let mut exe_path = env::current_exe()?;
    exe_path.pop();
    let search_path = vec![PathBuf::from("."), PathBuf::from("lib"), exe_path];
    let rpath = match hint {
        Some(path) => PathBuf::from(path).canonicalize().ok(),
        None => search_path
            .iter()
            .find(|p| {
                match p.join(so).canonicalize() {
                    Ok(fp) => fp.exists(),
                    Err(_) => false,
                }
            })
            .map(|p| p.clone()),
    };
    log::trace!("[main] library search path: {:?}", search_path);
    log::info!("[main] library-path chosen: {:?}", rpath);
    rpath.ok_or(Error::new(ErrorKind::NotFound, "cannot find a valid library path"))
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
                .help("set library search path for systrace libraries such as libsystrace-trampoline.so")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tool")
                .long("tool")
                .value_name("TOOL")
                .help("choose which tool (/path/to/lib<TOOL>.so) to run, default to none (libnone.so) if not specified. ")
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
                .help("set environment variables, can be used multiple times")
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
        .arg(Arg::with_name("disable-monkey-patcher")
             .long("disable-monkey-patcher")
             .help("do not patch any syscalls, handle all syscalls by seccomp")
             .takes_value(false)
        )
        .arg(Arg::with_name("show-perf-stats")
             .long("show-perf-stats")
             .help("show systrace softare performance counter statistics, --debug must be >= 3")
             .takes_value(false)
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

    let log_level = matches
        .value_of("debug")
        .and_then(|x| x.parse::<i32>().ok())
        .unwrap_or(0);
    let log_output = matches.value_of("with-log");
    setup_logger(log_level, log_output).expect("set log level");

    let tool = matches
        .value_of("tool")
        .expect("[main] tool not specified, default to none");

    let tool_path = PathBuf::from(tool)
        .canonicalize()
        .expect(&format!("[main] cannot locate {}", tool));

    let argv = Arguments {
        debug_level: log_level,
        tool_path: tool_path.clone(),
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
        output: log_output,
        disable_monkey_patcher: matches.is_present("disable-monkey-patcher"),
        show_perf_stats: matches.is_present("show-perf-stats"),
        program: matches.value_of("program").unwrap_or(""),
        program_args: matches
            .values_of("program_args")
            .map(|v| v.collect())
            .unwrap_or_else(|| Vec::new()),
    };

    std::env::set_var(consts::SYSTRACE_TRACEE_PRELOAD, tool_path.as_os_str());
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
                let f = std::fs::OpenOptions::new()
                    .write(true).truncate(true).create(true).open(output)?;
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
