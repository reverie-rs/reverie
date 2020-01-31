/*
 * Copyright (c) 2018-2019, Trustees of Indiana University
 *     ("University Works" via Baojun Wang)
 * Copyright (c) 2018-2019, Ryan Newton
 *     ("Traditional Works of Scholarship")
 *
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree.
 */

#![allow(unused_imports)]
#![allow(dead_code)]

#[macro_use]
extern crate lazy_static;

mod util;

use fern;
use libc;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::sys::wait::WaitStatus;
use nix::sys::{memfd, mman, ptrace, signal, wait};
use nix::unistd;
use nix::unistd::ForkResult;
use std::collections::HashMap;
use std::env;
use std::ffi::CString;
use std::io::{self, Error, ErrorKind};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use structopt::{clap::AppSettings, StructOpt};

use reverie_api::event::*;
use reverie_api::remote::*;
use reverie_api::task::*;

use reverie::reverie_common::{consts, state::*};
use reverie::sched_wait::SchedWait;
use reverie::{hooks, ns};

#[test]
fn can_resolve_syscall_hooks() -> io::Result<()> {
    let so = PathBuf::from("../lib").join("libecho.so").canonicalize()?;
    let parsed = hooks::resolve_syscall_hooks_from(so)?;
    assert_ne!(parsed.len(), 0);
    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(about)]
struct Arguments {
    /// Set debug level [0...5].
    #[structopt(
        long = "debug",
        value_name = "DEBUG_LEVEL",
        default_value = "0"
    )]
    log_level: u32,

    /// Preloader tool.
    #[structopt(
        long,
        value_name = "PRELOADER",
        parse(try_from_str = std::fs::canonicalize)
    )]
    preloader: PathBuf,

    /// Tool to run.
    #[structopt(
        long,
        value_name = "tool",
        parse(try_from_str = std::fs::canonicalize)
    )]
    tool: PathBuf,

    /// Do not pass-through host's environment variables.
    #[structopt(long = "no-host-envs")]
    host_envs: bool,

    /// Sets an environment variable. Can be used multiple times.
    #[structopt(
        long = "env",
        short = "e",
        value_name = "ENV[=VALUE]",
        parse(try_from_str = util::parse_env),
        number_of_values = 1
    )]
    envs: Vec<(String, String)>,

    /// Enables namespaces, including PID, USER, MOUNT... default is false.
    #[structopt(long = "with-namespace")]
    namespaces: bool,

    /// Configures how to do logging.
    #[structopt(long = "with-log", value_name = "OUTPUT")]
    log_output: Option<String>,

    /// Do not match any syscalls. Handle all syscalls by seccomp.
    #[structopt(long)]
    disable_monkey_patcher: bool,

    /// Shows reverie software performance counter statistics (--debug must be
    /// >=3).
    #[structopt(long)]
    show_perf_stats: bool,

    /// Name of the program to trace.
    #[structopt(value_name = "PROGRAM")]
    program: String,

    /// Arguments to the program to trace.
    #[structopt(value_name = "ARGS")]
    program_args: Vec<String>,
}

fn run_tracer_main<G>(sched: &mut SchedWait<G>) -> i32 {
    sched.run_all()
}

fn wait_sigstop(pid: unistd::Pid) -> io::Result<()> {
    match wait::waitpid(Some(pid), None).expect("waitpid failed") {
        WaitStatus::Stopped(new_pid, signal)
            if signal == signal::SIGSTOP && new_pid == pid =>
        {
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::Other, "expect SIGSTOP")),
    }
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(ErrorKind::Other, err)
}

// hardcoded because `libc` does not export
const PER_LINUX: u64 = 0x0;
const ADDR_NO_RANDOMIZE: u64 = 0x0004_0000;

fn tracee_init_signals() {
    unsafe {
        let _ = signal::sigaction(
            signal::SIGTTIN,
            &signal::SigAction::new(
                signal::SigHandler::SigIgn,
                signal::SaFlags::SA_RESTART,
                signal::SigSet::empty(),
            ),
        );
        let _ = signal::sigaction(
            signal::SIGTTOU,
            &signal::SigAction::new(
                signal::SigHandler::SigIgn,
                signal::SaFlags::SA_RESTART,
                signal::SigSet::empty(),
            ),
        );
    };
}

fn run_tracee(argv: &Arguments) -> io::Result<i32> {
    let libs: Vec<_> = vec![&argv.preloader];
    let ldpreload = String::from("LD_PRELOAD=")
        + &libs
            .iter()
            .map(|p| p.to_str().unwrap())
            .collect::<Vec<_>>()
            .join(":");

    unsafe {
        assert!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        assert!(libc::personality(PER_LINUX | ADDR_NO_RANDOMIZE) != -1);
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
        if v.is_empty() {
            envs.push(k.to_string())
        } else {
            envs.push(format!("{}={}", k, v));
        }
    });

    envs.push(ldpreload);
    let program = CString::new(argv.program.as_str())?;
    let mut args: Vec<CString> = Vec::new();
    args.push(program.clone());
    for v in argv.program_args.clone() {
        CString::new(v).map(|s| args.push(s))?;
    }
    let envp: Vec<CString> = envs
        .into_iter()
        .map(|s| CString::new(s.as_bytes()).unwrap())
        .collect();

    log::info!(
        "[main] launching: {} {:?}",
        &argv.program,
        &argv.program_args
    );
    unistd::execvpe(&program, args.as_slice(), envp.as_slice())
        .map_err(from_nix_error)?;
    panic!("exec failed: {} {:?}", &argv.program, &argv.program_args);
}

fn show_perf_stats(state: &ReverieState) {
    log::info!("Reverie global statistics (tracer + tracees):");
    let lines: Vec<String> =
        format!("{:#?}", state).lines().map(String::from).collect();
    for s in lines.iter().take(lines.len() - 1).skip(1) {
        log::info!("{}", s);
    }

    let syscalls = state.stats.nr_syscalls.load(Ordering::SeqCst);
    let syscalls_ptraced =
        state.stats.nr_syscalls_ptraced.load(Ordering::SeqCst);
    let syscalls_captured =
        state.stats.nr_syscalls_captured.load(Ordering::SeqCst);
    let syscalls_patched =
        state.stats.nr_syscalls_patched.load(Ordering::SeqCst);

    log::info!(
        "syscalls ptraced (slow): {:.2}%",
        100.0 * syscalls_ptraced as f64 / syscalls as f64
    );
    log::info!(
        "syscalls captured(w/ patching): {:.2}%",
        100.0 * syscalls_captured as f64 / syscalls as f64
    );
    log::info!(
        "syscalls captured(wo/ patching): {:.2}%",
        100.0 * (syscalls_captured - syscalls_patched) as f64 / syscalls as f64
    );
}

fn task_exec_cb(task: &mut dyn Task) -> io::Result<()> {
    log::trace!("[pid {}] exec cb", task.gettid());
    if let Some(init_proc_state) =
        task.resolve_symbol_address("init_process_state")
    {
        let args = SyscallArgs::from(0, 0, 0, 0, 0, 0);
        task.inject_funcall(init_proc_state, &args);
    }
    Ok(())
}
fn task_fork_cb(task: &mut dyn Task) -> io::Result<()> {
    log::trace!("[pid {}] fork cb", task.gettid());
    if let Some(init_proc_state) =
        task.resolve_symbol_address("init_process_state")
    {
        let args = SyscallArgs::from(0, 0, 0, 0, 0, 0);
        task.inject_funcall(init_proc_state, &args);
    }
    Ok(())
}
fn task_clone_cb(task: &mut dyn Task) -> io::Result<()> {
    log::trace!("[pid {}] clone cb", task.gettid());
    Ok(())
}
fn task_exit_cb(_exit_code: i32) -> io::Result<()> {
    Ok(())
}

fn run_tracer(
    starting_pid: unistd::Pid,
    starting_uid: unistd::Uid,
    starting_gid: unistd::Gid,
    argv: &Arguments,
) -> io::Result<i32> {
    // tracer is the 1st process in the new namespace.
    if argv.namespaces {
        ns::init_ns(starting_pid, starting_uid, starting_gid)?;
        debug_assert!(unistd::getpid() == unistd::Pid::from_raw(1));
    }

    let memfd_name = std::ffi::CStr::from_bytes_with_nul(&[
        b'r', b'e', b'v', b'e', b'r', b'i', b'e', 0,
    ])
    .unwrap();
    let fd_ = memfd::memfd_create(&memfd_name, memfd::MemFdCreateFlag::empty())
        .expect("memfd_create failed");
    let memfd = unistd::dup2(fd_, consts::REVERIE_GLOBAL_STATE_FD)
        .expect("dup2 to REVERIE_GLOBAL_STATE_FD failed");
    let _ = unistd::close(fd_);
    let glob_size = 32768 * 4096;
    let _ = unistd::ftruncate(memfd, 32768 * 4096)
        .expect(&format!("memfd, unable to alloc {} bytes.", glob_size));

    match unistd::fork().expect("fork failed") {
        ForkResult::Child => run_tracee(argv),
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
            ptrace::cont(child, None)
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            let tracee = Task::new(child);
            let cbs = TaskEventCB::new(
                Box::new(task_exec_cb),
                Box::new(task_fork_cb),
                Box::new(task_clone_cb),
                Box::new(task_exit_cb),
            );
            let mut sched: SchedWait<i32> = SchedWait::new(cbs, 0);
            sched.add(tracee);
            let res = run_tracer_main(&mut sched);
            if argv.show_perf_stats {
                let _ = reverie_global_state().lock().as_ref().and_then(|st| {
                    show_perf_stats(st);
                    Ok(())
                });
            }
            Ok(res)
        }
    }
}

fn run_app(argv: &Arguments) -> io::Result<i32> {
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
            ForkResult::Child => {
                run_tracer(starting_pid, starting_uid, starting_gid, argv)
            }
            ForkResult::Parent { child } => {
                match wait::waitpid(Some(child), None) {
                    Ok(wait::WaitStatus::Exited(_, exit_code)) => Ok(exit_code),
                    Ok(wait::WaitStatus::Signaled(_, sig, _)) => {
                        Ok(0x80 | sig as i32)
                    }
                    otherwise => panic!(
                        "unexpected status from waitpid: {:?}",
                        otherwise
                    ),
                }
            }
        }
    } else {
        run_tracer(starting_pid, starting_uid, starting_gid, argv)
    }
}

fn populate_rpath(hint: Option<&str>, so: &str) -> io::Result<PathBuf> {
    let mut exe_path = env::current_exe()?;
    exe_path.pop();
    let search_path = vec![PathBuf::from("."), PathBuf::from("lib"), exe_path];
    let rpath = match hint {
        Some(path) => PathBuf::from(path).canonicalize().ok(),
        None => search_path
            .iter()
            .find(|p| match p.join(so).canonicalize() {
                Ok(fp) => fp.exists(),
                Err(_) => false,
            })
            .cloned(),
    };
    log::trace!("[main] library search path: {:?}", search_path);
    log::info!("[main] library-path chosen: {:?}", rpath);
    rpath.ok_or_else(|| {
        Error::new(ErrorKind::NotFound, "cannot find a valid library path")
    })
}

#[paw::main]
fn main(args: Arguments) {
    setup_logger(args.log_level, args.log_output.as_ref().map(|s| s.as_ref()))
        .expect("set log level");

    std::env::set_var(consts::REVERIE_TRACEE_PRELOAD, args.tool.as_os_str());
    match run_app(&args) {
        Ok(exit_code) => std::process::exit(exit_code),
        err => panic!("run app failed with error: {:?}", err),
    }
}

fn fern_with_output(output: Option<&str>) -> io::Result<fern::Dispatch> {
    match output {
        None => Ok(fern::Dispatch::new().chain(std::io::stdout())),
        Some(s) => match s {
            "stdout" => Ok(fern::Dispatch::new().chain(std::io::stdout())),
            "stderr" => Ok(fern::Dispatch::new().chain(std::io::stderr())),
            output => {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .open(output)?;
                Ok(fern::Dispatch::new().chain(f))
            }
        },
    }
}

fn setup_logger(level: u32, output: Option<&str>) -> io::Result<()> {
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
