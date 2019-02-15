use libc;
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd;
use nix::unistd::Pid;
use nix::sys::socket;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::ptr::NonNull;
use std::rc::*;

use crate::consts;
use crate::consts::*;
use crate::hooks;
use crate::nr::*;
use crate::proc::*;
use crate::remote;
use crate::remote::*;
use crate::sched::Scheduler;
use crate::sched_wait::*;
use crate::stubs;
use crate::task::*;

fn libsystrace_load_address(pid: unistd::Pid) -> Option<u64> {
    match ptrace::read(
        pid,
        consts::DET_TLS_SYSCALL_TRAMPOLINE as ptrace::AddressType,
    ) {
        Ok(addr) if addr != 0 => Some(addr as u64 & !0xfff),
        _otherwise => None,
    }
}

lazy_static! {
    static ref SYSCALL_HOOKS: Vec<hooks::SyscallHook> = {
        let systrace_lib_path = std::env::var(consts::SYSTRACE_LIBRARY_PATH).unwrap();
        hooks::resolve_syscall_hooks_from(
            PathBuf::from(systrace_lib_path).join(consts::SYSTRACE_SO),
        )
        .expect(&format!("unable to load {}", consts::SYSTRACE_SO))
    };
}

#[derive(Debug, Clone)]
pub struct TracedTask {
    pub pid: Pid,
    pub ppid: Pid,
    pub tid: Pid,
    pub state: TaskState,
    pub memory_map: Vec<ProcMapsEntry>,
    pub stub_pages: Vec<SyscallStubPage>,
    pub trampoline_hooks: &'static Vec<hooks::SyscallHook>,
    pub ldpreload_address: Option<u64>,
    pub injected_mmap_page: Option<u64>,
    pub signal_to_deliver: Option<signal::Signal>,
    pub unpatchable_syscalls: Vec<u64>,
    pub detsched_connected: bool,
}

impl Task for TracedTask {
    fn new(pid: unistd::Pid) -> Self {
        TracedTask {
            pid,
            ppid: pid,
            tid: pid,
            state: TaskState::Stopped(None),
            memory_map: decode_proc_maps(pid).unwrap_or(Vec::new()),
            stub_pages: Vec::new(),
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: libsystrace_load_address(pid),
            injected_mmap_page: None,
            signal_to_deliver: None,
            unpatchable_syscalls: Vec::new(),
            detsched_connected: false,
        }
    }

    fn exited(&self) -> Option<i32> {
        match &self.state {
            TaskState::Exited(exit_code) => Some(*exit_code as i32),
            _otherwise => None,
        }
    }

    fn getpid(&self) -> Pid {
        self.pid
    }

    fn getppid(&self) -> Pid {
        self.ppid
    }

    fn gettid(&self) -> Pid {
        self.tid
    }

    fn run(self) -> Result<RunTask<TracedTask>> {
        let task = self;
        match task.state {
            TaskState::Running => Ok(RunTask::Runnable(task)),
            TaskState::Signaled(signal) => {
                task.resume(task.signal_to_deliver)?;
                Ok(RunTask::Runnable(task))
            }
            TaskState::Stopped(None) => {
                task.resume(None)?;
                Ok(RunTask::Runnable(task))
            }
            TaskState::Stopped(Some(signal)) => {
                task.resume(Some(signal))?;
                Ok(RunTask::Runnable(task))
            }
            TaskState::Event(ev) => handle_ptrace_event(task),
            TaskState::Exited(exit_code) => Ok(RunTask::Exited(exit_code)),
        }
    }
}

fn task_reset(task: &mut TracedTask) {
    task.memory_map = Vec::new();
    task.stub_pages = Vec::new();
    task.ldpreload_address = None;
    task.injected_mmap_page = Some(0x7000_0000);
    task.signal_to_deliver = None;
    task.unpatchable_syscalls = Vec::new();
    task.state = TaskState::Exited(0);
    task.detsched_connected = false;
}

fn update_memory_map(task: &mut TracedTask) {
    task.memory_map = decode_proc_maps(task.pid).unwrap_or(Vec::new());
}

fn find_syscall_hook(task: &mut TracedTask, rip: u64) -> Result<&'static hooks::SyscallHook> {
    let mut bytes: Vec<u8> = Vec::new();

    for i in 0..=1 {
        let u64_size = std::mem::size_of::<u64>();
        let remote_ptr = RemotePtr::new(
            NonNull::new((rip + i * std::mem::size_of::<u64>() as u64) as *mut u64)
                .expect("null pointer"),
        );
        let u: u64 = task.peek(remote_ptr)?;
        let raw: [u8; std::mem::size_of::<u64>()] = unsafe { std::mem::transmute(u) };
        raw.iter().for_each(|c| bytes.push(*c));
    }

    let mut it = task.trampoline_hooks.iter().filter(|hook| {
        let sequence: &[u8] = &bytes[0..hook.instructions.len()];
        sequence == hook.instructions.as_slice()
    });
    match it.next() {
        None => Err(Error::new(
            ErrorKind::Other,
            format!(
                "unpatchable syscall at {:x}, instructions: {:x?}",
                rip, bytes
            ),
        )),
        Some(found) => Ok(found),
    }
}

pub fn patch_syscall(task: &mut TracedTask, rip: u64) -> Result<()> {
    if task.ldpreload_address.is_none() {
        task.ldpreload_address = libsystrace_load_address(task.pid);
    }
    task.ldpreload_address.ok_or(Error::new(
        ErrorKind::Other,
        format!("libsystrace not loaded"),
    ))?;
    if task
        .unpatchable_syscalls
        .iter()
        .find(|&&pc| pc == rip)
        .is_some()
    {
        return Err(Error::new(
            ErrorKind::Other,
            format!("process {} syscall at {} is not patchable", task.pid, rip),
        ));
    };
    let hook_found = find_syscall_hook(task, rip)?;
    let regs = ptrace::getregs(task.pid).expect("ptrace getregs");
    // NB: when @hook_found, we assuem that we can patch the syscall
    // hence we force kernel skip the pending syscall, by setting
    // syscall no to -1.
    // we should do this as early as possible: because
    // PTRACE_EVENT_SECCOMP is more fragile than general STOP event
    // I.E: doing ptrace_cont after PTRACE_EVENT_SECCOMP has different
    // effect as general stop event (SIGTRAP).
    // if ptrace is stopped by SIGTRAP, it is general safe to do ptrace
    // continue, with the help of breakpoint; but not so with
    // PTRACE_EVENT_SECCOMP, as the kernel might allow previous syscall
    // to run through, this could cause chaotic issues if we rely ptrace
    // cont/breakpoint to control tracee's execution.
    skip_seccomp_syscall(task.pid, regs)?;
    let indirect_jump_address = extended_jump_from_to(task, rip)?;
    let regs = ptrace::getregs(task.pid).expect("ptrace getregs");
    patch_at(task, regs, hook_found, indirect_jump_address).map_err(|e| {
        task.unpatchable_syscalls.push(rip);
        e
    })
}

fn hook_index(task: &mut TracedTask, curr: &hooks::SyscallHook) -> Result<usize> {
    for (k, hook) in task.trampoline_hooks.iter().enumerate() {
        if hook == curr {
            return Ok(k);
        }
    }
    Err(Error::new(
        ErrorKind::Other,
        format!("cannot find syscall hook: {:?}", curr),
    ))
}

fn extended_jump_offset_from_stub_page(
    task: &mut TracedTask,
    curr: &hooks::SyscallHook,
) -> Result<usize> {
    let k = hook_index(task, curr)?;
    Ok(k * stubs::extended_jump_size())
}

// the extended (indirect) jump contains
//     callq *0(rip)
//     .qword trampoline_entry_offset
//     ret
// the the only difference is `trampoline_entry_offset`
// as a result we only need to allocate the extended
// jump stub per `trampoline_entry_offset`, instead of
// per syscall site.
fn extended_jump_from_to(task: &mut TracedTask, rip: u64) -> Result<u64> {
    let hook = find_syscall_hook(task, rip)?;
    let two_gb = 2u64.wrapping_shl(30);
    let page_address = match task.stub_pages.iter().find(|page| {
        let (start, end) = (page.address, page.address + page.size as u64);
        if end <= rip {
            rip - start <= two_gb
        } else if start >= rip {
            start + stubs::extended_jump_pages() as u64 * 0x1000 - rip <= two_gb
        } else {
            false
        }
    }) {
        None => allocate_extended_jumps(task, rip)?,
        Some(stub) => stub.address,
    };
    let offset = extended_jump_offset_from_stub_page(task, hook)?;
    Ok(page_address + offset as u64)
}

// allocate page(s) to store the extended jump stubs
// since the direct jump from the syscall site is a
// `callq extended_jump_stub`, the `extended_jump_stub`
// must be within +/- 2GB of IP.
fn allocate_extended_jumps(task: &mut TracedTask, rip: u64) -> Result<u64> {
    let size = (stubs::extended_jump_pages() * 0x1000) as i64;
    let at = search_stub_page(task.pid, rip, size as usize)? as i64;
    let allocated_at = task.traced_syscall(
        SYS_mmap,
        at,
        size,
        (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as i64,
        (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as i64,
        -1i64,
        0,
    )?;
    assert!(at == allocated_at);

    let preload_address = task.ldpreload_address.ok_or(Error::new(
        ErrorKind::Other,
        format!("{} not loaded", consts::SYSTRACE_SO),
    ))?;
    let stubs = stubs::gen_extended_jump_stubs(task.trampoline_hooks, preload_address);
    task.stub_pages.push(SyscallStubPage {
        address: at as u64,
        size: size as usize,
        allocated: stubs.len(),
    });
    let remote_ptr = RemotePtr::new(NonNull::new(at as *mut u8).expect("null pointer"));
    task.poke_bytes(remote_ptr, stubs.as_slice())?;

    task.untraced_syscall(
        SYS_mprotect,
        allocated_at,
        size,
        (libc::PROT_READ | libc::PROT_EXEC) as i64,
        0,
        0,
        0,
    )?;

    update_memory_map(task);

    Ok(allocated_at as u64)
}

impl Remote for TracedTask {
    fn peek_bytes(&self, addr: RemotePtr<u8>, size: usize) -> Result<Vec<u8>> {
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.as_ptr();
            let x = ptrace::read(self.pid, raw_ptr as ptrace::AddressType).expect("ptrace peek");
            let bytes: [u8; std::mem::size_of::<u64>()] = unsafe { std::mem::transmute(x) };
            let res: Vec<u8> = bytes.iter().cloned().take(size).collect();
            Ok(res)
        } else {
            let raw_ptr = addr.as_ptr();
            let remote_iov = &[uio::RemoteIoVec {
                base: raw_ptr as usize,
                len: size,
            }];
            let mut res = vec![0; size];
            let local_iov = &[uio::IoVec::from_mut_slice(res.as_mut_slice())];
            uio::process_vm_readv(self.pid, local_iov, remote_iov).expect("process_vm_readv");
            Ok(res)
        }
    }

    fn poke_bytes(&self, addr: RemotePtr<u8>, bytes: &[u8]) -> Result<()> {
        let size = bytes.len();
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.as_ptr();
            let mut u64_val = if size < std::mem::size_of::<u64>() {
                ptrace::read(self.pid, raw_ptr as ptrace::AddressType).expect("ptrace peek") as u64
            } else {
                0u64
            };
            let u64_val_ptr: *mut u64 = &mut u64_val;
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const u64, u64_val_ptr, size)
            };
            ptrace::write(
                self.pid,
                raw_ptr as ptrace::AddressType,
                u64_val as *mut libc::c_void,
            )
            .expect("ptrace poke");
            return Ok(());
        } else {
            let raw_ptr = addr.as_ptr();
            let remote_iov = &[uio::RemoteIoVec {
                base: raw_ptr as usize,
                len: size,
            }];
            let local_iov = &[uio::IoVec::from_slice(bytes)];
            uio::process_vm_writev(self.pid, local_iov, remote_iov).expect("process_vm_readv");
            return Ok(());
        }
    }

    fn getregs(&self) -> Result<libc::user_regs_struct> {
        let regs = ptrace::getregs(self.pid).expect(&format!("pid {}: ptrace getregs", self.pid));
        Ok(regs)
    }

    fn setregs(&self, regs: libc::user_regs_struct) -> Result<()> {
        ptrace::setregs(self.pid, regs).expect(&format!("pid {}: ptrace getregs", self.pid));
        Ok(())
    }

    fn resume(&self, sig: Option<signal::Signal>) -> Result<()> {
        ptrace::cont(self.pid, sig).expect(&format!("pid {}: ptrace cont", self.pid));
        Ok(())
    }

    fn getevent(&self) -> Result<i64> {
        let ev = ptrace::getevent(self.pid).expect("pid {}: ptrace getevent");
        Ok(ev)
    }
}

impl RemoteSyscall for TracedTask {
    fn untraced_syscall(
        &mut self,
        nr: SyscallNo,
        a0: i64,
        a1: i64,
        a2: i64,
        a3: i64,
        a4: i64,
        a5: i64,
    ) -> Result<i64> {
        remote_do_syscall_at(self, 0x7000_0008, nr, a0, a1, a2, a3, a4, a5)
    }
    fn traced_syscall(
        &mut self,
        nr: SyscallNo,
        a0: i64,
        a1: i64,
        a2: i64,
        a3: i64,
        a4: i64,
        a5: i64,
    ) -> Result<i64> {
        remote_do_syscall_at(self, 0x7000_0010, nr, a0, a1, a2, a3, a4, a5)
    }
}

// inject syscall for given tracee
// NB: limitations:
// - tracee must be in stopped state.
// - the tracee must have returned from PTRACE_EXEC_EVENT
fn remote_do_syscall_at(
    task: &mut TracedTask,
    rip: u64,
    nr: SyscallNo,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> Result<i64> {
    let pid = task.pid;
    let mut regs = task.getregs()?;
    let oldregs = regs.clone();

    let no = nr as u64;
    regs.orig_rax = no;
    regs.rax = no;
    regs.rdi = a0 as u64;
    regs.rsi = a1 as u64;
    regs.rdx = a2 as u64;
    regs.r10 = a3 as u64;
    regs.r8 = a4 as u64;
    regs.r9 = a5 as u64;

    // instruction at 0x7000_0008 must be
    // callq 0x70000000 (5-bytes)
    // .byte 0xcc
    regs.rip = rip;
    task.setregs(regs)?;
    task.resume(None)?;
    match wait::waitpid(pid, None) {
        Ok(WaitStatus::Stopped(pid, signal::SIGTRAP)) => (),
        Ok(WaitStatus::Stopped(pid, signal::SIGCHLD)) => {
            task.signal_to_deliver = Some(signal::SIGCHLD)
        }
        otherwise => {
            let regs = task.getregs()?;
            panic!("when doing syscall {:?} waitpid {} returned unknown status: {:x?} pc: {:x}", nr, pid, otherwise, regs.rip);
        }
    };
    let newregs = task.getregs()?;
    task.setregs(oldregs)?;
    if newregs.rax as u64 > (-4096i64) as u64 {
        Err(Error::from_raw_os_error(-(newregs.rax as i64) as i32))
    } else {
        Ok(newregs.rax as i64)
    }
}

fn handle_ptrace_signal(task: TracedTask) -> Result<TracedTask> {
    task.resume(task.signal_to_deliver)?;
    Ok(task)
}

fn handle_ptrace_event(mut task: TracedTask) -> Result<RunTask<TracedTask>> {
    let raw_event = match task.state {
        TaskState::Event(ev) => ev as i64,
        otherwise => panic!("task.state = {:x?}", otherwise),
    };
    if raw_event == ptrace::Event::PTRACE_EVENT_FORK as i64 {
        let pair = do_ptrace_fork(task)?;
        Ok(RunTask::Forked(pair.0, pair.1))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_VFORK as i64 {
        let pair = do_ptrace_vfork(task)?;
        Ok(RunTask::Forked(pair.1, pair.0))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_CLONE as i64 {
        let pair = do_ptrace_clone(task)?;
        Ok(RunTask::Forked(pair.0, pair.1))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_EXEC as i64 {
        do_ptrace_exec(&mut task).map_err(from_nix_error)?;
        Ok(RunTask::Runnable(task))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i64 {
        do_ptrace_vfork_done(task).and_then(|tsk| Ok(RunTask::Runnable(tsk)))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_EXIT as i64 {
        let sig = task.signal_to_deliver;
        let retval = task.getevent()?;
        ptrace::step(task.pid, sig).expect("ptrace cont");
        assert_eq!(
            wait::waitpid(Some(task.pid), None),
            Ok(WaitStatus::Exited(task.pid, 0))
        );
        Ok(RunTask::Exited(retval as i32))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_SECCOMP as i64 {
        do_ptrace_seccomp(task).and_then(|tsk| Ok(RunTask::Runnable(tsk)))
    } else {
        panic!("unknown ptrace event: {:x}", raw_event);
        Err(Error::new(
            ErrorKind::Other,
            format!("unknown ptrace event: {:x}", raw_event),
        ))
    }
}

fn handle_ptrace_syscall(task: &mut TracedTask) -> Result<()> {
    panic!("handle_ptrace_syscall, pid: {}", task.pid);
}

fn wait_sigstop(pid: Pid) -> Result<()> {
    match wait::waitpid(Some(pid), None).expect("waitpid failed") {
        WaitStatus::Stopped(new_pid, signal) if signal == signal::SIGSTOP && new_pid == pid => {
            Ok(())
        }
        _ => Err(Error::new(ErrorKind::Other, "expect SIGSTOP")),
    }
}

fn do_ptrace_vfork_done(task: TracedTask) -> Result<TracedTask> {
    let pid = task.pid;
    task.resume(task.signal_to_deliver)?;
    Ok(task)
}

fn do_ptrace_clone(task: TracedTask) -> Result<(TracedTask, TracedTask)> {
    let pid_raw = task.getevent()?;
    task.resume(None)?;
    let child = Pid::from_raw(pid_raw as libc::pid_t);
    let mut new_task = task.clone();
    new_task.pid = child;
    new_task.ppid = task.pid;
    new_task.tid = child;
    let _ = connect_detsched(&mut new_task);
    new_task.resume(None)?;
    Ok((task, new_task))
}

fn do_ptrace_fork(task: TracedTask) -> Result<(TracedTask, TracedTask)> {
    let pid_raw = task.getevent()?;
    task.resume(None)?;
    let child = Pid::from_raw(pid_raw as libc::pid_t);
    let mut new_task = task.clone();
    new_task.pid = child;
    new_task.ppid = task.pid;
    new_task.tid = child;
    let _ = connect_detsched(&mut new_task);
    new_task.resume(None)?;
    Ok((task, new_task))
}

fn do_ptrace_vfork(task: TracedTask) -> Result<(TracedTask, TracedTask)> {
    let pid_raw = task.getevent()?;
    let child = Pid::from_raw(pid_raw as libc::pid_t);
    let mut new_task = task.clone();
    new_task.pid = child;
    new_task.ppid = task.pid;
    new_task.tid = child;
    let _ = connect_detsched(&mut new_task);
    new_task.resume(None)?;
    task.resume(None)?;
    Ok((new_task, task))
}

fn do_ptrace_seccomp(mut task: TracedTask) -> Result<TracedTask> {
    let ev = ptrace::getevent(task.pid).map_err(from_nix_error)?;
    let regs = ptrace::getregs(task.pid).map_err(from_nix_error)?;
    let syscall = SyscallNo::from(regs.orig_rax as i32);
    let mut tsk = &mut task;
    if ev == 0x7fff {
        panic!("unfiltered syscall: {:?}", syscall);
    }
    // println!("seccomp syscall {:?}", syscall);
    match patch_syscall(&mut tsk, regs.rip) {
        Ok(_) => {
            just_continue(task.pid, None)
        }
        Err(_) => {
            just_continue(task.pid, None)
        }
    }?;
    Ok(task)
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(ErrorKind::Other, err)
}

fn just_continue(pid: Pid, sig: Option<signal::Signal>) -> Result<()> {
    ptrace::cont(pid, sig).map_err(from_nix_error)
}

fn tracee_preinit(task: &mut TracedTask) -> nix::Result<()> {
    let mut regs = ptrace::getregs(task.pid)?;
    let mut saved_regs = regs.clone();
    let page_addr = consts::DET_PAGE_OFFSET;
    let page_size = consts::DET_PAGE_SIZE;

    regs.orig_rax = SYS_mmap as u64;
    regs.rax = regs.orig_rax;
    regs.rdi = page_addr;
    regs.rsi = page_size;
    regs.rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    regs.r10 = (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as u64;
    regs.r8 = -1 as i64 as u64;
    regs.r9 = 0 as u64;

    ptrace::setregs(task.pid, regs)?;
    ptrace::cont(task.pid, None)?;

    // second breakpoint after syscall hit
    assert!(
        wait::waitpid(task.pid, None) == Ok(wait::WaitStatus::Stopped(task.pid, signal::SIGTRAP))
    );
    let regs = ptrace::getregs(task.pid).and_then(|r| {
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
    ptrace::write(
        task.pid,
        regs.rip as ptrace::AddressType,
        ((saved & !(0xffffffff as i64)) | bp_syscall_bp) as *mut libc::c_void,
    )?;
    ptrace::cont(task.pid, None)?;
    let wait_status = wait::waitpid(task.pid, None)?;
    assert!(wait_status == wait::WaitStatus::Stopped(task.pid, signal::SIGTRAP));
    tracee_preinit(task)?;
    ptrace::write(
        task.pid,
        regs.rip as ptrace::AddressType,
        saved as *mut libc::c_void,
    )?;
    let conn = connect_detsched(task);
    ptrace::cont(task.pid, None)?;
    task_reset(task);
    task.detsched_connected = conn.is_ok();
    Ok(())
}

// run on tracee not the tracer
// thus tracee must be in STOPPED state.
fn connect_detsched(task: &mut TracedTask) -> Result <()>{
    let unp_path = std::env::var(consts::SYSTRACE_DETSCHED_PATH).unwrap();
    let fd = task.untraced_syscall(
        SYS_socket,
        libc::AF_UNIX as i64,
        (libc::SOCK_STREAM as i64) | (libc::SOCK_CLOEXEC as i64),
        0, 0, 0, 0)?;
    task.untraced_syscall(
        SYS_dup2, fd as i64, consts::DETSCHED_FD as i64,
        0, 0, 0, 0)?;
    task.untraced_syscall(
        SYS_close, fd as i64, 0, 0, 0, 0, 0)?;

    let mut regs = task.getregs()?;
    let rbp = regs.rsp;
    let socklen = std::mem::size_of::<socket::sockaddr_un>();

    // allocate space for sockaddr_un
    regs.rsp -= socklen as u64;
    regs.rsp &= !0xf;

    task.setregs(regs)?;

    let addr = socket::sockaddr_un {
        sun_family: socket::AddressFamily::Unix as u16,
        sun_path: [0; std::mem::size_of::<socket::sockaddr_un>() -
                   std::mem::size_of::<u16>()],
    };

    // fill sun_path
    unsafe {
        std::ptr::copy_nonoverlapping(
            unp_path.as_ptr(),
            addr.sun_path.as_ptr() as *mut u8,
            std::cmp::min(addr.sun_path.len(),
                          unp_path.len())
        );
    };

    let remote_sockaddr = RemotePtr::new(NonNull::new(regs.rsp as *mut socket::sockaddr_un).unwrap());

    // fill remote struct sockaddr_un
    task.poke(remote_sockaddr.clone(), &addr)?;

    // must restore stack pointer even syscall fails
    match task.untraced_syscall(
        SYS_connect,
        consts::DETSCHED_FD as i64,
        regs.rsp as i64,
        socklen as i64, 0, 0, 0) {
        Ok(_) => {
            regs.rsp = rbp; // restore stack pointer
            task.setregs(regs)?;
            task.detsched_connected = true;
            Ok(())
        }
        Err(e) => {
            regs.rsp = rbp; // restore stack pointer
            task.setregs(regs)?;
            Err(e)
        }
    }
}

// so here we are, at ptrace seccomp stop, if we simply resume, the kernel would
// do the syscall, without our patch. we change to syscall number to -1, so that
// kernel would simply skip the syscall, so that we can jump to our patched syscall
// on the first run.
fn skip_seccomp_syscall(pid: unistd::Pid, regs: libc::user_regs_struct) -> Result<()> {
    let mut new_regs = regs.clone();
    new_regs.orig_rax = -1i64 as u64;
    ptrace::setregs(pid, new_regs).expect("ptrace setregs failed");
    ptrace::step(pid, None).expect("ptrace single step");
    assert!(wait::waitpid(Some(pid), None) == Ok(WaitStatus::Stopped(pid, signal::SIGTRAP)));
    ptrace::setregs(pid, regs).expect("ptrace setregs failed");
    Ok(())
}
