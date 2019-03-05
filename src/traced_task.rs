use libc;
use log::{trace, debug, warn, info};
use nix::sys::socket;
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd;
use nix::unistd::Pid;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::ptr::NonNull;
use std::rc::Rc;
use std::cell::{RefCell, RefMut};
use std::ops::{Deref, DerefMut};
use std::collections::{HashMap, HashSet};

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
use crate::remote_rwlock::*;
use crate::vdso;

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

pub struct TracedTask {
    /// task id, same as `gettid()`
    /// please note we use `tid` for `ptrace` instead of `pid`
    tid: Pid,
    /// process id as of `getpid()`
    pid: Pid,
    /// parent process id as of `getppid()`
    ppid: Pid,
    /// process group id as of `getpgid()`
    pgid: Pid,

    // vfork creates short-lived process folowed by exec
    // as a result it does add benefit to do expensive
    // syscall patching.
    in_vfork: bool,

    pub state: TaskState,
    pub ldpreload_address: Option<u64>,
    pub injected_mmap_page: Option<u64>,
    pub signal_to_deliver: Option<signal::Signal>,
    pub trampoline_hooks: &'static Vec<hooks::SyscallHook>,
    //
    // Even though the tracee can be multi-threaded
    // the tracer is not. hence no need for locking
    //
    // each process should have its own copy of below data
    // however, threads do resides in the same address space
    // as a result they should share below data as well
    pub memory_map: Rc<RefCell<Vec<ProcMapsEntry>>>,
    pub stub_pages: Rc<RefCell<Vec<SyscallStubPage>>>,
    pub unpatchable_syscalls: Rc<RefCell<Vec<u64>>>,
    pub patched_syscalls: Rc<RefCell<Vec<u64>>>,
    pub syscall_patch_lockset: Rc<RefCell<RemoteRWLock>>,
}

impl std::fmt::Debug for TracedTask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Task {{ tid: {}, pid: {}, ppid: {}, \
                   pgid: {}, state: {:?}, signal: {:?}}}",
               self.tid, self.pid, self.ppid, self.pgid,
               self.state, self.signal_to_deliver)
    }
}

impl Task for TracedTask {
    fn new(pid: unistd::Pid) -> Self {
        TracedTask {
            tid: pid,
            pid,
            ppid: pid,
            pgid: unistd::getpgid(Some(pid)).unwrap(),
            state: TaskState::Ready,
            in_vfork: false,
            memory_map: Rc::new(RefCell::new(Vec::new())),
            stub_pages: Rc::new(RefCell::new(Vec::new())),
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: libsystrace_load_address(pid),
            injected_mmap_page: None,
            signal_to_deliver: None,
            unpatchable_syscalls: Rc::new(RefCell::new(Vec::new())),
            patched_syscalls: Rc::new(RefCell::new(Vec::new())),
            syscall_patch_lockset: Rc::new(RefCell::new(RemoteRWLock::new())),
        }
    }

    fn cloned(&self) -> Self {
        let pid_raw = self.getevent().expect(&format!("{:?} ptrace getevent", self));
        let child = Pid::from_raw(pid_raw as libc::pid_t);
        TracedTask {
            tid: child,
            pid: self.pid,
            ppid: self.pid,
            pgid: self.pgid,
            state: TaskState::Ready,
            in_vfork: false,
            memory_map: self.memory_map.clone(),
            stub_pages: self.stub_pages.clone(),
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: self.ldpreload_address.clone(),
            injected_mmap_page: self.injected_mmap_page.clone(),
            signal_to_deliver: None,
            unpatchable_syscalls: self.unpatchable_syscalls.clone(),
            patched_syscalls: self.patched_syscalls.clone(),
            syscall_patch_lockset: self.syscall_patch_lockset.clone(),
        }
    }

    fn forked(&self) -> Self {
        let pid_raw = self.getevent().expect(&format!("{:?} ptrace getevent", self));
        let child = Pid::from_raw(pid_raw as libc::pid_t);
        TracedTask {
            tid: child,
            pid: child,
            ppid: self.pid,
            pgid: self.pgid,
            state: TaskState::Ready,
            in_vfork: false,
            memory_map: {
                let maps = self.memory_map.borrow().clone();
                Rc::new(RefCell::new(maps))
            },
            stub_pages: {
                let stubs = self.stub_pages.borrow().clone();
                Rc::new(RefCell::new(stubs))
            },
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: self.ldpreload_address,
            injected_mmap_page: self.injected_mmap_page,
            signal_to_deliver: None,
            unpatchable_syscalls: {
                let unpatchables = self.unpatchable_syscalls.borrow().clone();
                Rc::new(RefCell::new(unpatchables))
            },
            patched_syscalls: {
                let patched = self.patched_syscalls.borrow().clone();
                Rc::new(RefCell::new(patched))
            },
            syscall_patch_lockset: Rc::new(RefCell::new(RemoteRWLock::new())),
        }
    }

    fn exited(&self) -> Option<i32> {
        match &self.state {
            TaskState::Exited(exit_code) => Some(*exit_code as i32),
            _otherwise => None,
        }
    }

    fn gettid(&self) -> Pid {
        self.tid
    }

    fn getpid(&self) -> Pid {
        self.pid
    }

    fn getppid(&self) -> Pid {
        self.ppid
    }

    fn getpgid(&self) -> Pid {
        self.pgid
    }

    fn run(self) -> Result<RunTask<TracedTask>> {
        let mut task = self;
        match task.state {
            TaskState::Running => Ok(RunTask::Runnable(task)),
            TaskState::Signaled(signal) => {
                let _ = ptrace::cont(task.gettid(), Some(signal));
                Ok(RunTask::Exited(0x80 | signal as i32)
            }
            TaskState::Ready => {
                Ok(RunTask::Runnable(task))
            }
            TaskState::Stopped(signal) => {
                if signal == signal::SIGSEGV || signal == signal::SIGILL {
                    show_fault_context(&task, signal);
                }
                task.signal_to_deliver = Some(signal);
                Ok(RunTask::Runnable(task))
            }
            TaskState::Event(_ev) => handle_ptrace_event(task),
            TaskState::Syscall(_at) => handle_syscall_exit(task),
            TaskState::Exited(_exit_code) => unreachable!("run task which is already exited"),
        }
    }
}

fn show_stackframe(tid: Pid, stack: u64, top_size: usize, bot_size: usize) -> String{
    let sp_top = stack - top_size as u64;
    let sp_bot = stack + bot_size as u64;
    let mut sp = sp_top;
    let mut text = String::new();
    while sp <= sp_bot {
        match ptrace::read(tid, sp as ptrace::AddressType) {
            Err(_) => break,
            Ok(x)  => {
                if sp == stack {
                    text += &format!(" => {:12x}: {:16x}\n", sp, x);
                } else {
                    text += &format!("    {:12x}: {:16x}\n", sp, x);
                }
            }
        }
        sp += 8;
    }
    text
}

fn show_user_regs(regs: &libc::user_regs_struct) -> String {
    let mut res = String::new();

    res += &format!("rax {:16x} rbx {:16x} rcx {:16x} rdx {:16x}\n",
                    regs.rax, regs.rbx, regs.rcx, regs.rdx);
    res += &format!("rsi {:16x} rdi {:16x} rbp {:16x} rsp {:16x}\n",
                    regs.rsi, regs.rdi, regs.rbp, regs.rsp);
    res += &format!(" r8 {:16x}  r9 {:16x} r10 {:16x} r11 {:16x}\n",
                    regs.r8, regs.r9, regs.r10, regs.r11);
    res += &format!("r12 {:16x} r13 {:16x} r14 {:16x} r15 {:16x}\n",
                    regs.r12, regs.r13, regs.r14, regs.r15);
    res += &format!("rip {:16x} eflags {:16x}\n",
                    regs.rip, regs.eflags);
    res += &format!("cs {:x} ss {:x} ds {:x} es {:x}\nfs {:x} gs {:x}",
                    regs.cs, regs.ss, regs.ds, regs.es,
                    regs.fs, regs.gs);
    res
}

fn show_fault_context(task: &TracedTask, sig: signal::Signal) {
    let regs = task.getregs().unwrap();
    let siginfo = task.getsiginfo().unwrap();
    let tid = task.gettid();
    debug!("{:?} got {:?} si_errno: {}, si_code: {}, regs\n{}",
           task, sig,
           siginfo.si_errno, siginfo.si_code,
           show_user_regs(&regs));

    debug!("stackframe from rsp@{:x}\n{}", regs.rsp,
           show_stackframe(tid, regs.rsp, 0x40, 0x80));

    if regs.rip != 0 {
        let rptr = RemotePtr::new((regs.rip - 2) as *mut u8);
        match task.peek_bytes(rptr, 16) {
            Err(_) => (),
            Ok(v)  => {
                debug!("insn @{:x?} = {:02x?}", rptr.as_ptr(), v);
            }
        }
    }

    decode_proc_maps(task.gettid())
        .unwrap()
        .iter()
        .for_each(|e| { debug!("{:x?}", e);});
}

impl TracedTask {
    pub fn is_patched_syscall(&self, rip: u64) -> bool {
        self.patched_syscalls
            .borrow()
            .iter()
            .find(|&&pc| pc == rip)
            .is_some()
    }
    pub fn task_state_is_seccomp(&self) -> bool {
        self.state == TaskState::Event(7)
    }
}

fn check_ref_counters(task: &TracedTask) {
    let expected = 1;
    let refcnt = Rc::strong_count(&task.unpatchable_syscalls);
    if refcnt != expected {
        warn!("{:?} Rc::strong_count(&task.unpatchable_syscalls) expected {} got {}", task, expected, refcnt);
    }
    let expected = 1;
    let refcnt = Rc::strong_count(&task.memory_map);
    if refcnt != expected {
        warn!("{:?} Rc::strong_count(&task.memory_map) expected {} got {}", task, expected, refcnt);
    }

    let expected = 1;
    let refcnt = Rc::strong_count(&task.stub_pages);
    if refcnt != expected {
        warn!("{:?} Rc::strong_count(&task.stub_pages) expected {} got {}", task, expected, refcnt);
    }
}

// reset task after exec
// FIXME: may needs special handling
// see https://github.com/pgbovine/strace-plus/blob/master/README-linux-ptrace
// section: 1.x execve under ptrace.
fn task_exec_reset(task: &mut TracedTask) {
    task.ldpreload_address = None;
    task.injected_mmap_page = Some(0x7000_0000);
    task.signal_to_deliver = None;
    task.state = TaskState::Exited(0);
    task.in_vfork = false;
    check_ref_counters(task);
    *(task.patched_syscalls.borrow_mut()) = Vec::new();
    *(task.unpatchable_syscalls.borrow_mut()) = Vec::new();
    *(task.memory_map.borrow_mut()) = Vec::new();
    *(task.stub_pages.borrow_mut()) = Vec::new();
    *(task.syscall_patch_lockset.borrow_mut()) = RemoteRWLock::new();
}

fn update_memory_map(task: &mut TracedTask) {
    // update memory mapping from /proc/[pid]/maps
    // NB: we must use `pid` here.
    *(task.memory_map.borrow_mut()) = decode_proc_maps(task.getpid())
        .unwrap_or_else(|_|Vec::new());
}

fn find_syscall_hook(task: &TracedTask, rip: u64) -> Option<&'static hooks::SyscallHook> {
    let mut bytes: Vec<u8> = Vec::new();

    for i in 0..=1 {
        let remote_ptr = RemotePtr::new(
            (rip + i * std::mem::size_of::<u64>() as u64) as *mut u64
        );
        let u: u64 = task.peek(remote_ptr).unwrap();
        let raw: [u8; std::mem::size_of::<u64>()] = unsafe { std::mem::transmute(u) };
        raw.iter().for_each(|c| bytes.push(*c));
    }

    let mut it = task.trampoline_hooks.iter().filter(|hook| {
        let sequence: &[u8] = &bytes[0..hook.instructions.len()];
        sequence == hook.instructions.as_slice()
    });
    it.next()
}

/// patch a syscall site @rip for a given task.
/// returns OK(_) when patch success
/// or Err(_) when patch failed
/// NB: special case for `vfork`: this function returns Err(_) after
/// `vfork`, because `vfork` are usually followed by `exec*`
pub fn patch_syscall_with(task: &mut TracedTask, hook: &hooks::SyscallHook, syscall: SyscallNo, rip: u64) -> Result<()> {
    // vfork are usually followed by exec, after exec the program
    // is replaced with a new context, hence we don't patch any
    // syscall after vfork.
    if task.in_vfork {
        return Err(Error::new(ErrorKind::Other, format!("skip syscall patching due to vork")));
    }

    task.ldpreload_address.ok_or(Error::new(
        ErrorKind::Other,
        format!("libsystrace not loaded"),
    ))?;
    if task.is_patched_syscall(rip) {
        // already patched
        unreachable!("{:?} already patched?", task);
    }
    if task
        .unpatchable_syscalls
        .borrow()
        .iter()
        .find(|&&pc| pc == rip)
        .is_some()
    {
        return Err(Error::new(
            ErrorKind::Other,
            format!("process {} syscall at {} is not patchable", task.gettid(), rip),
        ));
    };
    let old_regs = ptrace::getregs(task.gettid()).expect("ptrace getregs");
    task.syscall_patch_lockset.borrow_mut().try_read_unlock(task.gettid(), rip);
    if !task.syscall_patch_lockset.borrow_mut().try_write_lock(task.gettid(), rip) {
        return Err(Error::new(
            ErrorKind::Other,
            format!("process {} cannot take write lock@{:x}", task.getpid(), rip),
            ));
    }

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
    skip_seccomp_syscall(task, old_regs)?;

    let indirect_jump_address = extended_jump_from_to(task, hook, rip)?;
    task.patched_syscalls.borrow_mut().push(rip);
    patch_syscall_at(task, syscall, hook, indirect_jump_address);
    task.syscall_patch_lockset.borrow_mut().try_write_unlock(task.gettid(), rip);
    Ok(())
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
fn extended_jump_from_to(task: &mut TracedTask, hook: &hooks::SyscallHook, rip: u64) -> Result<u64> {
    let two_gb = 2u64.wrapping_shl(30);
    let stub_address = task
        .stub_pages
        .borrow()
        .iter()
        .find(|page| {
            let (start, end) = (page.address, page.address + page.size as u64);
            if end <= rip {
                rip - start <= two_gb
            } else if start >= rip {
                start + stubs::extended_jump_pages() as u64 * 0x1000 - rip <= two_gb
            } else {
                false
            }
        }).map(|x| x.address);
    // NB: do not use `unwrap_or` here, which eagerly evaluate `optb`
    // see: https://doc.rust-lang.org/std/result/enum.Result.html#method.unwrap_or
    // for more details
    let page_address = match stub_address {
        None => allocate_extended_jumps(task, rip)?,
        Some(x) => x,
    };
    trace!("=== {:?} extended_jump_from_to rip {:x}, new pa: {:x}, stubs: {:x?}", task, rip, page_address, task.stub_pages.borrow().clone());
    let offset = extended_jump_offset_from_stub_page(task, hook)?;
    Ok(page_address + offset as u64)
}

// allocate page(s) to store the extended jump stubs
// since the direct jump from the syscall site is a
// `callq extended_jump_stub`, the `extended_jump_stub`
// must be within +/- 2GB of IP.
fn allocate_extended_jumps(task: &mut TracedTask, rip: u64) -> Result<u64> {
    let size = (stubs::extended_jump_pages() * 0x1000) as i64;
    let at = search_stub_page(task.gettid(), rip, size as usize)? as i64;
    let allocated_at = task.untraced_syscall(
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
    task.stub_pages.borrow_mut().push(SyscallStubPage {
        address: at as u64,
        size: size as usize,
        allocated: stubs.len(),
    });
    let remote_ptr = RemotePtr::new(at as *mut u8);
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
            let x = ptrace::read(self.tid, raw_ptr as ptrace::AddressType).expect("ptrace peek");
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
            uio::process_vm_readv(self.tid, local_iov, remote_iov).expect("process_vm_readv");
            Ok(res)
        }
    }

    fn poke_bytes(&self, addr: RemotePtr<u8>, bytes: &[u8]) -> Result<()> {
        let size = bytes.len();
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.as_ptr();
            let mut u64_val = if size < std::mem::size_of::<u64>() {
                ptrace::read(self.tid, raw_ptr as ptrace::AddressType).expect("ptrace peek") as u64
            } else {
                0u64
            };
            let masks = &[ 0xffffffff_ffffff00u64,
                           0xffffffff_ffff0000u64,
                           0xffffffff_ff000000u64,
                           0xffffffff_00000000u64,
                           0xffffff00_00000000u64,
                           0xffff0000_00000000u64,
                           0xff000000_00000000u64,
                           0x00000000_00000000u64 ];
            u64_val = u64_val & masks[size-1];
            for k in 0..size {
                u64_val |= (bytes[k] as u64).wrapping_shl(k as u32 *8);
            }
            ptrace::write(
                self.tid,
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
            uio::process_vm_writev(self.tid, local_iov, remote_iov).expect("process_vm_writev");
            return Ok(());
        }
    }

    fn getregs(&self) -> Result<libc::user_regs_struct> {
        let regs = ptrace::getregs(self.tid).expect(&format!("pid {}: ptrace getregs", self.tid));
        Ok(regs)
    }

    fn setregs(&self, regs: libc::user_regs_struct) -> Result<()> {
        ptrace::setregs(self.tid, regs).expect(&format!("pid {}: ptrace getregs", self.tid));
        Ok(())
    }

    fn resume(&self, sig: Option<signal::Signal>) -> Result<()> {
        ptrace::cont(self.tid, sig).expect(&format!("task {:?}: ptrace cont", self));
        Ok(())
    }

    fn step(&self, sig: Option<signal::Signal>) -> Result<()> {
        ptrace::step(self.tid, sig).expect(&format!("task {:?}: ptrace cont", self));
        Ok(())
    }

    fn getsiginfo(&self) -> Result<libc::siginfo_t> {
        let siginfo = ptrace::getsiginfo(self.tid).expect(&format!("task {:?}: getsiginfo", self));
        Ok(siginfo)
    }

    fn getevent(&self) -> Result<i64> {
        let ev = ptrace::getevent(self.tid).expect(&format!("task {:?}: ptrace getevent", self));
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
    let tid = task.tid;
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
    let status = wait::waitpid(tid, None).expect("waitpid");
    match status {
        WaitStatus::Stopped(_pid, signal::SIGTRAP) => (),
        WaitStatus::Stopped(_pid, signal::SIGCHLD) => {
            task.signal_to_deliver = Some(signal::SIGCHLD)
        }
        otherwise => {
            let regs = task.getregs()?;
            panic!(
                "when doing syscall {:?} waitpid {} returned unknown status: {:x?} pc: {:x}",
                nr, tid, otherwise, regs.rip
            );
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

fn ptrace_get_stopsig(tid: Pid) -> libc::siginfo_t {
    let si = ptrace::getsiginfo(tid).unwrap();
    si
}

const ERESTARTSYS:    i32 = 512;
const ERESTARTNOINTR: i32 = 513;
const ERESTARTNOHAND: i32 = 514;
const ERESTARTBLOCK:  i32 = 516;

// PTRACE_SYSCALL may return restarted syscall
// must restart them conditionally
fn should_restart_syscall(task: &mut TracedTask, regs: libc::user_regs_struct) -> bool {
    let tid = task.gettid();

    let si = ptrace_get_stopsig(tid);
    let sig = signal::Signal::from_c_int(si.si_signo).unwrap();
    assert!(sig == signal::SIGTRAP || sig == signal::SIGCHLD);

    if regs.rax as i64 == -ERESTARTSYS as i64 {
        true
    } else if regs.rax as i64 == -ERESTARTNOINTR as i64 {
        true
    } else if regs.rax as i64 == -ERESTARTNOHAND as i64 {
        true
    } else if regs.rax as i64 == -ERESTARTBLOCK  as i64 {
        true
    } else {
        false
    }
}

// PTRACE_SYSCALL stop. task was stopped because of syscall exit.
// this is desired because some syscalls are blocking
// we use it to do the read lock unlock
fn handle_syscall_exit(mut task: TracedTask) -> Result<RunTask<TracedTask>> {
    let regs = task.getregs()?;
    let rip = regs.rip;
    let tid = task.gettid();
    trace!("=== seccomp syscall {:?} @{:x}, return: {:x} ({})", SyscallNo::from(regs.orig_rax as i32), rip, regs.rax, regs.rax as i64);

    if should_restart_syscall(&mut task, regs) {
        debug!("=== seccomp syscall {:?} @{:x}, restarted", SyscallNo::from(regs.orig_rax as i32), rip);
        debug_assert_eq!(task.state, TaskState::Syscall(rip));
        // will re-enter syscall exit, state is TaskState::Syscall
        return Ok(RunTask::Runnable(task));
    }

    let syscall_end = rip + 9; // TODO: maximum patch is less than 16B
    let mut sig: Option<signal::Signal> = None;
    loop {
        ptrace::step(tid, sig).expect("ptrace single step");
        match wait::waitpid(Some(tid), None) {
            Ok(WaitStatus::Stopped(tid1, signal::SIGTRAP)) if tid1 == tid => {
                sig = None;
            }
            Ok(WaitStatus::Stopped(tid1, signal::SIGCHLD)) if tid1 == tid => {
                sig = Some(signal::SIGCHLD);
            }
            unexpected => {
                panic!("waitpid({}): unexpected status {:?}, rip {:x}",
                       tid, unexpected, rip);
            }
        }
        let new_regs = ptrace::getregs(tid).expect(&format!("tid {} ptrace getregs", tid));
        if !(new_regs.rip > regs.rip && new_regs.rip < syscall_end) {
            break;
        }
    }
    task.syscall_patch_lockset.borrow_mut().try_read_unlock(tid, rip);
    task.state = TaskState::Running;
    Ok(RunTask::Runnable(task))
}

fn handle_ptrace_event(mut task: TracedTask) -> Result<RunTask<TracedTask>> {
    let raw_event = match task.state {
        TaskState::Event(ev) => ev as i64,
        otherwise => panic!("unknown task.state = {:x?}", otherwise),
    };
    if raw_event == ptrace::Event::PTRACE_EVENT_FORK as i64 {
        let pair = do_ptrace_fork(task)?;
        Ok(RunTask::Forked(pair.0, pair.1))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_VFORK as i64 {
        let pair = do_ptrace_vfork(task)?;
        Ok(RunTask::Forked(pair.0, pair.1))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_CLONE as i64 {
        let pair = do_ptrace_clone(task)?;
        Ok(RunTask::Forked(pair.0, pair.1))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_EXEC as i64 {
        do_ptrace_exec(&mut task).map_err(from_nix_error)?;
        Ok(RunTask::Runnable(task))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_VFORK_DONE as i64 {
        do_ptrace_vfork_done(task).and_then(|tsk| Ok(RunTask::Runnable(tsk)))
    } else if raw_event == ptrace::Event::PTRACE_EVENT_EXIT as i64 {
        do_ptrace_event_exit(task)
    } else if raw_event == ptrace::Event::PTRACE_EVENT_SECCOMP as i64 {
        do_ptrace_seccomp(task).and_then(|tsk| Ok(RunTask::Runnable(tsk)))
    } else {
        panic!("unknown ptrace event: {:x}", raw_event);
    }
}

// From ptrace man page:
//
// If the PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, or PTRACE_O_TRACECLONE options are in effect,
// then  children  created by,  respectively,  vfork(2)  or  clone(2)  with the CLONE_VFORK flag,
// fork(2) or clone(2) with the exit signal set to SIGCHLD, and other kinds of clone(2), are
// automatically attached  to  the  same  tracer  which  traced  their  parent. SIGSTOP is
// delivered to the children, causing them to enter signal-delivery-stop after they exit the
// system call which created them.
//
fn wait_sigstop(task: &TracedTask) -> Result<()> {
    let tid = task.gettid();
    match wait::waitpid(Some(tid), None) {
        Ok(WaitStatus::Stopped(new_pid, signal)) if signal == signal::SIGSTOP && new_pid == tid => {
            task.resume(None)?;
            Ok(())
        }
        _st => Err(Error::new(ErrorKind::Other, format!("expect SIGSTOP, got: {:?}", _st))),
    }
}

fn do_ptrace_vfork_done(task: TracedTask) -> Result<TracedTask> {
    Ok(task)
}

fn do_ptrace_clone(task: TracedTask) -> Result<(TracedTask, TracedTask)> {
    let new_task = task.cloned();
    wait_sigstop(&new_task)?;
    Ok((task, new_task))
}

fn do_ptrace_fork(task: TracedTask) -> Result<(TracedTask, TracedTask)> {
    let new_task = task.forked();
    wait_sigstop(&new_task)?;
    Ok((task, new_task))
}

fn do_ptrace_vfork(task: TracedTask) -> Result<(TracedTask, TracedTask)> {
    let mut new_task = task.forked();
    new_task.in_vfork = true;
    wait_sigstop(&new_task)?;
    Ok((task, new_task))
}

fn do_ptrace_event_exit(task: TracedTask) -> Result<RunTask<TracedTask>> {
    let retval = task.getevent()?;
    ptrace::detach(task.gettid()).unwrap();
    Ok(RunTask::Exited(retval as i32))
}

fn do_ptrace_seccomp(mut task: TracedTask) -> Result<TracedTask> {
    let ev = ptrace::getevent(task.gettid()).map_err(from_nix_error)?;
    let regs = ptrace::getregs(task.gettid()).map_err(from_nix_error)?;
    let rip = regs.rip;
    let rip_before_syscall = regs.rip - consts::SYSCALL_INSN_SIZE as u64;
    let tid = task.gettid();
    let syscall = SyscallNo::from(regs.orig_rax as i32);
    if ev == 0x7fff {
        panic!("unfiltered syscall: {:?}", syscall);
    }

    if task.ldpreload_address.is_none() {
        task.ldpreload_address = libsystrace_load_address(tid);
    }
    let hook = find_syscall_hook(&task, regs.rip);
    trace!("{} seccomp syscall {:?}@{:x}, hook: {:x?}, preloaded: {}", tid, syscall, rip, hook, task.ldpreload_address.is_some());

    // NB: in multi-threaded context, one core could enter ptrace_event_seccomp
    // even another core already patched the very same syscall
    // we skip the (seccomp) syscall, do a synchronization, and let
    // it rerun from the begining of the patched instruction.
    if !is_syscall_insn(tid, rip_before_syscall) {
        let mut new_regs = regs;
        new_regs.rax = regs.orig_rax;
        debug!("{} seccomp syscall {:?}@{:x} restart because it is already patched, rax: {:x}", tid, syscall, rip, regs.rax);
        skip_seccomp_syscall(&mut task, new_regs).unwrap();
        synchronize_from(&mut task, rip_before_syscall);
        return Ok(task);
    }

    while !task.syscall_patch_lockset.borrow_mut().try_read_lock(tid, rip) {
        std::thread::sleep(std::time::Duration::from_micros(1000));
    }

    if !(task.ldpreload_address.is_none() || hook.is_none()) {
        let _ = patch_syscall_with(&mut task, hook.unwrap(), syscall, rip);
    }
    Ok(task)
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(ErrorKind::Other, err)
}

fn just_continue(pid: Pid, sig: Option<signal::Signal>) -> Result<()> {
    ptrace::cont(pid, sig).map_err(from_nix_error)
}

fn tracee_preinit(task: &mut TracedTask) -> nix::Result<()> {
    let tid = task.gettid();
    let mut regs = ptrace::getregs(tid)?;
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

    ptrace::setregs(tid, regs)?;
    ptrace::cont(tid, None)?;

    // second breakpoint after syscall hit
    let status = wait::waitpid(tid, None)?;
    assert!(
        status == wait::WaitStatus::Stopped(tid, signal::SIGTRAP)
    );
    let ret = ptrace::getregs(tid).and_then(|r| {
        if r.rax > (-4096i64 as u64) {
            let errno = -(r.rax as i64) as i32;
            Err(nix::Error::from_errno(nix::errno::from_i32(errno)))
        } else {
            Ok(r.rax)
        }
    })?;

    assert_eq!(ret, page_addr);
    remote::gen_syscall_sequences_at(tid, page_addr)?;

    let _ = vdso::vdso_patch(task);

    saved_regs.rip = saved_regs.rip - 1; // bp size
    ptrace::setregs(tid, saved_regs)?;

    Ok(())
}

fn do_ptrace_exec(task: &mut TracedTask) -> nix::Result<()> {
    let bp_syscall_bp: i64 = 0xcc050fcc;
    let tid = task.gettid();
    let regs = ptrace::getregs(tid)?;
    let saved: i64 = ptrace::read(tid, regs.rip as ptrace::AddressType)?;
    ptrace::write(
        task.tid,
        regs.rip as ptrace::AddressType,
        ((saved & !(0xffffffff as i64)) | bp_syscall_bp) as *mut libc::c_void,
    )?;
    ptrace::cont(tid, None)?;
    let wait_status = wait::waitpid(tid, None)?;
    assert!(wait_status == wait::WaitStatus::Stopped(tid, signal::SIGTRAP));
    tracee_preinit(task)?;
    ptrace::write(
        tid,
        regs.rip as ptrace::AddressType,
        saved as *mut libc::c_void,
    )?;
    task_exec_reset(task);
    Ok(())
}

// so here we are, at ptrace seccomp stop, if we simply resume, the kernel would
// do the syscall, without our patch. we change to syscall number to -1, so that
// kernel would simply skip the syscall, so that we can jump to our patched syscall
// on the first run. please note after calling this function, the task state will
// no longer in ptrace event seccomp.
fn skip_seccomp_syscall(task: &mut TracedTask, regs: libc::user_regs_struct) -> Result<()> {
    let tid = task.gettid();
    let mut new_regs = regs.clone();
    new_regs.orig_rax = -1i64 as u64;
    task.setregs(new_regs)?;
    task.step(None)?;
    assert!(wait::waitpid(Some(tid), None) == Ok(WaitStatus::Stopped(tid, signal::SIGTRAP)));
    task.state = TaskState::Stopped(signal::SIGTRAP);
    task.setregs(regs)?;
    Ok(())
}

fn is_syscall_insn(tid: unistd::Pid, rip: u64) -> bool {
    let insn = ptrace::read(tid, rip as ptrace::AddressType).expect("ptrace peek failed") as u64;
    insn & SYSCALL_INSN_MASK as u64 == SYSCALL_INSN
}
