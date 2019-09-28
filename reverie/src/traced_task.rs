//! ptraced task implements `Task` trait.
//!
//! `TracedTask` implements handlers for ptrace events including
//! seccomp. notably ptrace events include:
//!
//! `PTRACE_EVENT_EXEC`: `execvpe` is about to return, tracee stopped
//!  at entry point.
//!
//! `PTRACE_EVENT_FORK/VFORK/CLONE`: when `fork`/`vfork`/`clone` is about
//! to return
//!
//! `PTRACE_EVENT_SECCOMP`: seccomp stop caused by `RET_TRACE`
//! NB: we patch syscall in seccomp ptrace stop.
//!
//! `PTRACE_EVENT_EXIT`: process is about to exit
//!
//! signals: tracee's pending signal stop.
//!
use goblin::elf::Elf;
use libc;
use log::{debug, info, trace, warn};
use nix::sys::socket;
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal, uio, wait};
use nix::unistd;
use nix::unistd::Pid;
use procfs;
use std::cell::{RefCell, RefMut};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::ptr::NonNull;
use std::rc::Rc;
use std::sync::{atomic::Ordering, Arc, Mutex};

use reverie_common::consts;
use reverie_common::consts::*;
use reverie_common::local_state::*;
use reverie_common::state::*;

use reverie_api::task::*;
use reverie_api::event::*;

use syscalls::*;

use crate::aux;
use crate::auxv;
use crate::debug;
use crate::hooks;
use crate::remote;
use crate::remote::*;
use crate::remote_rwlock::*;
use crate::rpc_ptrace::*;
use crate::sched_wait::*;
use crate::stubs;

use crate::vdso;

lazy_static! {
// get all symbols from tool dso
    static ref PRELOAD_TOOL_SYMS: HashMap<String, u64> = {
        let mut res = HashMap::new();
        let so = std::env::var(consts::REVERIE_TRACEE_PRELOAD).unwrap();
        let mut bytes: Vec<u8> = Vec::new();
        let mut file = File::open(so).unwrap();
        file.read_to_end(&mut bytes).unwrap();
        let elf = Elf::parse(bytes.as_slice()).map_err(|e| Error::new(ErrorKind::Other, e)).unwrap();
        let strtab = elf.strtab;
        for sym in elf.syms.iter() {
            res.insert(strtab[sym.st_name].to_string(), sym.st_value);
        }
        res
    };
}

fn dso_load_address(pid: unistd::Pid, so: &str) -> Option<(u64, u64)> {
    let path = PathBuf::from(so);
    procfs::Process::new(pid.as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .find(|e| match &e.pathname {
            procfs::MMapPath::Path(soname) => soname == &path,
            _ => false,
        })
        .map(|e| e.address)
}

/// our tool library has been fully loaded
fn libtrampoline_load_address(pid: unistd::Pid) -> Option<(u64, u64)> {
    let so = std::env::var(consts::REVERIE_TRACEE_PRELOAD).ok()?;
    ptrace::read(
        pid,
        consts::REVERIE_LOCAL_SYSCALL_TRAMPOLINE as ptrace::AddressType,
    )
    .ok()
    .and_then(|addr| {
        if addr == 0 {
            None
        } else {
            dso_load_address(pid, &so)
        }
    })
}

lazy_static! {
    static ref SYSCALL_HOOKS: Vec<hooks::SyscallHook> = {
        let so = std::env::var(consts::REVERIE_TRACEE_PRELOAD).unwrap();
        hooks::resolve_syscall_hooks_from(PathBuf::from(so.clone()))
            .unwrap_or_else(|_| panic!("unable to load {}", so))
    };
}

fn init_rpc_stack_data(task: &mut TracedTask) {
    let _at = task.untraced_syscall(
        SYS_mmap,
        0,
        0x8000,
        i64::from(libc::PROT_READ | libc::PROT_WRITE),
        i64::from(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS),
        -1,
        0,
    );

    match _at {
        Err(_err) => panic!("init_rpc_stack_data failed: {:?}", _err),
        Ok(at) => {
            let stack_top = at + 0x4000;
            // stack grows from high -> low
            let stack = (RemotePtr::new(stack_top as *mut u64), 0x4000);
            let rpc_data =
                (RemotePtr::new((at + 0x4000) as *mut c_void), 0x4000);
            task.rpc_stack = Some(stack);
            task.rpc_data = Some(rpc_data);
        }
    }
}

/// ptraced task
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

    dpc_task: Option<Pid>,

    /// vfork creates short-lived process folowed by exec
    /// as a result it does add benefit to do expensive
    /// syscall patching.
    in_vfork: bool,

    /// we have a patchable syscall on the enter of
    /// seccomp event, and (may) have the patch sequence size
    /// should be used only in seccomp event
    seccomp_hook_size: Option<usize>,

    pub state: TaskState,
    pub ldpreload_address: Option<(u64, u64)>,
    pub ldpreload_symbols: &'static HashMap<String, u64>,
    pub injected_mmap_page: Option<u64>,
    pub injected_shared_page: Option<u64>,
    pub signal_to_deliver: Option<signal::Signal>,
    pub trampoline_hooks: &'static Vec<hooks::SyscallHook>,
    ///
    /// Even though the tracee can be multi-threaded
    /// the tracer is not. hence no need for locking
    ///
    /// each process should have its own copy of below data
    /// however, threads do resides in the same address space
    /// as a result they should share below data as well
    pub memory_map: Rc<RefCell<Vec<procfs::MemoryMap>>>,
    pub stub_pages: Rc<RefCell<Vec<SyscallStubPage>>>,
    pub unpatchable_syscalls: Rc<RefCell<HashSet<u64>>>,
    pub patched_syscalls: Rc<RefCell<HashSet<u64>>>,
    pub syscall_patch_lockset: Rc<RefCell<RemoteRWLock>>,

    /// breakpoints
    pub breakpoints: Rc<
        RefCell<
            HashMap<
                u64,
                (
                    u64,
                    Box<
                        dyn FnOnce(
                                TracedTask,
                                RemotePtr<c_void>,
                            )
                                -> Result<RunTask<TracedTask>>
                            + 'static,
                    >,
                ),
            >,
        >,
    >,

    /// ldso: ld.so loaded (range) by GNU linker
    /// NB: the linker itself is a static DSO with no dependencies
    /// but it also provides DSO, hence ld-linux.so and ld-XXX.so
    /// are different!
    pub ldso: Option<(u64, u64)>,
    /// ld.so symbols
    pub ldso_symbols: Rc<HashMap<String, u64>>,
    /// per-thread stack used by rpc
    pub rpc_stack: Option<(RemotePtr<u64>, usize)>,
    /// per-thread data area used by rpc
    pub rpc_data: Option<(RemotePtr<c_void>, usize)>,
    /// task event call backs for `TaskEvent`
    pub event_cbs: Option<Rc<RefCell<TaskEventCB>>>,
}

impl std::fmt::Debug for TracedTask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Task {{ tid: {}, pid: {}, ppid: {}, \
             pgid: {}, state: {:?}, signal: {:?}, dpc: {:?}}}",
            self.tid,
            self.pid,
            self.ppid,
            self.pgid,
            self.state,
            self.signal_to_deliver,
            self.dpc_task
        )
    }
}

impl Task for TracedTask {
    /// create a new `TracedTask` based on `pid`
    /// with `tid` = `pid` = `ppid`.
    fn new(pid: unistd::Pid) -> Self {
        TracedTask {
            tid: pid,
            pid,
            ppid: pid,
            pgid: unistd::getpgid(Some(pid)).unwrap(),
            dpc_task: None,
            state: TaskState::Ready,
            in_vfork: false,
            seccomp_hook_size: None,
            memory_map: Rc::new(RefCell::new(Vec::new())),
            stub_pages: Rc::new(RefCell::new(Vec::new())),
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: libtrampoline_load_address(pid),
            ldpreload_symbols: &PRELOAD_TOOL_SYMS,
            injected_mmap_page: None,
            injected_shared_page: None,
            signal_to_deliver: None,
            unpatchable_syscalls: Rc::new(RefCell::new(HashSet::new())),
            patched_syscalls: Rc::new(RefCell::new(HashSet::new())),
            syscall_patch_lockset: Rc::new(RefCell::new(RemoteRWLock::new())),
            breakpoints: Rc::new(RefCell::new(HashMap::new())),
            ldso: None,
            ldso_symbols: Rc::new(HashMap::new()),
            rpc_stack: None,
            rpc_data: None,
            event_cbs: None,
        }
    }

    /// cloned a `TracedTask`
    /// called only when received ptrace clone event.
    fn cloned(&self, child: Pid) -> Self {
        let new_task = TracedTask {
            tid: child,
            pid: self.pid,
            ppid: self.pid,
            pgid: self.pgid,
            dpc_task: None,
            state: TaskState::Ready,
            in_vfork: false,
            seccomp_hook_size: None,
            memory_map: self.memory_map.clone(),
            stub_pages: self.stub_pages.clone(),
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: self.ldpreload_address,
            ldpreload_symbols: &PRELOAD_TOOL_SYMS,
            injected_mmap_page: self.injected_mmap_page,
            injected_shared_page: self.injected_shared_page,
            signal_to_deliver: None,
            unpatchable_syscalls: self.unpatchable_syscalls.clone(),
            patched_syscalls: self.patched_syscalls.clone(),
            syscall_patch_lockset: self.syscall_patch_lockset.clone(),
            breakpoints: self.breakpoints.clone(),
            ldso: self.ldso,
            ldso_symbols: self.ldso_symbols.clone(),
            rpc_stack: None,
            rpc_data: None,
            event_cbs: self.event_cbs.clone(),
        };
        new_task
    }

    /// fork a `TracedTask`
    /// called when received ptrace fork/vfork event
    fn forked(&self, child: Pid) -> Self {
        TracedTask {
            tid: child,
            pid: child,
            ppid: self.pid,
            pgid: self.pgid,
            dpc_task: None,
            state: TaskState::Ready,
            in_vfork: false,
            seccomp_hook_size: None,
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
            ldpreload_symbols: &PRELOAD_TOOL_SYMS,
            injected_mmap_page: self.injected_mmap_page,
            injected_shared_page: self.injected_shared_page,
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
            breakpoints: Rc::new(RefCell::new(HashMap::new())),
            ldso: self.ldso,
            ldso_symbols: self.ldso_symbols.clone(),
            rpc_stack: self.rpc_stack,
            rpc_data: self.rpc_data,
            event_cbs: self.event_cbs.clone(),
        }
    }

    /// get task exit code
    /// called when task exits
    fn exited(&self, code: i32) -> Option<i32> {
        debug_assert!(self.state == TaskState::Exited(self.gettid(), code));
        Some(code)
    }

    /// get task tid
    fn gettid(&self) -> Pid {
        self.tid
    }

    /// get task pid
    fn getpid(&self) -> Pid {
        self.pid
    }

    /// get task parent pid
    fn getppid(&self) -> Pid {
        self.ppid
    }

    /// get task process group id
    fn getpgid(&self) -> Pid {
        self.pgid
    }
}

/// run a task, task ptrace event dispatcher
pub fn run_task<G>(
    gs: Arc<Mutex<G>>,
    mut task: TracedTask,
) -> Result<RunTask<TracedTask>> {
    match task.state {
        TaskState::Running => Ok(RunTask::Runnable(task)),
        TaskState::Signaled(signal) => {
            let _ = ptrace::cont(task.gettid(), Some(signal));
            Ok(RunTask::Exited(0x80 | signal as i32))
        }
        TaskState::Ready => Ok(RunTask::Runnable(task)),
        TaskState::Stopped(signal) => {
            if signal == signal::SIGTRAP {
                let mut regs = task.getregs()?;
                let rip_minus_1 = regs.rip - 1;
                let mut maybe_f: Option<FnBreakpoint> = None;
                match task.breakpoints.borrow_mut().remove(&rip_minus_1) {
                    None => {} // not a breakpoint
                    Some((saved_insn, op)) => {
                        let rptr = RemotePtr::new(rip_minus_1 as *mut u64);
                        task.poke(rptr, &saved_insn)?;
                        regs.rip = rip_minus_1;
                        task.setregs(regs)?;
                        maybe_f = Some(op);
                    }
                }
                match maybe_f {
                    None => {}
                    Some(f) => {
                        let rptr = RemotePtr::new(rip_minus_1 as *mut u64);
                        task.signal_to_deliver = None;
                        return f(task, rptr.cast());
                    }
                }
            }
            task.signal_to_deliver = Some(signal);
            Ok(RunTask::Runnable(task))
        }
        TaskState::Seccomp(syscall) => do_ptrace_seccomp(gs, task, syscall),
        TaskState::Exec => {
            let _ = do_ptrace_exec(&mut task);
            Ok(RunTask::Runnable(task))
        }
        TaskState::Clone(child) => {
            let new_task = do_ptrace_clone(gs, &mut task, child);
            Ok(RunTask::Forked(task, new_task))
        }
        TaskState::Fork(child) => {
            let new_task = do_ptrace_clone(gs, &mut task, child);
            Ok(RunTask::Forked(task, new_task))
        }
        TaskState::VforkDone => Ok(RunTask::Runnable(task)),
        TaskState::Syscall(_sc) => handle_syscall_exit(task),
        TaskState::Exited(pid, exit_code) => {
            do_ptrace_event_exit(gs, pid, exit_code);
            Ok(RunTask::Exited(exit_code))
        }
    }
}

impl TracedTask {
    /// return syscall instruction at `rip` is patched or not
    pub fn is_patched_syscall(&self, rip: u64) -> bool {
        self.patched_syscalls.borrow().get(&rip).is_some()
    }

    /// return whether or net task state is seccomp stop
    pub fn task_state_is_seccomp(&self) -> bool {
        match self.state {
            TaskState::Seccomp(_) => true,
            _ => false,
        }
    }

    /// get ld preloaded tool symbol address
    pub fn get_preloaded_symbol_address(&self, sym: &str) -> Option<u64> {
        if let Some((la, _)) = self.ldpreload_address {
            self.ldpreload_symbols.get(sym).map(|x| *x + la)
        } else {
            None
        }
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
        warn!(
            "{:?} Rc::strong_count(&task.memory_map) expected {} got {}",
            task, expected, refcnt
        );
    }

    let expected = 1;
    let refcnt = Rc::strong_count(&task.stub_pages);
    if refcnt != expected {
        warn!(
            "{:?} Rc::strong_count(&task.stub_pages) expected {} got {}",
            task, expected, refcnt
        );
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
    task.state = TaskState::Exited(task.gettid(), 0);
    task.in_vfork = false;
    task.seccomp_hook_size = None;
    check_ref_counters(task);
    *(task.patched_syscalls.borrow_mut()) = HashSet::new();
    *(task.unpatchable_syscalls.borrow_mut()) = HashSet::new();
    *(task.memory_map.borrow_mut()) = Vec::new();
    *(task.stub_pages.borrow_mut()) = Vec::new();
    *(task.syscall_patch_lockset.borrow_mut()) = RemoteRWLock::new();
    *(task.breakpoints.borrow_mut()) = HashMap::new();
}

fn update_memory_map(task: &mut TracedTask) {
    // update memory mapping from /proc/[pid]/maps
    // NB: we must use `pid` here.
    *(task.memory_map.borrow_mut()) =
        procfs::Process::new(task.getpid().as_raw())
            .and_then(|p| p.maps())
            .unwrap_or_else(|_| Vec::new());
}

fn find_syscall_hook(
    task: &TracedTask,
    rip: u64,
) -> Option<&'static hooks::SyscallHook> {
    let mut bytes: Vec<u8> = Vec::new();

    for i in 0..=1 {
        let remote_ptr = RemotePtr::new(
            (rip + i * std::mem::size_of::<u64>() as u64) as *mut u64,
        );
        match task.peek(remote_ptr).ok() {
            None => return None,
            Some(u) => {
                let raw: [u8; std::mem::size_of::<u64>()] =
                    unsafe { std::mem::transmute(u) };
                raw.iter().for_each(|c| bytes.push(*c));
            }
        }
    }

    let mut it = task.trampoline_hooks.iter().filter(|hook| {
        let sequence: &[u8] = &bytes[0..hook.instructions.len()];
        sequence == hook.instructions.as_slice()
    });
    it.next()
}

/// patch a syscall site at `rip` for a given task.
///
/// returns `OK(_)` when patch success
/// or `Err(_)` when patch failed
///
/// NB: special case for `vfork`: this function returns Err(_) after
/// `vfork`, because `vfork` are usually followed by `exec*`
///
pub fn patch_syscall_with(
    task: &mut TracedTask,
    hook: &hooks::SyscallHook,
    syscall: SyscallNo,
    rip: u64,
) -> Result<()> {
    // vfork are usually followed by exec, after exec the program
    // is replaced with a new context, hence we don't patch any
    // syscall after vfork.
    if task.in_vfork {
        return Err(Error::new(
            ErrorKind::Other,
            "skip syscall patching due to vork",
        ));
    }

    task.ldpreload_address.ok_or_else(|| {
        Error::new(ErrorKind::Other, "libtrampoline not loaded")
    })?;

    // NB: it is normal mmap could return the same address
    // after munmap, however, they might point to different
    // physical memory. so we shouldn't assume the patch work
    // is done. ideally we could update `is_patched_syscall`
    // in `munmap` syscall, but it is easier to just apply
    // the patch.
    //
    // keep this empty statement for documentation purpose.
    if task.is_patched_syscall(rip) {}

    if task
        .unpatchable_syscalls
        .borrow()
        .iter()
        .any(|&pc| pc == rip)
    {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "process {} syscall at {} is not patchable",
                task.gettid(),
                rip
            ),
        ));
    };
    let old_regs = ptrace::getregs(task.gettid()).expect("ptrace getregs");
    task.syscall_patch_lockset
        .borrow_mut()
        .try_read_unlock(task.gettid(), rip);
    if !task
        .syscall_patch_lockset
        .borrow_mut()
        .try_write_lock(task.gettid(), rip)
    {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "process {} cannot take write lock@{:x}",
                task.getpid(),
                rip
            ),
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
    task.patched_syscalls.borrow_mut().insert(rip);
    patch_syscall_at(task, syscall, hook, indirect_jump_address);
    task.syscall_patch_lockset
        .borrow_mut()
        .try_write_unlock(task.gettid(), rip);
    Ok(())
}

fn hook_index(
    task: &mut TracedTask,
    curr: &hooks::SyscallHook,
) -> Result<usize> {
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
fn extended_jump_from_to(
    task: &mut TracedTask,
    hook: &hooks::SyscallHook,
    rip: u64,
) -> Result<u64> {
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
                start + stubs::extended_jump_pages() as u64 * 0x1000 - rip
                    <= two_gb
            } else {
                false
            }
        })
        .map(|x| x.address);
    // NB: do not use `unwrap_or` here, which eagerly evaluate `optb`
    // see: https://doc.rust-lang.org/std/result/enum.Result.html#method.unwrap_or
    // for more details
    let page_address = match stub_address {
        None => allocate_extended_jumps(task, rip)?,
        Some(x) => x,
    };
    trace!(
        "=== {:?} extended_jump_from_to rip {:x}, new pa: {:x}, stubs: {:x?}",
        task,
        rip,
        page_address,
        task.stub_pages.borrow().clone()
    );
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
        i64::from(libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC),
        i64::from(libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS),
        -1i64,
        0,
    )?;
    assert!(at == allocated_at);

    let so = std::env::var(consts::REVERIE_TRACEE_PRELOAD).unwrap();

    let preload_address = task.ldpreload_address.ok_or_else(|| {
        Error::new(ErrorKind::Other, format!("{} not loaded", so))
    })?;
    let stubs = stubs::gen_extended_jump_stubs(
        task.trampoline_hooks,
        preload_address.0,
    );
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
        i64::from(libc::PROT_READ | libc::PROT_EXEC),
        0,
        0,
        0,
    )?;

    update_memory_map(task);

    Ok(allocated_at as u64)
}

/// convenient ptrace interface for `TracedTask`
impl Remote for TracedTask {
    fn peek_bytes(&self, addr: RemotePtr<u8>, size: usize) -> Result<Vec<u8>> {
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.as_ptr();
            let x = ptrace::read(self.tid, raw_ptr as ptrace::AddressType)
                .map_err(from_nix_error)?;
            let bytes: [u8; std::mem::size_of::<u64>()] =
                unsafe { std::mem::transmute(x) };
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
            uio::process_vm_readv(self.tid, local_iov, remote_iov)
                .map_err(from_nix_error)?;
            Ok(res)
        }
    }

    fn poke_bytes(&self, addr: RemotePtr<u8>, bytes: &[u8]) -> Result<()> {
        let size = bytes.len();
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.as_ptr();
            let mut u64_val = if size < std::mem::size_of::<u64>() {
                ptrace::read(self.tid, raw_ptr as ptrace::AddressType)
                    .map_err(from_nix_error)? as u64
            } else {
                0u64
            };
            let masks = &[
                0xffffffff_ffffff00u64,
                0xffffffff_ffff0000u64,
                0xffffffff_ff000000u64,
                0xffffffff_00000000u64,
                0xffffff00_00000000u64,
                0xffff0000_00000000u64,
                0xff000000_00000000u64,
                0x00000000_00000000u64,
            ];
            u64_val &= masks[size - 1];
            // for k in 0..size {
            bytes.iter().enumerate().take(size).for_each(|(k, x)| {
                u64_val |= u64::from(*x).wrapping_shl(k as u32 * 8);
            });
            ptrace::write(
                self.tid,
                raw_ptr as ptrace::AddressType,
                u64_val as *mut libc::c_void,
            )
            .expect("ptrace poke");
            Ok(())
        } else {
            let raw_ptr = addr.as_ptr();
            let remote_iov = &[uio::RemoteIoVec {
                base: raw_ptr as usize,
                len: size,
            }];
            let local_iov = &[uio::IoVec::from_slice(bytes)];
            uio::process_vm_writev(self.tid, local_iov, remote_iov)
                .map_err(from_nix_error)?;
            Ok(())
        }
    }

    fn getregs(&self) -> Result<libc::user_regs_struct> {
        let regs = ptrace::getregs(self.tid).map_err(from_nix_error);
        regs
    }

    fn setregs(&self, regs: libc::user_regs_struct) -> Result<()> {
        ptrace::setregs(self.tid, regs).map_err(from_nix_error)
    }

    fn resume(&self, sig: Option<signal::Signal>) -> Result<()> {
        ptrace::cont(self.tid, sig).map_err(from_nix_error)
    }

    fn step(&self, sig: Option<signal::Signal>) -> Result<()> {
        ptrace::step(self.tid, sig).map_err(from_nix_error)
    }

    fn getsiginfo(&self) -> Result<libc::siginfo_t> {
        let siginfo = ptrace::getsiginfo(self.tid).map_err(from_nix_error);
        siginfo
    }

    fn getevent(&self) -> Result<i64> {
        let ev = ptrace::getevent(self.tid).map_err(from_nix_error);
        ev
    }

    fn setbp<F>(&mut self, _at: RemotePtr<c_void>, op: F) -> Result<()>
    where
        F: 'static
            + FnOnce(TracedTask, RemotePtr<c_void>) -> Result<RunTask<TracedTask>>,
    {
        let rptr = _at.cast();
        let at = rptr.as_ptr() as u64;
        let saved_insn: u64 = self.peek(rptr)?;
        let insn = (saved_insn & !0xffu64) | 0xccu64;
        self.poke(rptr, &insn)?;
        self.breakpoints
            .borrow_mut()
            .insert(at, (saved_insn, Box::new(op)));
        Ok(())
    }
}

/// `RemoteSyscall` trait implementation so that
/// tracer can inject syscalls for the tracee
///
/// NB: tracee must be in stopped state
impl RemoteSyscall for TracedTask {
    /// inject a syscall which won't be traced by the tracer
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
}

/// inject syscall for given tracee
///
/// NB: limitations:
/// - tracee must be in stopped state.
/// - the tracee must have returned from PTRACE_EXEC_EVENT
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
    let mut regs = task.getregs()?;
    let oldregs = regs;

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
    wait_sigtrap_sigchld(task)?;
    let newregs = task.getregs()?;
    task.setregs(oldregs)?;
    if newregs.rax as u64 > (-4096i64) as u64 {
        Err(Error::from_raw_os_error(-(newregs.rax as i64) as i32))
    } else {
        Ok(newregs.rax as i64)
    }
}

// wait either SIGTRAP (breakpoint) or SIGCHLD.
fn wait_sigtrap_sigchld(task: &mut TracedTask) -> Result<()> {
    let tid = task.gettid();
    let status = wait::waitpid(tid, None).expect("waitpid");
    match status {
        WaitStatus::Stopped(_pid, signal::SIGTRAP) => (),
        WaitStatus::Stopped(_pid, signal::SIGCHLD) => {
            task.signal_to_deliver = Some(signal::SIGCHLD)
        }
        otherwise => {
            panic!(
                "task {} expecting SIGTRAP|SIGCHLD but got {:?}",
                tid, otherwise
            );
        }
    };
    Ok(())
}

// inject clone into tracee, returns `RunTask`
fn remote_do_clone(
    mut task: TracedTask,
    entry: u64,
    child_stack: u64,
    flags: u64,
    args: u64,
) -> Result<RunTask<TracedTask>> {
    let tid = task.gettid();
    let mut regs = task.getregs()?;
    let oldregs = regs;

    let no = SYS_clone as u64;
    regs.orig_rax = no;
    regs.rax = no;
    regs.rdi = flags as u64;
    regs.rsi = child_stack as u64;
    regs.rdx = 0;
    regs.r10 = 0;
    regs.r8 = 0;
    regs.r9 = 0;

    // instruction at 0x7000_0008 must be
    // callq 0x70000000 (5-bytes)
    // .byte 0xcc
    regs.rip = 0x7000_0008;
    task.setregs(regs)?;

    task.resume(None)?;
    let status = wait::waitpid(tid, None);
    assert_eq!(status, Ok(WaitStatus::PtraceEvent(tid, signal::SIGTRAP, 1)));
    let new_pid = ptrace::getevent(task.gettid()).unwrap() as i32;
    let child = Pid::from_raw(new_pid);
    let new_task = task.cloned(child);
    wait_sigstop(&new_task)?;
    task.resume(None)?;
    wait_sigtrap_sigchld(&mut task)?;
    task.setregs(oldregs)?;

    // the new task is stopped by breakpoint instruction
    // at 0x7000_0002. we need to fake a regular function
    // call to the thread_routine, but we'll have to adjust
    // our stack accordingly..
    let mut new_regs = new_task.getregs()?;
    let fake_ra = RemotePtr::new(new_regs.rsp as *mut u64);
    new_task.poke(fake_ra, &0xdeadbeef)?;
    new_regs.rip = entry;
    new_regs.rdi = args;
    new_regs.rsp -= std::mem::size_of::<u64>() as u64;
    new_task.setregs(new_regs)?;
    Ok(RunTask::Forked(task, new_task))
}

fn ptrace_get_stopsig(tid: Pid) -> libc::siginfo_t {
    let si = ptrace::getsiginfo(tid).unwrap();
    si
}

const ERESTARTSYS: i32 = 512;
const ERESTARTNOINTR: i32 = 513;
const ERESTARTNOHAND: i32 = 514;
const ERESTARTBLOCK: i32 = 516;

// PTRACE_SYSCALL may return restarted syscall
// must restart them conditionally
fn should_restart_syscall(
    task: &mut TracedTask,
    regs: libc::user_regs_struct,
) -> bool {
    let tid = task.gettid();

    if regs.rax < 0xfffffffffffff000u64 {
        return false;
    }

    let retval = -(regs.rax as i64) as i32;

    let res = match retval {
        ERESTARTSYS => true,
        ERESTARTNOINTR => true,
        ERESTARTNOHAND => true,
        _ => false,
    };

    if res {
        let si = ptrace_get_stopsig(tid);
        let sig = signal::Signal::from_c_int(si.si_signo).unwrap();
        assert!(sig == signal::SIGTRAP || sig == signal::SIGCHLD);
    }
    res
}

// PTRACE_SYSCALL stop. task was stopped because of syscall exit.
// this is desired because some syscalls are blocking
// we use it to do the read lock unlock
fn handle_syscall_exit(mut task: TracedTask) -> Result<RunTask<TracedTask>> {
    let tid = task.gettid();
    let regs = task.getregs()?;
    let rip = regs.rip;

    trace!(
        "=== seccomp syscall {:?} @{:x}, return: {:x} ({})",
        SyscallNo::from(regs.orig_rax as i32),
        rip,
        regs.rax,
        regs.rax as i64
    );

    if should_restart_syscall(&mut task, regs) {
        debug!(
            "=== seccomp syscall {:?} @{:x} to be restarted",
            SyscallNo::from(regs.orig_rax as i32),
            rip
        );
        // will re-enter syscall exit, state is TaskState::Syscall
        return Ok(RunTask::Runnable(task));
    }

    let mut sig: Option<signal::Signal> = None;
    if let Some(hook_size) = task.seccomp_hook_size {
        task.seccomp_hook_size = None;
        let syscall_end = rip + hook_size as u64;
        loop {
            ptrace::step(tid, sig).expect("ptrace single step");
            match wait::waitpid(Some(tid), None) {
                Ok(WaitStatus::Stopped(tid1, sig1)) if tid1 == tid => {
                    sig = if sig1 == signal::SIGTRAP {
                        None
                    } else {
                        Some(sig1)
                    }
                }
                unexpected => {
                    panic!(
                        "waitpid({}): unexpected status {:?}, rip {:x}",
                        tid, unexpected, rip
                    );
                }
            }
            let new_regs = ptrace::getregs(tid)
                .unwrap_or_else(|_| panic!("tid {} ptrace getregs", tid));
            if !(new_regs.rip > regs.rip && new_regs.rip < syscall_end) {
                break;
            }
        }
    }
    task.syscall_patch_lockset
        .borrow_mut()
        .try_read_unlock(tid, rip);
    task.state = TaskState::Running;
    Ok(RunTask::Runnable(task))
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
        Ok(WaitStatus::Stopped(new_pid, signal))
            if signal == signal::SIGSTOP && new_pid == tid =>
        {
            Ok(())
        }
        _st => Err(Error::new(
            ErrorKind::Other,
            format!("expect SIGSTOP, got: {:?}", _st),
        )),
    }
}

fn do_ptrace_vfork_done(task: TracedTask) -> Result<TracedTask> {
    Ok(task)
}

fn do_ptrace_clone<G>(
    gs: Arc<Mutex<G>>,
    task: &mut TracedTask,
    child: Pid,
) -> TracedTask {
    let mut new_task = task.cloned(child);
    wait_sigstop(&new_task).unwrap();

    let state = reverie_global_state();
    state
        .lock()
        .unwrap()
        .stats
        .nr_syscalls
        .fetch_add(1, Ordering::SeqCst);
    state
        .lock()
        .unwrap()
        .stats
        .nr_syscalls_ptraced
        .fetch_add(1, Ordering::SeqCst);
    state
        .lock()
        .unwrap()
        .stats
        .nr_cloned
        .fetch_add(1, Ordering::SeqCst);

    init_rpc_stack_data(&mut new_task);

    if let Some(cbs) = &task.event_cbs.clone() {
        let mut clonefn = &mut cbs.borrow_mut().on_task_clone;
        let _ = clonefn(task);
    }

    new_task
}

fn do_ptrace_fork<G>(
    gs: Arc<Mutex<G>>,
    task: &mut TracedTask,
    child: Pid,
) -> TracedTask {
    let mut new_task = task.forked(child);
    wait_sigstop(&new_task).unwrap();

    let state = reverie_global_state();
    state
        .lock()
        .unwrap()
        .stats
        .nr_syscalls
        .fetch_add(1, Ordering::SeqCst);
    state
        .lock()
        .unwrap()
        .stats
        .nr_syscalls_ptraced
        .fetch_add(1, Ordering::SeqCst);
    state
        .lock()
        .unwrap()
        .stats
        .nr_forked
        .fetch_add(1, Ordering::SeqCst);

    let regs = new_task.getregs().unwrap();
    let _rptr = RemotePtr::new(regs.rip as *mut c_void);
    // new_task.setbp(rptr, handle_fork_entry_bkpt)?;

    if let Some(cbs) = &task.event_cbs.clone() {
        let mut forkfn = &mut cbs.borrow_mut().on_task_fork;
        let _ = forkfn(task);
    }

    new_task
}

fn do_ptrace_vfork(
    task: TracedTask,
    child: Pid,
) -> Result<(TracedTask, TracedTask)> {
    let mut new_task = task.forked(child);
    new_task.in_vfork = true;
    wait_sigstop(&new_task)?;

    let state = reverie_global_state();
    state
        .lock()
        .unwrap()
        .stats
        .nr_syscalls
        .fetch_add(1, Ordering::SeqCst);
    state
        .lock()
        .unwrap()
        .stats
        .nr_syscalls_ptraced
        .fetch_add(1, Ordering::SeqCst);
    state
        .lock()
        .unwrap()
        .stats
        .nr_forked
        .fetch_add(1, Ordering::SeqCst);

    let regs = new_task.getregs()?;
    let _rptr = RemotePtr::new(regs.rip as *mut c_void);
    //new_task.setbp(rptr, handle_fork_entry_bkpt)?;
    Ok((task, new_task))
}

fn do_ptrace_event_exit<G>(gs: Arc<Mutex<G>>, pid: Pid, retval: i32) {
    let state = reverie_global_state();
    state
        .lock()
        .unwrap()
        .stats
        .nr_exited
        .fetch_add(1, Ordering::SeqCst);

    let _ = ptrace::detach(pid);
}

enum PatchStatus {
    NotTried,
    Failed,
    Successed,
}

#[repr(C)]
struct SyscallInfo {
    no: u64,
    args: [u64; 6],
}

fn do_ptrace_seccomp<G>(
    gs: Arc<Mutex<G>>,
    mut task: TracedTask,
    syscall: SyscallNo,
) -> Result<RunTask<TracedTask>> {
    let regs = task.getregs()?;
    let rip = regs.rip;
    let rip_before_syscall = regs.rip - consts::SYSCALL_INSN_SIZE as u64;
    let tid = task.gettid();

    if task.ldpreload_address.is_none() {
        task.ldpreload_address = libtrampoline_load_address(tid);
    }
    let hook = find_syscall_hook(&task, regs.rip);
    trace!(
        "{} seccomp syscall {:?}@{:x}, hook: {:x?}, preloaded: {}",
        tid,
        syscall,
        rip,
        hook,
        task.ldpreload_address.is_some()
    );

    task.seccomp_hook_size = task
        .ldpreload_address
        .and_then(|_| hook.map(|x| x.instructions.len()));

    // NB: in multi-threaded context, one core could enter ptrace_event_seccomp
    // even another core already patched the very same syscall
    // we skip the (seccomp) syscall, do a synchronization, and let
    // it rerun from the begining of the patched instruction.
    if !is_syscall_insn(tid, rip_before_syscall)? {
        let mut new_regs = regs;
        new_regs.rax = regs.orig_rax;
        debug!("{} seccomp syscall {:?}@{:x} restart because it is already patched, rax: {:x}", tid, syscall, rip, regs.rax);
        skip_seccomp_syscall(&mut task, new_regs).unwrap();
        synchronize_from(&task, rip_before_syscall);
        return Ok(RunTask::Runnable(task));
    }

    // NB: another thread is patching this syscall, retry syscall
    if !task
        .syscall_patch_lockset
        .borrow_mut()
        .try_read_lock(tid, rip)
    {
        let mut new_regs = regs;
        new_regs.rax = regs.orig_rax;
        let _ = skip_seccomp_syscall(&mut task, new_regs);
        let _ = task.setregs(regs);
        task.state = TaskState::Ready;
        return Ok(RunTask::Runnable(task));
    }

    let mut patch_status = if task.ldpreload_address.is_some() && hook.is_none()
    {
        PatchStatus::Failed
    } else {
        PatchStatus::NotTried
    };
    if !(task.ldpreload_address.is_none() || hook.is_none()) {
        match patch_syscall_with(&mut task, hook.unwrap(), syscall, rip) {
            Err(_) => patch_status = PatchStatus::Failed,
            Ok(_) => patch_status = PatchStatus::Successed,
        }
    }

    let state = reverie_global_state();
    match patch_status {
        PatchStatus::NotTried => {
            state
                .lock()
                .unwrap()
                .stats
                .nr_syscalls
                .fetch_add(1, Ordering::SeqCst);
            state
                .lock()
                .unwrap()
                .stats
                .nr_syscalls_ptraced
                .fetch_add(1, Ordering::SeqCst);
        }
        //PatchStatus::Failed => {}
        PatchStatus::Failed => {
            let hook = task
                .get_preloaded_symbol_address("syscall_hook")
                .expect("syscall_hook not found");
            let mut new_regs = regs;
            new_regs.rax = regs.orig_rax;
            skip_seccomp_syscall(&mut task, new_regs).unwrap();
            task.setregs(regs)?;

            let rptr = task.rpc_data.unwrap().0.cast();
            let info = SyscallInfo {
                no: regs.orig_rax,
                args: [
                    regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9,
                ],
            };
            task.poke(rptr, &info).unwrap();
            let args = &[rptr.as_ptr() as u64, 0, 0, 0, 0, 0];
            let _ = unsafe { rpc_call(&task, hook, args) };
        }
        PatchStatus::Successed => {
            // others fields are updated in tracee instead.
            state
                .lock()
                .unwrap()
                .stats
                .nr_syscalls_patched
                .fetch_add(1, Ordering::SeqCst);
        }
    }

    Ok(RunTask::Runnable(task))
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(ErrorKind::Other, err)
}

fn from_nix_error_with(err: nix::Error, msg: &str) -> Error {
    let my_error = format!("{}: {:?}", msg, err);
    Error::new(ErrorKind::Other, my_error)
}

fn just_continue(pid: Pid, sig: Option<signal::Signal>) -> Result<()> {
    ptrace::cont(pid, sig).map_err(from_nix_error)
}

// set tool library log level
fn systool_set_log_level(task: &TracedTask) {
    let systool_log_ptr = consts::REVERIE_LOCAL_SYSTOOL_LOG_LEVEL as *mut i64;
    let rptr = RemotePtr::new(systool_log_ptr);
    let lvl =
        std::env::var(consts::REVERIE_ENV_TOOL_LOG_KEY).map(|s| match &s[..] {
            "error" => 1,
            "warn" => 2,
            "info" => 3,
            "debug" => 4,
            "trace" => 5,
            _ => 0,
        });
    match lvl {
        Ok(x) if x >= 1 && x <= 5 => {
            let _ = task.poke(rptr, &x);
        }
        _ => (),
    }
}

fn tracee_preinit(task: &mut TracedTask) -> nix::Result<()> {
    let tid = task.gettid();
    let mut regs = ptrace::getregs(tid)?;
    let mut saved_regs = regs;
    let page_addr = consts::REVERIE_PRIVATE_PAGE_OFFSET;
    let page_size = consts::REVERIE_PRIVATE_PAGE_SIZE;

    regs.orig_rax = SYS_mmap as u64;
    regs.rax = regs.orig_rax;
    regs.rdi = page_addr;
    regs.rsi = page_size;
    regs.rdx = (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64;
    regs.r10 =
        (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as u64;
    regs.r8 = -1 as i64 as u64;
    regs.r9 = 0 as u64;

    ptrace::setregs(tid, regs)?;
    ptrace::cont(tid, None)?;

    // loop until second breakpoint hit after injected syscall
    loop {
        let status = wait::waitpid(tid, None)?;
        match status {
            wait::WaitStatus::Stopped(tid1, signal::SIGTRAP) if tid1 == tid => {
                break
            }
            wait::WaitStatus::PtraceEvent(tid, signal::SIGTRAP, 7) => {
                ptrace::cont(tid, None)?;
            }
            unknown => {
                panic!("task {} returned unknown status {:?}", tid, unknown);
            }
        }
    }

    let ret = ptrace::getregs(tid).and_then(|r| {
        if r.rax > (-4096i64 as u64) {
            let errno = -(r.rax as i64) as i32;
            Err(nix::Error::from_errno(nix::errno::from_i32(errno)))
        } else {
            Ok(r.rax)
        }
    })?;
    assert_eq!(ret, page_addr);

    systool_set_log_level(task);

    remote::gen_syscall_sequences_at(tid, page_addr)?;

    let _ = vdso::vdso_patch(task);

    saved_regs.rip -= 1; // bp size
    ptrace::setregs(tid, saved_regs)
}

// get ld.so load address (range) from pid.
fn get_proc_maps(pid: Pid) -> Option<Vec<procfs::MemoryMap>> {
    procfs::Process::new(pid.as_raw())
        .and_then(|p| p.maps())
        .ok()
}

fn do_ptrace_exec(mut task: &mut TracedTask) -> nix::Result<()> {
    let auxv = unsafe { aux::getauxval(task).unwrap() };

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

    init_rpc_stack_data(&mut task);

    // create per process local state.
    let local_state_addr = task
        .untraced_syscall(
            SYS_mmap,
            0,
            consts::REVERIE_GLOBAL_STATE_SIZE as i64,
            i64::from(libc::PROT_READ | libc::PROT_WRITE),
            i64::from(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS),
            -1i64,
            0,
        )
        .unwrap();
    ptrace::write(
        tid,
        consts::REVERIE_LOCAL_REVERIE_LOCAL_STATE as ptrace::AddressType,
        local_state_addr as *mut _,
    )?;

    let state = reverie_global_state();

    state
        .lock()
        .unwrap()
        .stats
        .nr_process_spawns
        .fetch_add(1, Ordering::SeqCst);

    if let Some(dyn_entry) = auxv.get(&auxv::AT_ENTRY) {
        let _rptr = RemotePtr::new(*dyn_entry as *mut c_void);
        task.setbp(_rptr, Box::new(handle_program_entry_bkpt))
            .unwrap();
    }

    if let Some(ldso_start) = auxv.get(&auxv::AT_BASE) {
        if let Some(ldso) = get_proc_maps(task.getpid()).and_then(|ents| {
            ents.iter().find(|e| e.address.0 == *ldso_start).cloned()
        }) {
            task.ldso = Some(ldso.address);
            if let procfs::MMapPath::Path(so) = &ldso.pathname {
                let mut res: HashMap<String, u64> = HashMap::new();
                let mut bytes: Vec<u8> = Vec::new();
                let mut file = File::open(so).unwrap();
                file.read_to_end(&mut bytes).unwrap();
                let elf = Elf::parse(bytes.as_slice())
                    .map_err(|e| Error::new(ErrorKind::Other, e))
                    .unwrap();
                let strtab = elf.dynstrtab;
                elf.dynsyms.iter().for_each(|s| {
                    res.insert(
                        String::from(&strtab[s.st_name]),
                        ldso.address.0 + s.st_value,
                    );
                });
                task.ldso_symbols = Rc::new(res);
            }
        }
    }

    Ok(())
}

fn populate_ldpreload(task: &mut TracedTask) {
    let pid = task.getpid();
    task.ldpreload_address = libtrampoline_load_address(pid);
}

const PTRACE_SECCOMP_GET_FILTER: usize = 0x420c;
fn dump_bpf_filter(task: &TracedTask) {
    unsafe {
        let mut filter: [u64; 256] = std::mem::zeroed();
        let nb = libc::syscall(
            SYS_ptrace as i64,
            PTRACE_SECCOMP_GET_FILTER,
            task.getpid(),
            0,
            filter.as_mut(),
        );
        if nb != -1 {
            filter.iter().take_while(|x| *x != &0).for_each(|f| {
                println!("|| {:x?}", f);
            });
        } else {
            println!("get filter: {:?}", std::io::Error::last_os_error());
        }
    }
}

type FnBreakpoint = Box<
    (dyn FnOnce(TracedTask, RemotePtr<c_void>) -> Result<RunTask<TracedTask>>
         + 'static),
>;

// breakpoint at program's entry, likley `libc_start_main`for
// for programs linked against glibc
fn handle_program_entry_bkpt(
    mut task: TracedTask,
    _at: RemotePtr<c_void>,
) -> Result<RunTask<TracedTask>> {
    populate_ldpreload(&mut task);
    if let Some(init_proc_state) =
        task.get_preloaded_symbol_address("init_process_state")
    {
        let args: &[u64; 6] = &[0, 0, 0, 0, 0, 0];
        unsafe { rpc_call(&task, init_proc_state, args) };
    }

    may_start_dpc_task(task)
}

// breakpoint at program's entry, likley `libc_start_main`for
// for programs linked against glibc
fn handle_fork_entry_bkpt(
    task: TracedTask,
    _at: RemotePtr<c_void>,
) -> Result<RunTask<TracedTask>> {
    if let Some(init_proc_state) =
        task.get_preloaded_symbol_address("init_process_state")
    {
        let args: &[u64; 6] = &[0, 0, 0, 0, 0, 0];
        unsafe { rpc_call(&task, init_proc_state, args) };
    }

    may_start_dpc_task(task)
}

fn may_start_dpc_task(mut task: TracedTask) -> Result<RunTask<TracedTask>> {
    if let Some(dpc_entry) = task.get_preloaded_symbol_address("dpc_entry") {
        let tid = task.gettid();
        debug!("found dpc_entry: {:x?}", dpc_entry);
        let flags = libc::CLONE_THREAD
            | libc::SIGCHLD
            | libc::CLONE_SIGHAND
            | libc::CLONE_VM
            | libc::CLONE_FILES
            | libc::CLONE_FS
            | libc::CLONE_IO
            | libc::CLONE_SYSVSEM;
        let stack_size = 0x2000;
        let child_stack = task
            .untraced_syscall(
                SYS_mmap,
                0,
                stack_size,
                i64::from(libc::PROT_READ | libc::PROT_WRITE),
                i64::from(libc::MAP_PRIVATE | libc::MAP_ANONYMOUS),
                -1,
                0,
            )
            .unwrap();
        let stack_top = child_stack + stack_size - 0x10;
        match remote_do_clone(
            task,
            dpc_entry,
            stack_top as u64,
            flags as u64,
            0,
        ) {
            Ok(RunTask::Forked(mut parent, child)) => {
                parent.dpc_task = Some(child.gettid());
                assert_eq!(parent.gettid(), tid);
                Ok(RunTask::Forked(parent, child))
            }
            _err => {
                panic!("remote_do_clone failed: {:?}", _err);
            }
        }
    } else {
        Ok(RunTask::Runnable(task))
    }
}

// so here we are, at ptrace seccomp stop, if we simply resume, the kernel would
// do the syscall, without our patch. we change to syscall number to -1, so that
// kernel would simply skip the syscall, so that we can jump to our patched syscall
// on the first run. please note after calling this function, the task state will
// no longer in ptrace event seccomp.
fn skip_seccomp_syscall(
    task: &mut TracedTask,
    regs: libc::user_regs_struct,
) -> Result<()> {
    let tid = task.gettid();
    let mut new_regs = regs;
    new_regs.orig_rax = -1i64 as u64;
    task.setregs(new_regs)?;
    task.step(None)?;
    assert!(
        wait::waitpid(Some(tid), None)
            == Ok(WaitStatus::Stopped(tid, signal::SIGTRAP))
    );
    task.state = TaskState::Stopped(signal::SIGTRAP);
    task.setregs(regs)?;
    Ok(())
}

fn is_syscall_insn(tid: unistd::Pid, rip: u64) -> Result<bool> {
    let insn = ptrace::read(tid, rip as ptrace::AddressType)
        .map_err(from_nix_error)? as u64;
    Ok(insn & SYSCALL_INSN_MASK as u64 == SYSCALL_INSN)
}

fn handle_breakpoint_event(
    task: TracedTask,
    _at: u64,
) -> Result<RunTask<TracedTask>> {
    Ok(RunTask::Runnable(task))
}
