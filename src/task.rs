use std::ptr::NonNull;
use std::io::{Result, Error, ErrorKind};
use std::path::PathBuf;
use nix::unistd;
use nix::sys::{uio, ptrace, signal, wait};
use nix::sys::wait::WaitStatus;
use nix::unistd::{Pid};
use libc;

use crate::stubs;
use crate::nr;
use crate::hooks;
use crate::consts;
use crate::consts::*;
use crate::proc::*;
use crate::remote::*;

fn libsystrace_load_address(pid: unistd::Pid) -> Option<u64> {
    match ptrace::read(pid, consts::DET_TLS_SYSCALL_TRAMPOLINE as ptrace::AddressType) {
        Ok(addr) if addr != 0 => Some(addr as u64 & !0xfff),
        _otherwise => None,
    }
}

lazy_static! {
    static ref SYSCALL_HOOKS: Vec<hooks::SyscallHook> = {
        hooks::resolve_syscall_hooks_from(PathBuf::from(consts::LIB_PATH).join(consts::SYSTRACE_SO))
            .expect(&format!("unable to load {}", consts::SYSTRACE_SO))
    };
}

#[derive(Debug, Clone)]
pub struct Task {
    pub pid: Pid,
    pub parent: Pid,
    pub tid: Pid,
    pub memory_map: Vec<ProcMapsEntry>,
    pub stub_pages: Vec<SyscallStubPage>,
    pub trampoline_hooks: &'static Vec<hooks::SyscallHook>,
    pub ldpreload_address: Option<u64>,
    pub injected_mmap_page: Option<u64>,
    pub signal_to_deliver: Option<signal::Signal>,
    pub unpatchable_syscalls: Vec<u64>,
}

impl Task {
    pub fn new(pid: unistd::Pid) -> Self {
        Task {
            pid,
            parent:pid,
            tid: pid,
            memory_map: decode_proc_maps(pid).unwrap_or(Vec::new()),
            stub_pages: Vec::new(),
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: libsystrace_load_address(pid),
            injected_mmap_page: None,
            signal_to_deliver: None,
            unpatchable_syscalls: Vec::new(),
        }
    }

    pub fn forked(&self, child: unistd::Pid) -> Self {
        Task {
            pid: child,
            parent: self.pid,
            tid: child,
            memory_map: self.memory_map.clone(),
            stub_pages: self.stub_pages.clone(),
            trampoline_hooks: self.trampoline_hooks,
            ldpreload_address: self.ldpreload_address.clone(),
            injected_mmap_page: self.injected_mmap_page.clone(),
            signal_to_deliver: None,
            unpatchable_syscalls: self.unpatchable_syscalls.clone(),
        }
    }

    // vforked process usually calls exec*
    // the process life spam is expected to be short
    pub fn vforked(&self, child: unistd::Pid) -> Self {
        Task {
            pid: child,
            parent: self.pid,
            tid: child,
            memory_map: Vec::new(),
            stub_pages: Vec::new(),
            trampoline_hooks: self.trampoline_hooks,
            ldpreload_address: None,
            injected_mmap_page: None,
            signal_to_deliver: None,
            unpatchable_syscalls: Vec::new(),
        }
    }

    pub fn cloned(&self, child: Pid) -> Self {
        Task {
            pid: child,
            parent: self.pid,
            tid: child,
            memory_map: self.memory_map.clone(),
            stub_pages: self.stub_pages.clone(),
            trampoline_hooks: self.trampoline_hooks,
            ldpreload_address: self.ldpreload_address.clone(),
            injected_mmap_page: self.injected_mmap_page.clone(),
            signal_to_deliver: None,
            unpatchable_syscalls: self.unpatchable_syscalls.clone(),
        }
    }

    pub fn reset(&mut self) {
        self.memory_map = Vec::new();
        self.stub_pages = Vec::new();
        self.ldpreload_address = None;
        self.injected_mmap_page = Some(0x7000_0000);
        self.signal_to_deliver = None;
        self.unpatchable_syscalls = Vec::new();
    }

    pub fn getpid(self) -> Pid {
        self.pid
    }

    pub fn getppid(self) -> Pid {
        self.parent
    }

    pub fn gettid(self) -> Pid {
        self.tid
    }

    pub fn update_memory_map(&mut self) {
        self.memory_map = decode_proc_maps(self.pid).unwrap_or(Vec::new());
    }

    pub fn find_syscall_hook(&mut self, rip: u64) -> Result<&'static hooks::SyscallHook> {
        let mut bytes: Vec<u8> = Vec::new();

        for i in 0..=1 {
            let u64_size = std::mem::size_of::<u64>();
            let remote_ptr = RemotePtr::new(
                NonNull::new(
                    (rip + i * std::mem::size_of::<u64>() as u64) as *mut u64).expect("null pointer"));
            let u: u64 = self.peek(remote_ptr)?;
            let raw: [u8; std::mem::size_of::<u64>()]  = unsafe { std::mem::transmute(u) };
            raw.iter().for_each(|c| bytes.push(*c));
        }

        let mut it = self.trampoline_hooks.iter().filter(|hook| {
            let sequence: &[u8] = &bytes[0..hook.instructions.len()];
            sequence == hook.instructions.as_slice()
        });
        match it.next() {
            None        => {
                Err(Error::new(ErrorKind::Other, format!("unpatchable syscall at {:x}, instructions: {:x?}", rip, bytes)))
            },
            Some(found) => {
                Ok(found)
            },
        }
    }

    pub fn patch_syscall(&mut self, rip: u64) -> Result<()> {
        if self.ldpreload_address.is_none() {
            self.ldpreload_address = libsystrace_load_address(self.pid);
        }
        self.ldpreload_address.ok_or(Error::new(ErrorKind::Other, format!("libsystrace not loaded")))?;
        if self.unpatchable_syscalls.iter().find(|&&pc| pc == rip).is_some() {
            return Err(Error::new(ErrorKind::Other, format!("process {} syscall at {} is not patchable", self.pid, rip)));
        };
        let hook_found = self.find_syscall_hook(rip)?;
        let indirect_jump_address = self.extended_jump_from_to(rip)?;
        let regs = ptrace::getregs(self.pid).expect("ptrace getregs");
        patch_at(self, regs, hook_found, indirect_jump_address)
            .map_err(|e| {
                self.unpatchable_syscalls.push(rip);
                e
            })
    }

    fn hook_index(&mut self, curr: &hooks::SyscallHook) -> Result<usize> {
        for (k, hook) in self.trampoline_hooks.iter().enumerate() {
            if hook == curr {
                return Ok(k);
            }
        }
        Err(Error::new(ErrorKind::Other, format!("cannot find syscall hook: {:?}", curr)))
    }

    fn extended_jump_offset_from_stub_page(&mut self, curr: &hooks::SyscallHook) -> Result<usize> {
        let k = self.hook_index(curr)?;
        Ok(k * stubs::extended_jump_size())
    }

    pub fn extended_jump_from_to(&mut self, rip: u64) -> Result<u64> {
        let hook = self.find_syscall_hook(rip)?;
        let two_gb = 2u64.wrapping_shl(30);
        let page_address = match self.stub_pages
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
            }) {
                None => self.allocate_extended_jumps(rip)?,
                Some(stub) => stub.address,
            };
        let offset = self.extended_jump_offset_from_stub_page(hook)?;
        Ok(page_address + offset as u64)
    }

    fn allocate_extended_jumps (&mut self, rip: u64) -> Result<u64> {
        let size = (stubs::extended_jump_pages() * 0x1000) as u64;
        let at = search_stub_page(self.pid, rip, size as usize)? as u64;
        let allocated_at = self.untraced_syscall(
            nr::SYS_mmap, at, size,
            (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64,
            (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as u64,
            -1i64 as u64, 0)?;
        assert!(at == allocated_at as u64);

        let preload_address = self.ldpreload_address.ok_or(Error::new(ErrorKind::Other, format!("{} not loaded", consts::SYSTRACE_SO)))?;
        let stubs = stubs::gen_extended_jump_stubs(self.trampoline_hooks, preload_address);
        self.stub_pages.push(SyscallStubPage{address:at, size: size as usize, allocated: stubs.len()});
        let remote_ptr = RemotePtr::new(
            NonNull::new(at as *mut u8).expect("null pointer"));
        self.poke_bytes(remote_ptr, stubs.as_slice())?;

        self.untraced_syscall(nr::SYS_mprotect, allocated_at as u64, size,
                              (libc::PROT_READ | libc::PROT_EXEC) as u64, 0, 0, 0)?;

        self.update_memory_map();

        Ok(allocated_at as u64)
    }
}

impl Remote for Task {
    fn peek_bytes(&self, addr: RemotePtr<u8>, size: usize) -> Result<Vec<u8>> {
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.as_ptr();
            let x = ptrace::read(self.pid, raw_ptr as ptrace::AddressType).expect("ptrace peek");
            let bytes: [u8; std::mem::size_of::<u64>()] = unsafe { std::mem::transmute(x) };
            Ok(bytes.iter().take(size).map(|c|*c).collect())
        } else {
            let raw_ptr = addr.as_ptr();
            let remote_iov = &[uio::RemoteIoVec{base: raw_ptr as usize, len: size}];
            let mut res = vec![0; size];
            let local_iov = &[ uio::IoVec::from_mut_slice(res.as_mut_slice())];
            uio::process_vm_readv(self.pid, local_iov, remote_iov).expect("process_vm_readv");
            Ok(res)
        }
    }

    fn poke_bytes(&self, addr: RemotePtr<u8>, bytes: &[u8]) -> Result<()> {
        let size = bytes.len();
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.as_ptr();
            let mut u64_val = if size < std::mem::size_of::<u64>() {
                ptrace::read(self.pid, raw_ptr as ptrace::AddressType)
                    .expect("ptrace peek") as u64
            } else {
                0u64
            };
            let u64_val_ptr: *mut u64 = &mut u64_val;
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const u64, u64_val_ptr, size) };
            ptrace::write(self.pid, raw_ptr as ptrace::AddressType,
                          u64_val as *mut libc::c_void).expect("ptrace poke");
            return Ok(())
        } else {
            let raw_ptr = addr.as_ptr();
            let remote_iov = &[uio::RemoteIoVec{base: raw_ptr as usize, len: size}];
            let local_iov = &[uio::IoVec::from_slice(bytes)];
            uio::process_vm_writev(self.pid, local_iov, remote_iov).expect("process_vm_readv");
            return Ok(())
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

    fn cont(&mut self) -> Result<()> {
        ptrace::cont(self.pid, self.signal_to_deliver).expect("pid {}: ptrace cont");
        self.signal_to_deliver = None;
        Ok(())
    }
}

impl RemoteSyscall for Task {
    fn untraced_syscall(&mut self, nr: nr::SyscallNo, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<i64> {
        remote_do_untraced_syscall(self, nr, a0, a1, a2, a3, a4, a5)
    }
}

// inject syscall for given tracee
// NB: limitations:
// - tracee must be in stopped state.
// - the tracee must have returned from PTRACE_EXEC_EVENT
fn remote_do_untraced_syscall(task: &mut Task, nr: nr::SyscallNo, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<i64>{
    let pid = task.pid;
    let mut regs = task.getregs()?;
    let oldregs = regs.clone();

    let no = nr as u64;
    regs.orig_rax = no;
    regs.rax      = no;
    regs.rdi      = a0 as u64;
    regs.rsi      = a1 as u64;
    regs.rdx      = a2 as u64;
    regs.r10      = a3 as u64;
    regs.r8       = a4 as u64;
    regs.r9       = a5 as u64;

    // instruction at 0x7000_0008 must be
    // callq 0x70000000 (5-bytes)
    // .byte 0xcc
    regs.rip = 0x7000_0008u64;

    task.setregs(regs)?;
    task.cont()?;
    match wait::waitpid(pid, None) {
        Ok(WaitStatus::Stopped(pid, signal::SIGTRAP)) => (),
        Ok(WaitStatus::Stopped(pid, signal::SIGCHLD)) => (), // XXX: deliver SIGCHLD?
        otherwise => panic!("waitpid {} returned unknown status: {:x?}", pid, otherwise),
    };
    let newregs = task.getregs()?;
    task.setregs(oldregs)?;
    if newregs.rax as u64 > (-4096i64) as u64 {
        Err(Error::from_raw_os_error(-(newregs.rax as i64) as i32))
    } else {
        Ok(newregs.rax as i64)
    }
}

