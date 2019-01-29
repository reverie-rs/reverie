
use std::ptr::NonNull;
use std::io::{Result, Error, ErrorKind};
use std::path::PathBuf;
use nix::unistd;
use nix::sys::{uio, ptrace, signal, wait};
use nix::unistd::{Pid};
use libc;

use crate::patch::{ProcMapsEntry, decode_proc_maps, search_stub_page};
use crate::stubs;
use crate::nr;
use crate::hooks;
use crate::consts;
use crate::patch;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallStubPage {
    pub address: u64,
    pub size: usize,
    pub allocated: usize,
}

#[derive(Debug, Clone)]
pub struct TracedTask{
    pub pid: Pid,
    pub parent: Pid,
    pub tid: Pid,
    pub memory_map: Vec<ProcMapsEntry>,
    pub stub_pages: Vec<SyscallStubPage>,
    pub trampoline_hooks: &'static Vec<hooks::SyscallHook>,
    pub ldpreload_address: Option<u64>,
    pub injected_mmap_page: Option<u64>,
}

#[derive(Debug)]
pub struct RemotePtr<T> {
    ptr: NonNull<T>,
}

impl <T> RemotePtr<T>
where T: Sized
{
    pub fn new(not_null: NonNull<T>) -> Self {
        RemotePtr{ptr: not_null}
    }
}

impl <T> Clone for RemotePtr<T> {
    fn clone(&self) -> Self {
        RemotePtr{ptr: self.ptr.clone()}
    }
}

pub fn cast_remote_ptr<U, T>(from_ptr: RemotePtr<U>) -> RemotePtr<T> {
    let raw_ptr = from_ptr.ptr.as_ptr() as *mut T;
    RemotePtr::new(NonNull::new(raw_ptr).unwrap())
}

fn libsystrace_load_address(pid: unistd::Pid) -> Option<u64> {
    match ptrace::read(pid, consts::DET_TLS_SYSCALL_TRAMPOLINE as ptrace::AddressType) {
        Ok(addr) if addr != 0 => Some(addr as u64 & !0xfff),
        _otherwise => None,
    }
}

lazy_static! {
    static ref SYSCALL_HOOKS: Vec<hooks::SyscallHook> = {
        hooks::resolve_syscall_hooks_from(PathBuf::from(consts::LIB_PATH).join(consts::SYSTRACE_SO)).unwrap()
    };
}

impl TracedTask {
    pub fn new(pid: unistd::Pid) -> Self {
        TracedTask {
            pid,
            parent:pid,
            tid: pid,
            memory_map: decode_proc_maps(pid).unwrap_or(Vec::new()),
            stub_pages: Vec::new(),
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: libsystrace_load_address(pid),
            injected_mmap_page: None,
        }
    }

    pub fn forked(&self, child: unistd::Pid) -> Self {
        TracedTask {
            pid: child,
            parent: self.pid,
            tid: child,
            memory_map: self.memory_map.clone(),
            stub_pages: self.stub_pages.clone(),
            trampoline_hooks: self.trampoline_hooks,
            ldpreload_address: self.ldpreload_address.clone(),
            injected_mmap_page: self.injected_mmap_page.clone(),
        }
    }
    pub fn cloned(&self) -> Self {
        TracedTask {
            pid: self.pid,
            parent: self.pid,
            tid: self.pid,
            memory_map: self.memory_map.clone(),
            stub_pages: self.stub_pages.clone(),
            trampoline_hooks: self.trampoline_hooks,
            ldpreload_address: self.ldpreload_address.clone(),
            injected_mmap_page: self.injected_mmap_page.clone(),
        }
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

    fn peek_bytes(&self, addr: &RemotePtr<u8>, size: usize) -> Result<Vec<u8>> {
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.ptr.as_ptr();
            let x = ptrace::read(self.pid, raw_ptr as ptrace::AddressType).expect("ptrace peek");
            let bytes: [u8; std::mem::size_of::<u64>()] = unsafe { std::mem::transmute(x) };
            Ok(bytes.iter().take(size).map(|c|*c).collect())
        } else {
            let raw_ptr = addr.ptr.as_ptr();
            let remote_iov = &[uio::RemoteIoVec{base: raw_ptr as usize, len: size}];
            let mut res = vec![0; size];
            let local_iov = &[ uio::IoVec::from_mut_slice(res.as_mut_slice())];
            uio::process_vm_readv(self.pid, local_iov, remote_iov).expect("process_vm_readv");
            Ok(res)
        }
    }

    fn poke_bytes(&self, addr: &RemotePtr<u8>, bytes: &[u8]) -> Result<()> {
        let size = bytes.len();
        if size <= std::mem::size_of::<u64>() {
            let raw_ptr = addr.ptr.as_ptr();
            let mut val: u64 = 0;
            let val_ptr: *mut u64 = &mut val;
            let vall: u64 = unsafe { std::mem::transmute(bytes.as_ptr()) };
            let x = ptrace::write(self.pid, raw_ptr as ptrace::AddressType, val as *mut libc::c_void).expect("ptrace peek");
            return Ok(())
        } else {
            let raw_ptr = addr.ptr.as_ptr();
            let remote_iov = &[uio::RemoteIoVec{base: raw_ptr as usize, len: size}];
            let local_iov = &[uio::IoVec::from_slice(bytes)];
            uio::process_vm_writev(self.pid, local_iov, remote_iov).expect("process_vm_readv");
            return Ok(())
        }
    }

    pub fn peek<T>(&self, ref addr: RemotePtr<T>) -> Result<T>
        where T: Sized
    {
        let new_ptr = NonNull::new(addr.ptr.as_ptr() as *mut u8).unwrap();
        let bytes: Vec<u8> = TracedTask::peek_bytes(self, &RemotePtr::new(new_ptr), std::mem::size_of::<T>())?;
        // to be initialized by copy_nonoverlapping.
        let mut res: T = unsafe { std::mem::uninitialized() };
        let ret_ptr: *mut T = &mut res;
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const T, ret_ptr, std::mem::size_of::<T>()) };
        Ok(res)
    }
    pub fn poke<T>(&self, ref addr: RemotePtr<T>, value: &T) -> Result<()>
        where T: Sized
    {
        let value_ptr: *const T = value;
        let new_ptr = NonNull::new(addr.ptr.as_ptr() as *mut u8).unwrap();
        let bytes: &[u8] = unsafe {
            let raw_bytes = std::mem::transmute(value_ptr as *const u8);
            std::slice::from_raw_parts(raw_bytes, std::mem::size_of::<T>())
        };
        TracedTask::poke_bytes(self, &RemotePtr::new(new_ptr), bytes)?;
        Ok(())
    }

    pub fn find_syscall_hook(&mut self, rip: u64) -> Result<&'static hooks::SyscallHook> {
        let mut bytes: Vec<u8> = Vec::new();

        for i in 0..=1 {
            let u64_size = std::mem::size_of::<u64>();
            let remote_ptr = RemotePtr::new(
                NonNull::new(
                    (rip + i * std::mem::size_of::<u64>() as u64) as *mut u64).unwrap());
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
        let hook_found = self.find_syscall_hook(rip)?;
        let indirect_jump_address = self.extended_jump_from_to(rip)?;
        let regs = ptrace::getregs(self.pid).expect("ptrace getregs");
        patch::patch_at(self.pid, regs, hook_found, indirect_jump_address)?;
        Ok(())
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
        
        let page_address = match self.stub_pages.iter().find(|SyscallStubPage{address, size, allocated}|{
            let (start, end) = (*address, *address + *size as u64);
            if end <= rip {
                rip - start <= two_gb
            } else if start >= rip {
                start + stubs::extended_jump_pages() as u64 * 0x1000 - rip <= two_gb
            } else {
                false
            }
        }) {
            None => self.allocate_extended_jumps(rip)?,
            Some(hook) => {
                hook.address
            },
        };

        let offset = self.extended_jump_offset_from_stub_page(hook)?;
        Ok(page_address + offset as u64)
    }
    
    fn allocate_extended_jumps (&mut self, rip: u64) -> Result<u64> {
        let size = (stubs::extended_jump_pages() * 0x1000) as u64;
        let at = search_stub_page(self.pid, rip, size as usize)? as u64;
        let allocated_at = remote_do_untraced_syscall(
            self.pid, nr::SYS_mmap, at, size,
            (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64,
            (libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_ANONYMOUS) as u64,
            -1i64 as u64, 0)?;
        assert!(at == allocated_at as u64);

        let stubs = stubs::gen_extended_jump_stubs(self.trampoline_hooks, self.ldpreload_address.unwrap());
        self.stub_pages.push(SyscallStubPage{address:at, size: size as usize, allocated: stubs.len()});
        let remote_ptr = RemotePtr::new(
            NonNull::new(at as *mut u8).unwrap());
        self.poke_bytes(&remote_ptr, stubs.as_slice())?;

        remote_do_untraced_syscall(self.pid, nr::SYS_mprotect, allocated_at as u64, size,
                                   (libc::PROT_READ | libc::PROT_EXEC) as u64, 0, 0, 0)?;

        self.update_memory_map();

        Ok(allocated_at as u64)
    }
}

// inject syscall for given tracee
// NB: limitations:
// - tracee must be in stopped state.
// - the tracee must have returned from PTRACE_EXEC_EVENT
pub fn remote_do_untraced_syscall(pid: Pid, nr: nr::SyscallNo, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<i64>{
    let mut regs = ptrace::getregs(pid).expect("ptrace getregs");
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

    ptrace::setregs(pid, regs).expect("ptrace setregs");
    ptrace::cont(pid, None).expect("ptrace cont");
    assert!(wait::waitpid(pid, None) == Ok(wait::WaitStatus::Stopped(pid, signal::SIGTRAP)));
    let newregs = ptrace::getregs(pid).expect("ptrace getregs");
    ptrace::setregs(pid, oldregs).expect("ptrace setregs");

    if newregs.rax as u64 > (-4096i64) as u64 {
        Err(Error::from_raw_os_error(-(newregs.rax as i64) as i32))
    } else {
        Ok(newregs.rax as i64)
    }
}
