
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
    pub signal_to_deliver: Option<signal::Signal>,
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
            signal_to_deliver: None,
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
            signal_to_deliver: None,
        }
    }
    pub fn vforked(&self, child: unistd::Pid) -> Self {
        TracedTask {
            pid: child,
            parent: self.pid,
            tid: child,
            memory_map: Vec::new(),
            stub_pages: Vec::new(),
            trampoline_hooks: self.trampoline_hooks,
            ldpreload_address: None,
            injected_mmap_page: None,
            signal_to_deliver: None,
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
            signal_to_deliver: None,
        }
    }

    pub fn reset(&mut self) {
        self.memory_map = Vec::new();
        self.stub_pages = Vec::new();
        self.ldpreload_address = None;
        self.injected_mmap_page = Some(0x7000_0000);
        self.signal_to_deliver = None;
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

    pub fn getregs(&self) -> Result<libc::user_regs_struct> {
        let regs = ptrace::getregs(self.pid).expect(&format!("pid {}: ptrace getregs", self.pid));
        Ok(regs)
    }

    pub fn setregs(&self, regs: libc::user_regs_struct) -> Result<()> {
        ptrace::setregs(self.pid, regs).expect(&format!("pid {}: ptrace getregs", self.pid));
        Ok(())
    }

    pub fn cont(&mut self) -> Result<()> {
        ptrace::cont(self.pid, self.signal_to_deliver).expect("pid {}: ptrace cont");
        self.signal_to_deliver = None;
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
        patch_at(self, regs, hook_found, indirect_jump_address)?;
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
    match wait::waitpid(pid, None) {
        Ok(WaitStatus::Stopped(pid, signal::SIGTRAP)) => (),
        Ok(WaitStatus::Stopped(pid, signal::SIGCHLD)) => (), // XXX: deliver SIGCHLD?
        otherwise => panic!("waitpid {} returned unknown status: {:x?}", pid, otherwise),
    };
    let newregs = ptrace::getregs(pid).expect("ptrace getregs");
    ptrace::setregs(pid, oldregs).expect("ptrace setregs");
    if newregs.rax as u64 > (-4096i64) as u64 {
        Err(Error::from_raw_os_error(-(newregs.rax as i64) as i32))
    } else {
        Ok(newregs.rax as i64)
    }
}

fn ensure_syscall(pid: unistd::Pid, rip: u64) -> Result<()> {
    let insn = ptrace::read(pid, rip as ptrace::AddressType).expect("ptrace peek failed") as u64;
    match insn & SYSCALL_INSN_MASK as u64 {
        SYSCALL_INSN => Ok(()),
        _otherwise => Err(Error::new(ErrorKind::Other, format!("expect syscall instructions at {:x}, but got: {:x}", rip, insn))),
    }
}

// so here we are, at ptrace seccomp stop, if we simply resume, the kernel would
// do the syscall, without our patch. we change to syscall number to -1, so that
// kernel would simply skip the syscall, so that we can jump to our patched syscall
// on the first run.
fn skip_seccomp_syscall(pid: unistd::Pid, regs: &libc::user_regs_struct) -> Result<()> {
    let mut new_regs = regs.clone();
    new_regs.orig_rax = -1i64 as u64;
    ptrace::setregs(pid, new_regs).expect("ptrace setregs failed");
    ptrace::step(pid, None).expect("ptrace single step");
    assert!(wait::waitpid(Some(pid), None) == Ok(WaitStatus::Stopped(pid, signal::SIGTRAP)));
    Ok(())
}

fn synchronize_from(task: &mut TracedTask, rip: u64) -> Result<()> {
    let pid = task.pid;
    let saved_insn = ptrace::read(pid, rip as ptrace::AddressType).expect("ptrace peek");
    let new_insn = (saved_insn & !0xff) | 0xcc;
    ptrace::write(pid, rip as ptrace::AddressType, new_insn as *mut libc::c_void).expect("ptrace poke");
    ptrace::cont(pid, None).expect("ptrace cont");
    match wait::waitpid(Some(pid), None) {
        Ok(WaitStatus::Stopped(pid, signal::SIGTRAP)) => (),
        Ok(WaitStatus::Stopped(pid, signal::SIGCHLD)) => {
            task.signal_to_deliver = Some(signal::SIGCHLD)
        },
        otherwise => panic!("waitpid ({}) returend unknown status {:x?}", pid, otherwise)
    };
    let mut regs = ptrace::getregs(pid).expect("ptrace getregs");
    regs.rip -= 1;
    ptrace::write(pid, rip as ptrace::AddressType, saved_insn as *mut libc::c_void).expect("ptrace poke");
    ptrace::setregs(pid, regs).expect("ptrace setregs");
    Ok(())
}

pub fn patch_at(task: &mut TracedTask, regs: libc::user_regs_struct, hook: &hooks::SyscallHook, target: u64) -> Result<()> {
    let resume_from = regs.rip - SYSCALL_INSN_SIZE as u64;
    let jmp_insn_size = 5;
    let ip = resume_from;
    let pid = task.pid;

    let rela: i64 = target as i64 - ip as i64 - jmp_insn_size as i64;
    assert!(rela >= -1i64.wrapping_shl(31) && rela < 1i64.wrapping_shl(31));

    let mut insn_at_syscall = ptrace::read(pid, ip as ptrace::AddressType).expect("ptrace peek failed") as u64;
    // set LSB-40bit to a callq/jmp instruction.
    insn_at_syscall &= !(0xff_ffffffffu64);
    insn_at_syscall |=    0xe8u64
                        | (rela as u64 & 0xff).wrapping_shl(8)
                        | (rela as u64 & 0xff00).wrapping_shl(8)
                        | (rela as u64 & 0xff0000).wrapping_shl(8)
                        | (rela as u64 & 0xff000000).wrapping_shl(8);

    skip_seccomp_syscall(pid, &regs)?;

    ptrace::write(pid, ip as ptrace::AddressType, insn_at_syscall as *mut libc::c_void).expect("ptrace poke failed");

    let padding_size = SYSCALL_INSN_SIZE + hook.instructions.len() - jmp_insn_size as usize;
    assert!(padding_size <= 9);

    let nops: Vec<(usize, u64)> = vec![
        (0, 0x0),
        (1, 0x90),
        (2, 0x9066),
        (3, 0x001f0f),
        (4, 0x00401f0f),
        (5, 0x0000441f0f),
        (6, 0x0000441f0f66),
        (7, 0x00000000801f0f),
        (8, 0x0000000000841f0f),
        (9, 0x0000000000841f0f66),
    ];
    let masks: Vec<u64> = vec![0x0u64, 0xffu64, 0xffffu64, 0xffffffu64, 0xffffffffu64,
                               0xff_ffffffffu64, 0xffff_ffffffffu64,
                               0xffffff_ffffffffu64, 0xffffffff_ffffffffu64];
    if padding_size == 0 {
        ;
    } else if padding_size <= 8 {
        let insn_after_patch = ip + jmp_insn_size;
        let mut padding_insn = ptrace::read(pid, insn_after_patch as ptrace::AddressType).expect("ptrace peek") as u64;
        padding_insn &= !(masks[padding_size]);
        padding_insn |= nops[padding_size].1;
        ptrace::write(pid, insn_after_patch as ptrace::AddressType, padding_insn as *mut libc::c_void).expect("ptrace poke");
    } else if padding_size == 9 {
        let insn_after_patch = ip + jmp_insn_size;
        let insn_after_patch_2 = insn_after_patch + std::mem::size_of::<u64>() as u64;
        ptrace::write(pid, insn_after_patch as ptrace::AddressType, nops[padding_size].1 as *mut libc::c_void).expect("ptrace poke");
        ;
        let mut insn2 = ptrace::read(pid, insn_after_patch_2 as ptrace::AddressType).expect("ptrace peek") as u64;
        insn2 &= !0xff;  // the last byte of the 9-byte nop is 0x00.
        ptrace::write(pid, insn_after_patch as ptrace::AddressType, insn2 as *mut libc::c_void).expect("ptrace poke");
    } else {
        panic!("maximum padding is 9");
    }

    let mut new_regs = regs.clone();
    new_regs.rax = regs.orig_rax; // for our patch, we use rax as syscall no.
    new_regs.rip = ip; // rewind pc back (-2).
    ptrace::setregs(pid, new_regs).expect("ptrace setregs");

    // because we modified tracee's code
    // we need some kind of synchronization to make sure
    // the CPU (especially i-cache) noticed the change
    // hence we set a breakponit at ip (original rip - 2)
    // to force synchronization.
    synchronize_from(task, ip)
}

// search for spare page(s) which can be allocated (mmap) within the
// range of @addr_hint +/- 2GB.
pub fn search_stub_page(pid: Pid, addr_hint: u64, pages: usize) -> Result<u64> {
    let mappings = decode_proc_maps(pid)?;
    let page_size: u64 = 0x1000;
    let one_mb: u64 = 0x100000;
    let almost_2gb: u64 = 2u64.wrapping_shl(30) - 0x100000;
    let mut ranges_from: Vec<(u64, u64)> = Vec::new();
    let mut ranges_to:Vec<(u64, u64)> = Vec::new();

    ranges_from.push((one_mb - page_size, one_mb));
    mappings.iter().for_each(|e|ranges_from.push((e.base(), e.end())));
    mappings.iter().for_each(|e|ranges_to.push((e.base(), e.end())));
    ranges_to.push((0xffffffff_ffff_8000u64, 0xffffffff_ffff_f000u64));
    debug_assert_eq!(ranges_from.len(), ranges_to.len());

    let res: Vec<u64> = ranges_from.iter().zip(ranges_to).filter_map(| ((x1, y1), (x2, y2)) | {
        let space = x2 - y1;
        let start_from = *y1;
        if space >= (pages as u64 * page_size) {
            if start_from <= addr_hint && start_from + almost_2gb >= addr_hint {
                Some(start_from)
            } else if start_from >= addr_hint && start_from - addr_hint <= almost_2gb - (pages as u64 * page_size) {
                Some(start_from)
            } else {
                None
            }
        } else {
            None
        }
    }).collect();

    match res.iter().next() {
        None => Err(Error::new(ErrorKind::Other, format!("cannot allocate stub page for {:x}", addr_hint))),
        Some(addr) => Ok(*addr),
    }
}

#[test]
fn can_find_stub_page() {
    let pid = unistd::getpid();
    let ranges: Vec<(u64, u64)> = decode_proc_maps(pid).unwrap().iter().map(|e|(e.base(), e.end())).collect();
    let addr_hints: Vec<u64> = decode_proc_maps(pid).unwrap().iter().map(|e|e.base()+0x234).collect();
    let two_gb = 2u64.wrapping_shl(30);
    for hint in addr_hints {
        let ret_ = search_stub_page(pid, hint, 1);
        assert!(ret_.is_ok());
        let ret = ret_.unwrap();
        println!("searching {:x} returned {:x}", hint, ret);
        if ret <= hint {
            assert!(hint - ret <= two_gb);
        } else {
            assert!(ret - hint <= two_gb);
        }
        let has_collision = ranges.iter().fold(false, | acc, (start, end) | {
            if acc {
                acc
            } else {
                ret >= *start && ret < *end
            }
        });
        assert!(!has_collision);
    }
}

pub fn gen_syscall_sequences_at(pid: Pid, page_address: u64) -> nix::Result<()> {
    /* the syscall sequences used here:
     * 0:   0f 05                   syscall 
     * 2:   c3                      retq                     // not filered by seccomp, untraced_syscall
     * 3:   90                      nop
     * 4:   0f 05                   syscall                  // traced syscall
     * 6:   c3                      retq   
     * 7:   90                      nop
     * 8:   e8 f3 ff ff ff          callq  0 <_do_syscall>   // untraced syscall, then breakpoint.
     * d:   cc                      int3   
     * e:   66 90                   xchg   %ax,%ax
     * 10:   e8 ef ff ff ff          callq  4 <_do_syscall+0x4> // traced syscall, then breakpoint
     * 15:   cc                      int3   
     * 16:   66 90                   xchg   %ax,%ax
     */
    let syscall_stub: &[u64] = &[ 0x90c3050f90c3050f,
                                  0xe8f7ffffffcc6690,
                                  0xe8efffffffcc6690
    ];
    // please note we force each `ptrace::write` to be exactly ptrace_poke (8 bytes a time)
    // instead of using `process_vm_writev`, because this function can be called in
    // PTRACE_EXEC_EVENT, the process seems not fully loaded by ld-linux.so
    // call process_vm_{readv, writev} would 100% fail.
    for (k, s) in syscall_stub.iter().enumerate() {
        let offset = k * std::mem::size_of::<u64>() + page_address as usize;
        ptrace::write(pid, offset as ptrace::AddressType, *s as *mut libc::c_void)?;
    }
    Ok(())
}
