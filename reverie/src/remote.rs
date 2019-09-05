//! `remote` implements APIs so that tracer can control tracees by ptrace interface
use libc;
use log::debug;
use nix::sys::wait::WaitStatus;
use nix::sys::{ptrace, signal};
use nix::unistd;
use nix::unistd::Pid;
use procfs;
use std::ffi::c_void;
use std::io::{Error, ErrorKind, Result};
use std::path::PathBuf;
use std::ptr::NonNull;

use reverie_common::consts;
use reverie_common::consts::*;

use crate::hooks;
use crate::nr;
use crate::nr::SyscallNo;
use crate::nr::SyscallNo::*;
use crate::stubs;
use crate::task::{RunTask, Task};
use crate::traced_task::TracedTask;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallStubPage {
    pub address: u64,
    pub size: usize,
    pub allocated: usize,
}

/// a pointer belongs to tracee's address space
#[derive(Debug)]
pub struct RemotePtr<T> {
    ptr: NonNull<T>,
}

impl<T> RemotePtr<T>
where
    T: Sized,
{
    pub fn new(ptr: *mut T) -> Self {
        RemotePtr {
            ptr: NonNull::new(ptr).unwrap(),
        }
    }
    pub fn as_ptr(self) -> *mut T {
        self.ptr.as_ptr()
    }
    pub fn cast<U>(self) -> RemotePtr<U> {
        RemotePtr {
            ptr: self.ptr.cast::<U>(),
        }
    }
    pub unsafe fn offset(self, count: isize) -> Self {
        RemotePtr {
            ptr: NonNull::new(self.as_ptr().offset(count)).unwrap(),
        }
    }
}

impl<T> Clone for RemotePtr<T> {
    fn clone(&self) -> Self {
        RemotePtr { ptr: self.ptr }
    }
}

impl<T: Sized> Copy for RemotePtr<T> {}

/// doing syscalls from the tracer on behalf of tracee
pub trait RemoteSyscall {
    /// inject syscall into tracee and return the syscall
    /// return value. the injected syscall won't be trapped
    /// by seccomp.
    fn untraced_syscall(
        &mut self,
        nr: nr::SyscallNo,
        a0: i64,
        a1: i64,
        a2: i64,
        a3: i64,
        a4: i64,
        a5: i64,
    ) -> Result<i64>;
}

/// trait implements most ptrace interface.
pub trait Remote {
    /// peek bytes from inferior
    fn peek_bytes(&self, addr: RemotePtr<u8>, size: usize) -> Result<Vec<u8>>;
    /// poke bytes into inferior
    fn poke_bytes(&self, addr: RemotePtr<u8>, bytes: &[u8]) -> Result<()>;
    /// peek a `Sized` remote pointer from inferior
    fn peek<T>(&self, addr: RemotePtr<T>) -> Result<T>
    where
        T: Sized,
    {
        let new_ptr = addr.cast::<u8>();
        let size = std::mem::size_of::<T>();
        let bytes: Vec<u8> = self.peek_bytes(new_ptr, size)?;
        // to be initialized by copy_nonoverlapping.
        let mut res = std::mem::MaybeUninit::<T>::uninit();
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                res.as_mut_ptr() as *mut u8,
                size,
            )
        };
        Ok(unsafe { res.assume_init() })
    }
    /// poke a `Sized` remote pointer from inferior
    fn poke<T>(&self, addr: RemotePtr<T>, value: &T) -> Result<()>
    where
        T: Sized,
    {
        let value_ptr: *const T = value;
        let size = std::mem::size_of::<T>();
        let new_ptr = addr.cast::<u8>();
        let bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(value_ptr as *const u8, size) };
        self.poke_bytes(new_ptr, bytes)?;
        Ok(())
    }
    /// get inferior user regs
    fn getregs(&self) -> Result<libc::user_regs_struct>;
    /// set inferior user regs
    fn setregs(&self, regs: libc::user_regs_struct) -> Result<()>;
    /// get inferior ptrace event
    fn getevent(&self) -> Result<i64>;
    /// resume a stopped inferior
    fn resume(&self, sig: Option<signal::Signal>) -> Result<()>;
    /// single step a stopped inferior
    fn step(&self, sig: Option<signal::Signal>) -> Result<()>;
    /// get `siginfo_t` from stopped inferior
    fn getsiginfo(&self) -> Result<libc::siginfo_t>;

    /// set breakpoint at inferior `addr` with handler `op`.
    fn setbp<F>(&mut self, addr: RemotePtr<c_void>, op: F) -> Result<()>
    where
        F: 'static
            + FnOnce(TracedTask, RemotePtr<c_void>) -> Result<RunTask<TracedTask>>;
}

/// tell the tracee to do context synchronization at given `rip`
///
/// NB: this is required when tracee modified its code region
/// where the same code region is shared by other threads in the
/// same thread group.
///
/// the synchronization is done by injecting `cpuid` sequence as
/// recomended by the Intel's programmer's manual.
pub fn synchronize_from(task: &TracedTask, rip: u64) {
    let mut regs = task.getregs().unwrap();
    // stub for cpuid routine
    regs.rip = 0x7000_0018u64;
    // push return address
    regs.rsp -= 8;
    let remote_return_address_ptr = RemotePtr::new(regs.rsp as *mut u64);
    let remote_return_address = rip;
    task.poke(remote_return_address_ptr, &remote_return_address)
        .unwrap();
    task.setregs(regs).unwrap();
}

pub fn remote_do_syscall(
    task: &TracedTask,
    nr: SyscallNo,
    a0: i64,
    a1: i64,
    a2: i64,
    a3: i64,
    a4: i64,
    a5: i64,
) -> Result<()> {
    let mut regs = task.getregs()?;
    let syscall_helper_addr_ptr =
        RemotePtr::new(consts::REVERIE_LOCAL_SYSCALL_HELPER as *mut u64);
    let syscall_helper_addr = task.peek(syscall_helper_addr_ptr)?;
    let return_address = regs.rip;
    regs.rip = syscall_helper_addr;
    regs.rsp -= 9 * 8; // return_address + nr + a0-a5 + pad
    let remote_rsp = RemotePtr::new(regs.rsp as *mut i64);
    let regs_to_save =
        vec![0, a5, a4, a3, a2, a1, a0, nr as i64, return_address as i64];
    regs_to_save.iter().enumerate().for_each(|(k, x)| {
        let current_rsp = unsafe { remote_rsp.offset(k as isize) };
        task.poke(current_rsp, x).unwrap();
    });
    task.setregs(regs)
}

/// patch a given syscall sequence at `rip` with provided `hook`
/// target is a indirect interim jump, who then jump to the final
/// trampoline.
///
/// NB: this function calls `synchronized_from`
///
pub fn patch_syscall_at(
    task: &mut TracedTask,
    syscall: SyscallNo,
    hook: &hooks::SyscallHook,
    target: u64,
) {
    let jmp_insn_size = 5i64;
    let regs = task.getregs().unwrap();
    let resume_from = regs.rip - SYSCALL_INSN_SIZE as u64;
    let ip = resume_from;
    let rela: i64 = target as i64 - ip as i64 - jmp_insn_size;
    assert!(rela >= -(1i64.wrapping_shl(31)) && rela < 1i64.wrapping_shl(31));

    let mut patch_bytes: Vec<u8> = Vec::new();

    let remote_rip = RemotePtr::new(ip as *mut u8);

    patch_bytes.push(0xe8);
    patch_bytes.push((rela & 0xff) as u8);
    patch_bytes.push((rela.wrapping_shr(8) & 0xff) as u8);
    patch_bytes.push((rela.wrapping_shr(16) & 0xff) as u8);
    patch_bytes.push((rela.wrapping_shr(24) & 0xff) as u8);

    let padding_size =
        SYSCALL_INSN_SIZE + hook.instructions.len() - jmp_insn_size as usize;
    assert!(padding_size <= 9);

    match padding_size {
        0 => (),
        1 => patch_bytes.push(0x90),
        2 => {
            patch_bytes.push(0x66);
            patch_bytes.push(0x90);
        }
        3 => {
            patch_bytes.push(0x0f);
            patch_bytes.push(0x1f);
            patch_bytes.push(0x00);
        }
        4 => {
            patch_bytes.push(0x0f);
            patch_bytes.push(0x1f);
            patch_bytes.push(0x40);
            patch_bytes.push(0x00);
        }
        5 => {
            patch_bytes.push(0x0f);
            patch_bytes.push(0x1f);
            patch_bytes.push(0x44);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
        }
        6 => {
            patch_bytes.push(0x66);
            patch_bytes.push(0x0f);
            patch_bytes.push(0x1f);
            patch_bytes.push(0x44);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
        }
        7 => {
            patch_bytes.push(0x0f);
            patch_bytes.push(0x1f);
            patch_bytes.push(0x80);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
        }
        8 => {
            patch_bytes.push(0x0f);
            patch_bytes.push(0x1f);
            patch_bytes.push(0x84);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
        }
        9 => {
            patch_bytes.push(0x66);
            patch_bytes.push(0x0f);
            patch_bytes.push(0x1f);
            patch_bytes.push(0x84);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
            patch_bytes.push(0x00);
        }
        _ => panic!("maximum padding is 9"),
    };
    assert_eq!(
        patch_bytes.len(),
        hook.instructions.len() + consts::SYSCALL_INSN_SIZE
    );
    let patch_head: Vec<_> = patch_bytes
        .iter()
        .cloned()
        .take(SYSCALL_INSN_SIZE)
        .collect();
    let patch_tail: Vec<_> = patch_bytes
        .iter()
        .cloned()
        .skip(SYSCALL_INSN_SIZE)
        .collect();
    let original_bytes =
        task.peek_bytes(remote_rip, patch_bytes.len()).unwrap();
    // split into chunks so that ptrace::write is called
    // explicitly avoid process_vm_writev because the later
    // requires memory map permission change
    // since bytes to write is small, we can save the permission
    // change and restore, which requires two mprotect
    for (k, chunk) in patch_tail.chunks(std::mem::size_of::<u64>()).enumerate()
    {
        let rptr: RemotePtr<u8> = RemotePtr::new(
            (ip as usize + k * std::mem::size_of::<u64>() + SYSCALL_INSN_SIZE)
                as *mut u8,
        );
        task.poke_bytes(rptr, chunk).unwrap();
    }
    task.poke_bytes(remote_rip, patch_head.as_slice()).unwrap();
    debug!(
        "{} patched {:?}@{:x} {:02x?} => {:02x?} (callq {:x})",
        task.gettid(),
        syscall,
        ip,
        original_bytes,
        patch_bytes,
        target
    );
    let mut new_regs = regs;
    new_regs.rax = regs.orig_rax; // for our patch, we use rax as syscall no.
    new_regs.rip = ip; // rewind pc back (-2).
    task.setregs(new_regs).unwrap();
    // because we modified tracee's code
    // we need some kind of synchronization to make sure
    // the CPU (especially i-cache) noticed the change
    // hence we set a breakponit at ip (original rip - 2)
    // to force synchronization.
    synchronize_from(task, ip)
}

/// search for spare page(s) which can be allocated (mmap) within the
/// range of @addr_hint +/- 2GB.
pub fn search_stub_page(pid: Pid, addr_hint: u64, pages: usize) -> Result<u64> {
    let mappings = procfs::Process::new(pid.as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new());
    let page_size: u64 = 0x1000;
    let one_mb: u64 = 0x100000;
    let almost_2gb: u64 = 2u64.wrapping_shl(30) - 0x100000;
    let mut ranges_from: Vec<(u64, u64)> = Vec::new();
    let mut ranges_to: Vec<(u64, u64)> = Vec::new();

    ranges_from.push((one_mb - page_size, one_mb));
    mappings
        .iter()
        .for_each(|e| ranges_from.push((e.address.0, e.address.1)));
    mappings
        .iter()
        .for_each(|e| ranges_to.push((e.address.0, e.address.1)));
    ranges_to.push((0xffffffff_ffff_8000u64, 0xffffffff_ffff_f000u64));
    debug_assert_eq!(ranges_from.len(), ranges_to.len());

    let res: Vec<u64> = ranges_from
        .iter()
        .zip(ranges_to)
        .filter_map(|((_x1, y1), (x2, _y2))| {
            let space = x2 - y1;
            let start_from = *y1;
            if space >= (pages as u64 * page_size) {
                if (start_from <= addr_hint
                    && start_from + almost_2gb >= addr_hint)
                    || (start_from >= addr_hint
                        && start_from - addr_hint
                            <= almost_2gb - (pages as u64 * page_size))
                {
                    Some(start_from)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    match res.iter().next() {
        None => Err(Error::new(
            ErrorKind::Other,
            format!("cannot allocate stub page for {:x}", addr_hint),
        )),
        Some(addr) => Ok(*addr),
    }
}

#[test]
fn can_find_stub_page() {
    let pid = unistd::getpid();
    let ranges: Vec<_> = procfs::Process::new(pid.as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .map(|e| e.address)
        .collect();
    let addr_hints: Vec<u64> = procfs::Process::new(pid.as_raw())
        .and_then(|p| p.maps())
        .unwrap_or_else(|_| Vec::new())
        .iter()
        .map(|e| e.address.0 + 0x234)
        .collect();
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
        let has_collision = ranges.iter().fold(false, |acc, (start, end)| {
            if acc {
                acc
            } else {
                ret >= *start && ret < *end
            }
        });
        assert!(!has_collision);
    }
}

/// generate syscall instructions at injected page
/// the page address should be 0x7000_0000
/// the byte code can be confirmed by running objcopy
/// x86_64-linux-gnu-objcopy -I binary /tmp/1.bin -O elf64-x86-64 -B i386:x86-64 /tmp/1.elf
/// then objdump -d 1.elf must match the instructions listed below.
pub fn gen_syscall_sequences_at(
    pid: Pid,
    page_address: u64,
) -> nix::Result<()> {
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
     * 10:  e8 ef ff ff ff          callq  4 <_do_syscall+0x4> // traced syscall, then breakpoint
     * 15:  cc                      int3
     * 16:  66 90                   xchg   %ax,%ax
     * 18:  50                   	push   %rax
     * 19:  53                   	push   %rbx
     * 1a:  51                   	push   %rcx
     * 1b:  52                   	push   %rdx
     * 1c:  b8 00 00 00 00       	mov    $0x0,%eax
     * 21:  0f a2                	cpuid
     * 23:  5a                   	pop    %rdx
     * 24:  59                   	pop    %rcx
     * 25:  5b                   	pop    %rbx
     * 26:  58                   	pop    %rax
     * 27:  c3                   	retq
     * 28:  50                   	push   %rax
     * 29:  53                   	push   %rbx
     * 2a:  51                   	push   %rcx
     * 2b:  52                   	push   %rdx
     * 2c:  b8 00 00 00 00       	mov    $0x0,%eax
     * 31:  0f a2                	cpuid
     * 33:  5a                   	pop    %rdx
     * 34:  59                   	pop    %rcx
     * 35:  5b                   	pop    %rbx
     * 36:  58                   	pop    %rax
     * 37:  cc                   	int3
     */
    let syscall_stub: &[u64] = &[
        0x90c3050f90c3050f,
        0x9066ccfffffff3e8,
        0x9066ccffffffefe8,
        0x000000b852515350,
        0xc3585b595aa20f00,
        0x000000b852515350,
        0xcc585b595aa20f00,
    ];
    // please note we force each `ptrace::write` to be exactly ptrace_poke (8 bytes a time)
    // instead of using `process_vm_writev`, because this function can be called in
    // PTRACE_EXEC_EVENT, the process seems not fully loaded by ld-linux.so
    // call process_vm_{readv, writev} would 100% fail.
    for (k, s) in syscall_stub.iter().enumerate() {
        let offset = k * std::mem::size_of::<u64>() + page_address as usize;
        ptrace::write(
            pid,
            offset as ptrace::AddressType,
            *s as *mut libc::c_void,
        )?;
    }
    Ok(())
}
