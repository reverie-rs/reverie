
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
use crate::task::{Task};
use crate::traced_task::TracedTask;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallStubPage {
    pub address: u64,
    pub size: usize,
    pub allocated: usize,
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
    pub fn as_ptr(self) -> *mut T {
        self.ptr.as_ptr()
    }
    pub fn cast<U>(self) -> RemotePtr<U> {
        RemotePtr{ptr: self.ptr.cast::<U>()}
    }
}

impl <T> Clone for RemotePtr<T> {
    fn clone(&self) -> Self {
        RemotePtr{ptr: self.ptr.clone()}
    }
}

pub trait RemoteSyscall {
    fn untraced_syscall(&mut self, nr: nr::SyscallNo, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<i64>;
}

pub trait Remote {
    fn peek_bytes(&self, addr: RemotePtr<u8>, size: usize) -> Result<Vec<u8>>;
    fn poke_bytes(&self, addr: RemotePtr<u8>, bytes: &[u8]) -> Result<()>;
    fn peek<T>(&self, addr: RemotePtr<T>) -> Result<T>
        where T: Sized
    {
        let new_ptr = addr.cast::<u8>();
        let size = std::mem::size_of::<T>();
        let bytes: Vec<u8> = self.peek_bytes(new_ptr, size)?;
        // to be initialized by copy_nonoverlapping.
        let mut res: T = unsafe { std::mem::uninitialized() };
        let ret_ptr: *mut T = &mut res;
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const T, ret_ptr, size) };
        Ok(res)
    }
    fn poke<T>(&self, addr: RemotePtr<T>, value: &T) -> Result<()>
        where T: Sized
    {
        let value_ptr: *const T = value;
        let size = std::mem::size_of::<T>();
        let new_ptr = addr.cast::<u8>();
        let bytes: &[u8] = unsafe {
            let raw_bytes = std::mem::transmute(value_ptr as *const u8);
            std::slice::from_raw_parts(raw_bytes, size)
        };
        self.poke_bytes(new_ptr, bytes)?;
        Ok(())
    }
    fn getregs(&self) -> Result<libc::user_regs_struct>;
    fn setregs(&self, regs: libc::user_regs_struct) -> Result<()>;
    fn getevent(&self) -> Result<i64>;
    fn resume(&self, sig: Option<signal::Signal>) -> Result<()>;
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
    let pid = task.getpid();
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
