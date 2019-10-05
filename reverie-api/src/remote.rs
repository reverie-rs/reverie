use std::ffi::CString;
use std::ptr::NonNull;

use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::uio;
use nix::sys::wait;
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid;
use std::io::{Error, Result};
use syscalls::*;

use crate::task::*;

/// a pointer belongs to tracee's address space
#[derive(Debug, PartialEq, Eq)]
pub struct RemotePtr<T> {
    ptr: NonNull<T>,
}

impl<T> RemotePtr<T>
where
    T: Sized,
{
    pub fn new(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(|nll| RemotePtr { ptr: nll })
    }
    pub fn as_ptr(self) -> *mut T {
        self.ptr.as_ptr()
    }
    pub fn cast<U>(self) -> RemotePtr<U> {
        RemotePtr {
            ptr: self.ptr.cast(),
        }
    }
    pub unsafe fn offset(self, count: isize) -> Self {
        RemotePtr {
            ptr: NonNull::new(self.ptr.as_ptr().offset(count)).unwrap(),
        }
    }
}

impl<T> Clone for RemotePtr<T> {
    fn clone(&self) -> Self {
        RemotePtr { ptr: self.ptr }
    }
}

impl<T: Sized> Copy for RemotePtr<T> {}

#[derive(PartialEq, Eq)]
pub struct LocalPtr<T>(NonNull<T>);

impl<T> Clone for LocalPtr<T> {
    fn clone(&self) -> Self {
        LocalPtr(self.0)
    }
}

impl<T: Sized> Copy for LocalPtr<T> {}

impl<T> LocalPtr<T> {
    pub fn new(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(|p| LocalPtr(p))
    }
    pub fn as_ptr(self) -> *mut T {
        self.0.as_ptr()
    }
    pub fn cast<U>(self) -> LocalPtr<U> {
        LocalPtr(self.0.cast())
    }
    pub unsafe fn offset(self, count: isize) -> Self {
        LocalPtr(NonNull::new(self.0.as_ptr().offset(count)).unwrap())
    }
}

/// A reference to an object that MAY reside on another machine.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Remoteable<T> {
    Local(LocalPtr<T>),
    Remote(RemotePtr<T>),
}

impl<T> std::fmt::Display for Remoteable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Remoteable::Remote(rptr) => write!(f, "{:x?}", rptr.as_ptr()),
            Remoteable::Local(lptr) => write!(f, "{:x?}", lptr.as_ptr()),
        }
    }
}

impl<T> std::fmt::Debug for Remoteable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Remoteable::Remote(rptr) => write!(f, "{:x?}", rptr.as_ptr()),
            Remoteable::Local(lptr) => write!(f, "{:x?}", lptr.as_ptr()),
        }
    }
}

impl<T> Remoteable<T>
where
    T: Sized,
{
    pub fn local(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(|nll| Remoteable::Local(LocalPtr(nll)))
    }
    pub fn remote(ptr: *mut T) -> Option<Self> {
        RemotePtr::new(ptr).map(|nll| Remoteable::Remote(nll))
    }
    pub unsafe fn offset(self, count: isize) -> Self {
        match self {
            Remoteable::Local(lptr) => Remoteable::Local(LocalPtr(
                NonNull::new(lptr.as_ptr().offset(count)).unwrap(),
            )),
            Remoteable::Remote(rptr) => Remoteable::Remote(rptr.offset(count)),
        }
    }
    pub fn cast<U>(self) -> Remoteable<U> {
        match self {
            Remoteable::Local(lptr) => Remoteable::Local(lptr.cast::<U>()),
            Remoteable::Remote(rptr) => Remoteable::Remote(rptr.cast::<U>()),
        }
    }

    pub fn as_ptr(self) -> *mut T {
        match self {
            Remoteable::Local(lptr) => lptr.as_ptr(),
            Remoteable::Remote(rptr) => rptr.as_ptr(),
        }
    }
}

pub trait GuestMemoryAccess {
    /// peek bytes from inferior
    fn peek_bytes(&self, addr: Remoteable<u8>, size: usize) -> Result<Vec<u8>>;
    /// poke bytes into inferior
    fn poke_bytes(&self, addr: Remoteable<u8>, bytes: &[u8]) -> Result<()>;
    /// peek a `Sized` remote pointer from inferior
    fn peek<T>(&self, addr: Remoteable<T>) -> Result<T>
    where
        T: Sized,
    {
        match addr {
            Remoteable::Local(lptr) => {
                let v = unsafe { std::ptr::read(lptr.as_ptr()) };
                Ok(v)
            }
            Remoteable::Remote(rptr) => {
                let new_ptr = rptr.cast::<u8>();
                let size = std::mem::size_of::<T>();
                let bytes: Vec<u8> =
                    self.peek_bytes(Remoteable::Remote(new_ptr), size)?;
                let mut uninit = std::mem::MaybeUninit::<T>::uninit();
                let res = unsafe {
                    std::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        uninit.as_mut_ptr() as *mut u8,
                        size,
                    );
                    uninit.assume_init()
                };
                Ok(res)
            }
        }
    }
    /// poke a `Sized` remote pointer from inferior
    fn poke<T>(&self, addr: Remoteable<T>, value: &T) -> Result<()>
    where
        T: Sized,
    {
        match addr {
            Remoteable::Local(lptr) => {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        value as *const T,
                        lptr.as_ptr(),
                        std::mem::size_of::<T>(),
                    )
                };
                Ok(())
            }
            Remoteable::Remote(rptr) => {
                let value_ptr = value as *const T;
                let size = std::mem::size_of::<T>();
                let new_ptr = rptr.cast::<u8>();
                let bytes: &[u8] = unsafe {
                    std::slice::from_raw_parts(value_ptr as *const u8, size)
                };
                self.poke_bytes(Remoteable::Remote(new_ptr), bytes)?;
                Ok(())
            }
        }
    }

    /// peek null terminated C-style string
    fn peek_cstring<'a>(&self, addr: Remoteable<i8>) -> Result<CString> {
        match addr {
            Remoteable::Local(lptr) => {
                let cstr =
                    unsafe { std::ffi::CString::from_raw(lptr.as_ptr()) };
                Ok(cstr)
            }
            Remoteable::Remote(rptr) => {
                let mut v: Vec<u8> = Vec::new();
                let mut p: Remoteable<i8> = Remoteable::Remote(rptr.cast());
                loop {
                    let t: u64 = self.peek(p.cast())?;
                    if t & 0xff == 0 {
                        break;
                    } else if t & 0xff00 == 0 {
                        v.push((t & 0xff) as u8);
                        break;
                    } else if t & 0xff_0000 == 0 {
                        v.push((t & 0xff) as u8);
                        v.push(((t >> 8) & 0xff) as u8);
                        break;
                    } else if t & 0xff00_0000 == 0 {
                        v.push((t & 0xff) as u8);
                        v.push(((t >> 8) & 0xff) as u8);
                        v.push(((t >> 16) & 0xff) as u8);
                        break;
                    } else if t & 0xff_0000_0000 == 0 {
                        v.push((t & 0xff) as u8);
                        v.push(((t >> 8) & 0xff) as u8);
                        v.push(((t >> 16) & 0xff) as u8);
                        v.push(((t >> 24) & 0xff) as u8);
                        break;
                    } else if t & 0xff00_0000_0000 == 0 {
                        v.push((t & 0xff) as u8);
                        v.push(((t >> 8) & 0xff) as u8);
                        v.push(((t >> 16) & 0xff) as u8);
                        v.push(((t >> 24) & 0xff) as u8);
                        v.push(((t >> 32) & 0xff) as u8);
                        break;
                    } else if t & 0xff_0000_0000_0000 == 0 {
                        v.push((t & 0xff) as u8);
                        v.push(((t >> 8) & 0xff) as u8);
                        v.push(((t >> 16) & 0xff) as u8);
                        v.push(((t >> 24) & 0xff) as u8);
                        v.push(((t >> 32) & 0xff) as u8);
                        v.push(((t >> 40) & 0xff) as u8);
                        break;
                    } else if t & 0xff00_0000_0000_0000 == 0 {
                        v.push((t & 0xff) as u8);
                        v.push(((t >> 8) & 0xff) as u8);
                        v.push(((t >> 16) & 0xff) as u8);
                        v.push(((t >> 24) & 0xff) as u8);
                        v.push(((t >> 32) & 0xff) as u8);
                        v.push(((t >> 40) & 0xff) as u8);
                        v.push(((t >> 48) & 0xff) as u8);
                        break;
                    } else {
                        v.push((t & 0xff) as u8);
                        v.push(((t >> 8) & 0xff) as u8);
                        v.push(((t >> 16) & 0xff) as u8);
                        v.push(((t >> 24) & 0xff) as u8);
                        v.push(((t >> 32) & 0xff) as u8);
                        v.push(((t >> 40) & 0xff) as u8);
                        v.push(((t >> 48) & 0xff) as u8);
                        v.push(((t >> 56) & 0xff) as u8);
                        p = unsafe {
                            p.offset(std::mem::size_of::<u64>() as isize)
                        };
                    }
                }
                let cstr = unsafe { CString::from_vec_unchecked(v) };
                Ok(cstr)
            }
        }
    }
}

/// trait implements most ptrace interface.
pub trait Ptracer: GuestMemoryAccess {
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
}

fn from_nix_error(err: nix::Error) -> Error {
    Error::new(std::io::ErrorKind::Other, err)
}

/// peek bytes from inferior
pub fn ptrace_peek_bytes(
    pid: Pid,
    addr: RemotePtr<u8>,
    size: usize,
) -> Result<Vec<u8>> {
    if size <= std::mem::size_of::<u64>() {
        let raw_ptr = addr.as_ptr();
        let x = ptrace::read(pid, raw_ptr as ptrace::AddressType)
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
        uio::process_vm_readv(pid, local_iov, remote_iov)
            .map_err(from_nix_error)?;
        Ok(res)
    }
}

/// poke bytes into inferior
pub fn ptrace_poke_bytes(
    pid: Pid,
    addr: RemotePtr<u8>,
    bytes: &[u8],
) -> Result<()> {
    let size = bytes.len();
    if size <= std::mem::size_of::<u64>() {
        let raw_ptr = addr.as_ptr();
        let mut u64_val = if size < std::mem::size_of::<u64>() {
            ptrace::read(pid, raw_ptr as ptrace::AddressType)
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
            pid,
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
        uio::process_vm_writev(pid, local_iov, remote_iov)
            .map_err(from_nix_error)?;
        Ok(())
    }
}

/// The 6 arguments of a syscall, raw untyped version.
///
/// TODO: Use a helper function to convert to a structured Syscall+Args enum.
#[derive(PartialEq, Debug, Eq, Clone, Copy)]
pub struct SyscallArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

impl SyscallArgs {
    pub fn from(a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> Self {
        SyscallArgs {
            arg0: a0,
            arg1: a1,
            arg2: a2,
            arg3: a3,
            arg4: a4,
            arg5: a5,
        }
    }
}

// The value returned in RAX on x86_64:
pub type SysCallRet = i64;

// syscall number
pub type SysNo = i32;

pub type FunAddr = Remoteable<u64>;

/// Run code *inside* a guest process.
///
/// The Injector interface provides the "downcalls".
/// The injector inserts either new system calls or function calls into the guest.  
/// It does *not* create (JIT compile) new functions in the guest, rather it calls
/// existing functions. (Though it does inject new code in the case of individual syscalls.)
///
/// NOTE: there is currently no way to inject *signals* into the guest.  Rather, one must
/// inject the functional calls, and instead intercept and prevent attempts by the guest
/// to register signal handlers in the first place.
pub trait Injector {
    /// Inject a system call into the guest and wait for the return value
    fn inject_syscall(&self, nr: SyscallNo, args: &SyscallArgs) -> i64;

    /// Look up the symbol address within the guest.
    /// only symbols from dso passwd by `--tool` is looked up
    fn resolve_symbol_address(&self, sym: &str) -> Option<FunAddr>;

    /// Call a function in the guest.
    /// Even though function ABI is a lot more flexibile
    /// we only allow syscall style function calls, that is,
    /// up to six arguments without fpu/vector.
    fn inject_funcall(&self, func: FunAddr, args: &SyscallArgs);

    // Wait for the guest to exit.
    // fn wait_exit(&self);

    // inject_signal(...) -> ...;
}

/// inject syscall for given tracee
///
/// NB: limitations:
/// - tracee must be in stopped state.
/// - the tracee must have returned from PTRACE_EXEC_EVENT
pub fn untraced_syscall(
    task: &dyn Task,
    nr: SyscallNo,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> i64 {
    let tid = task.gettid();
    let mut regs = ptrace::getregs(tid).unwrap();
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
    regs.rip = 0x7000_0008;

    ptrace::setregs(task.gettid(), regs).unwrap();
    ptrace::cont(tid, None).unwrap();

    wait_sigtrap_sigchld(tid).unwrap();

    let newregs = ptrace::getregs(tid).unwrap();
    ptrace::setregs(tid, oldregs).unwrap();
    newregs.rax as i64
}

// wait either SIGTRAP (breakpoint) or SIGCHLD.
fn wait_sigtrap_sigchld(pid: Pid) -> Result<Option<signal::Signal>> {
    let mut signal_to_deliver = None;
    let status = wait::waitpid(pid, None).expect("waitpid");
    match status {
        WaitStatus::Stopped(_pid, signal::SIGTRAP) => (),
        WaitStatus::Stopped(_pid, signal::SIGCHLD) => {
            signal_to_deliver = Some(signal::SIGCHLD)
        }
        otherwise => {
            panic!(
                "task {} expecting SIGTRAP|SIGCHLD but got {:?}",
                pid, otherwise
            );
        }
    };
    Ok(signal_to_deliver)
}

/// inject syscall for given tracee
///
/// NB: limitations:
/// - tracee must be in stopped state.
/// - the tracee must have returned from PTRACE_EXEC_EVENT
pub fn ptraced_syscall(
    pid: Pid,
    nr: SyscallNo,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) {
    let mut regs = ptrace::getregs(pid).unwrap();

    let no = nr as u64;
    regs.orig_rax = no;
    regs.rax = no;
    regs.rdi = a0 as u64;
    regs.rsi = a1 as u64;
    regs.rdx = a2 as u64;
    regs.r10 = a3 as u64;
    regs.r8 = a4 as u64;
    regs.r9 = a5 as u64;

    ptrace::setregs(pid, regs).unwrap();
    ptrace::syscall(pid).unwrap();
}
