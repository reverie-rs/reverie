
use crate::syscall::nr::*;
use crate::syscall::raw::*;
use crate::io::*;

fn syscall_ret(ret: i64) -> Result<i64, i64> {
    let t :i64 = -4096;
    if ret as u64 > t as u64 {
        Err(-ret)
    } else {
        Ok(ret)
    }
}

pub fn syscall(no: i32, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> Result<i64, i64> {
    syscall_ret(untraced_syscall(no, a0, a1, a2, a3, a4, a5))
}

pub fn __mmap(addr: *mut (), length: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> Result<*mut (), i64> {
    syscall(MMAP as i32, addr as i64, length as i64, prot as i64, flags as i64, fd as i64, offset as i64).map(|x| x as *mut _)
}

pub fn __munmap(ptr: *mut (), size: usize) -> Result<i32, i64> {
    syscall(MUNMAP as i32, ptr as i64, size as i64, 0, 0, 0, 0).map(|x| x as i32)
}

pub fn __mremap(old_addr: *mut (), old_size: usize, new_size: usize, flags: i32) -> Result<i32, i64> {
    syscall(MREMAP as i32, old_addr as i64, old_size as i64, new_size as i64, flags as i64, 0, 0).map(|x| x as i32)
}

pub fn __mprotect(addr: *mut (), len: usize, prot: i32) -> Result<(), i64> {
    syscall(MPROTECT as i32, addr as i64, len as i64, prot as i64, 0, 0, 0).map(|_| ())
}

pub fn __madvise(addr: *mut (), len: usize, advise: i32) -> Result<(), i64> {
    syscall(MADVISE as i32, addr as i64, len as i64, advise as i64, 0, 0, 0).map(|_| ())
}
