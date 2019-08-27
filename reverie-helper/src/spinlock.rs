//!
//! static spinlocks allow nested locking.
//! the same thread can do nested spin locks, however
//! there must be matching amount of spin unlocks
//! unlock a lock locked by other thread will panic
//!
use core::sync::atomic::{AtomicUsize, Ordering};

use syscalls::syscall;

/// spinlock struct
#[derive(Default)]
pub struct SpinLock {
    __lock: AtomicUsize,
}

const NEST_LEVEL_SHIFT: u32 = 48;
#[allow(unused)]
const NEST_LEVEL_MASK: usize = 0xffffusize.wrapping_shl(NEST_LEVEL_SHIFT);
const THREAD_ID_SHIFT: u32 = 0;
const THREAD_ID_MASK: usize = 0xffffffffffffusize;

#[allow(unused)]
fn nest_level(x: usize) -> usize {
    (x & NEST_LEVEL_MASK).wrapping_shr(NEST_LEVEL_SHIFT)
}

fn thread_id(x: usize) -> usize {
    (x & THREAD_ID_MASK).wrapping_shr(THREAD_ID_SHIFT)
}

fn level_tid(level: usize, tid: usize) -> usize {
    level.wrapping_shl(NEST_LEVEL_SHIFT) | tid
}

fn inc_level(x: usize) -> usize {
    x + 1usize.wrapping_shl(NEST_LEVEL_SHIFT)
}

fn dec_level(x: usize) -> usize {
    x - 1usize.wrapping_shl(NEST_LEVEL_SHIFT)
}

impl SpinLock {
    /// create a new (unlocked) spinlock
    pub const fn new() -> Self {
        SpinLock { __lock: AtomicUsize::new(0) }
    }
    /// obtain a spinlock
    pub fn lock(&self) {
        __spin_lock(&self.__lock);
    }
    /// release a spinlock
    pub fn unlock(&self) {
        __spin_unlock(&self.__lock);
    }
}

fn gettid() -> usize {
    let tid = syscall!(SYS_gettid);
    tid.unwrap() as usize
}

fn __spin_lock(lock: &AtomicUsize) {
    let tid = gettid();

    loop {
        match lock
            .compare_exchange(0,
                              level_tid(1, tid),
                              Ordering::Acquire,
                              Ordering::Relaxed) {
                Ok(_) => break,
                Err(old) if thread_id(old) == tid => {
                    lock.store(inc_level(old), Ordering::SeqCst);
                    break;
                }
                _ => continue,
        }
    }
}

fn __spin_unlock(lock: &AtomicUsize) {
    let tid = gettid();
    let expected = level_tid(1, tid);
    match lock.compare_exchange(
        expected,
        0,
        Ordering::Release,
        Ordering::Relaxed) {
        Ok(_) => (),
        Err(old) if thread_id(old) == tid => {
            lock.store(dec_level(old), Ordering::SeqCst);
        }
        _ => panic!("trying to unlock a spinlock belongs to others"),
    }
}
