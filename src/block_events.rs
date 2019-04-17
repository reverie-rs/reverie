
pub enum BlockingEvents {
    BlockOnFdRead(i32),
    BlockOnFdWrite(i32),
    BlockOnFdPri(i32),

    // waitpid
    BlockOnPid(u32),
    BlockOnAnyChild,
    BlockOnAnyChildPgid(u32),

    BlockOnTimeoutRel(u64),

    // futex
    BlockOnFutexWait(u64, u64),
    BlockOnFutexWaitBit(u64, u64),
    BlockOnFutexLockPI(u64),

    BlockOnSignal(u64),
}
