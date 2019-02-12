pub const SYSTRACE_LIBRARY_PATH: &'static str = "SYSTRACE_LIBRARY_PATH";
pub const SYSTRACE_SO: &'static str = "libsystrace.so";
pub const DET_SO: &'static str = "libdet.so";

pub const SYSCALL_INSN_SIZE: usize = 2;
pub const SYSCALL_INSN_MASK: u64 = 0xffff;
pub const SYSCALL_INSN: u64 = 0x050f;

pub const DET_PAGE_OFFSET: u64 = 0x7000_0000;
pub const DET_PAGE_SIZE: u64 = 0x4000;

pub const DET_PAGE_TLS: u64 = DET_PAGE_OFFSET + 0x1000;

pub const DET_TLS_SYSCALL_HOOK_SIZE: u64 = DET_PAGE_TLS + 0x0;
pub const DET_TLS_SYSCALL_HOOK_ADDR: u64 =
    DET_TLS_SYSCALL_HOOK_SIZE + std::mem::size_of::<u64>() as u64;

pub const DET_TLS_STUB_SCRATCH: u64 = DET_TLS_SYSCALL_HOOK_ADDR + std::mem::size_of::<u64>() as u64;
pub const DET_TLS_STACK_NESTING_LEVEL: u64 =
    DET_TLS_STUB_SCRATCH + std::mem::size_of::<u64>() as u64;

pub const DET_TLS_SYSCALL_TRAMPOLINE: u64 =
    DET_TLS_STACK_NESTING_LEVEL + std::mem::size_of::<u64>() as u64;
pub const DET_TLS_LIBDET_HOOK: u64 = DET_TLS_SYSCALL_TRAMPOLINE + std::mem::size_of::<u64>() as u64;

#[test]
fn det_tls_sanity_check() {
    assert_eq!(DET_TLS_SYSCALL_HOOK_SIZE, DET_PAGE_TLS + 0);
    assert_eq!(DET_TLS_SYSCALL_HOOK_ADDR, DET_PAGE_TLS + 8);
    assert_eq!(DET_TLS_STUB_SCRATCH, DET_PAGE_TLS + 16);
    assert_eq!(DET_TLS_STACK_NESTING_LEVEL, DET_PAGE_TLS + 24);
    assert_eq!(DET_TLS_SYSCALL_TRAMPOLINE, DET_PAGE_TLS + 32);
    assert_eq!(DET_TLS_LIBDET_HOOK, DET_PAGE_TLS + 40);
}
