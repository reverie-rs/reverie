//! Predefined patchable syscall sites
use std::fs::File;
use std::io::{Error, ErrorKind, Read, Result};
use std::path::PathBuf;

use goblin::elf::Elf;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyscallHook {
    pub name: String,
    pub offset: u64,
    pub instructions: Vec<u8>,
    pub is_multi: bool,
}

/// resolve syscall hooks from (LD) preload library
///
/// `preload` should be the tool shared library which has symbols for
/// syscall hooks
///
/// returns a `Vec` of predefined syscall hooks.
pub fn resolve_syscall_hooks_from(
    preload: PathBuf,
) -> Result<Vec<SyscallHook>> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut file = File::open(preload)?;
    let mut res: Vec<SyscallHook> = Vec::new();
    file.read_to_end(&mut bytes)?;
    let elf = Elf::parse(bytes.as_slice())
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let strtab = elf.strtab;
    for sym in elf.syms.iter() {
        for hook in SYSCALL_HOOKS {
            if hook.symbol == &strtab[sym.st_name] {
                res.push(SyscallHook {
                    name: String::from(hook.symbol),
                    offset: sym.st_value,
                    instructions: Vec::from(hook.instructions),
                    is_multi: hook.is_multi,
                });
            }
        }
    }
    Ok(res)
}

/// Syscall patch sequence
struct SyscallPatchHook<'a> {
    /// NB: if the patched sequence contains multiple
    /// instructions, it is possible in the same function
    /// there is a jmp @label within the very function,
    /// and the @label is within the range of the patched
    /// multiple instructions. This could cause the function
    /// jumps to the middle of our patched sequence, which is
    /// likely cause undefined behavior.
    /// one example is `clock_nanosleep` in glibc.
    is_multi: bool,
    instructions: &'a [u8],
    symbol: &'a str,
}

const SYSCALL_HOOKS: &[SyscallPatchHook] = &[
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed by
     * cmp $-4095,%rax */
    SyscallPatchHook {
        is_multi: false,
        instructions: &[0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff],
        symbol: "_syscall_hook_trampoline_48_3d_01_f0_ff_ff",
    },
    /* Many glibc syscall wrappers (e.g. __libc_recv) have 'syscall'
     * followed by
     * cmp $-4096,%rax */
    SyscallPatchHook {
        is_multi: false,
        instructions: &[0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff],
        symbol: "_syscall_hook_trampoline_48_3d_00_f0_ff_ff",
    },
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed by
     * mov (%rsp),%rdi */
    SyscallPatchHook {
        is_multi: false,
        instructions: &[0x48, 0x8b, 0x3c, 0x24],
        symbol: "_syscall_hook_trampoline_48_8b_3c_24",
    },
    /* __lll_unlock_wake has 'syscall' followed by
     * pop %rdx; pop %rsi; ret */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0x5a, 0x5e, 0xc3],
        symbol: "_syscall_hook_trampoline_5a_5e_c3",
    },
    /* posix_fadvise64 has 'syscall' followed by
     * mov %eax,%edx;
     * neg %edx */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0x89, 0xc2, 0xf7, 0xda],
        symbol: "_syscall_hook_trampoline_89_c2_f7_da",
    },
    /* Our VDSO vsyscall patches have 'syscall' followed by
     * nop; nop; nop */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0x90, 0x90, 0x90],
        symbol: "_syscall_hook_trampoline_90_90_90",
    },
    /* glibc-2.22-17.fc23.x86_64 has 'syscall' followed by
     * 'mov $1,%rdx' in pthread_barrier_wait.
     */
    SyscallPatchHook {
        is_multi: false,
        instructions: &[0xba, 0x01, 0x00, 0x00, 0x00],
        symbol: "_syscall_hook_trampoline_ba_01_00_00_00",
    },
    /* pthread_sigmask has 'syscall' followed by
     * 'mov %eax,%ecx;
     *  xor %edx,%edx' */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0x89, 0xc1, 0x31, 0xd2],
        symbol: "_syscall_hook_trampoline_89_c1_31_d2",
    },
    /* getpid has 'syscall' followed by
     * 'retq;
     *  nopl 0x0(%rax,%rax,1) */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0xc3, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
        symbol: "_syscall_hook_trampoline_c3_nop",
    },
    /* liblsan internal_close has 'syscall' followed by
     * 'retq;
     *  nopl 0x0(%rax,%rax,1) */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00],
        symbol: "_syscall_hook_trampoline_c3_nop",
    },
    /* liblsan internal_open has 'syscall' followed by
     * 'retq;
     *  nopl (%rax) */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0xc3, 0x0f, 0x1f, 0x00],
        symbol: "_syscall_hook_trampoline_c3_nop",
    },
    /* liblsan internal_dup2 has 'syscall' followed by
     * 'retq;
     *  xchg %ax,%ax' */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0xc3, 0x66, 0x90],
        symbol: "_syscall_hook_trampoline_c3_nop",
    },
    /* ld-linux.so SYS_access has 'syscall' followed by
     * 'test %eax, %eax
     *  sete dl' */
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0x85, 0xc0, 0x0f, 0x94, 0xc2],
        symbol: "_syscall_hook_trampoline_85_c0_0f_94_c2",
    },
    /* ubuntu 18.04 libc-2.27.so, `syscall` followed by
     * nopl   0x0(%rax)
     */
    SyscallPatchHook {
        is_multi: false,
        instructions: &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
        symbol: "_syscall_hook_trampoline_90_90_90",
    },
    /* ubuntu 18.04 pthread_setcanceltype@libc-2.27.so, `syscall` followed by
     * mov    %edx,%eax
     * xchg   %eax,(%rdi)
     */
    /* NB: disabled because of jump into middle of generated stub
    SyscallPatchHook {
        is_multi: true,
        instructions: &[0x89, 0xd0, 0x87, 0x07],
        symbol: "_syscall_hook_trampoline_89_d0_87_07",
    },
    */
];

#[test]
fn syscall_patch_hooks_sanity_check() {
    for hook in SYSCALL_HOOKS {
        assert!(hook.instructions.len() >= 3);
        assert!(hook.instructions.len() < 2 * std::mem::size_of::<u64>());
        // maximum nop bytes is 9 bytes
        // 12 comes from: max_nop_bytes + jmp_insn_size(5) - syscall_insn_size
        // see: https://reverseengineering.stackexchange.com/questions/11971/nop-with-argument-in-x86-64
        // it is possible to support larger instructions
        // by adding more nops, for now we think 12 is sufficient.
        assert!(hook.instructions.len() <= 12);
    }
}
