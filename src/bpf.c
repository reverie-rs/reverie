#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
#include <stddef.h>

#include "syscallbuf.h"
#include "utils.h"

static void relocate_syscall(int syscall_no)
{
  struct sock_filter filter [] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscall_no, 0, 3),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x70000002, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
    .filter = filter,
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
  };

  ThrowErrnoIfMinus(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  ThrowErrnoIfMinus(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog));
}

void bpf_patch_syscall(int syscall)
{
  Expect(syscall >= 0 && syscall < SYSCALL_MAX);

  relocate_syscall(syscall);
}

void bpf_patch_all(void)
{
  struct sock_filter filter [] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_mmap, 5, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_exit, 4, 0),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_exit_group, 3, 0),
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, instruction_pointer)),
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x70000002, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog prog = {
    .filter = filter,
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
  };

  ThrowErrnoIfMinus(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  ThrowErrnoIfMinus(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog));
}

