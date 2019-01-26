#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
#include <stddef.h>

#include "bpf-helper.h"

#include "scinfo.h"
#include "utils.h"

void bpf_install(void)
{
  struct bpf_labels l = {
    .count = 0,
  };
  struct sock_filter filter[] = {
    LOAD_SYSCALL_NR,
    SYSCALL(__NR_exit, ALLOW),
    SYSCALL(__NR_exit_group, ALLOW),
    SYSCALL(__NR_mmap, ALLOW),
    SYSCALL(__NR_mremap, ALLOW),
    SYSCALL(__NR_munmap, ALLOW),
    SYSCALL(__NR_madvise, ALLOW),
    SYSCALL(__NR_mprotect, ALLOW),
    SYSCALL(__NR_brk, ALLOW),
    SYSCALL(__NR_wait4, ALLOW),
    SYSCALL(__NR_clone, ALLOW),
    SYSCALL(__NR_fork, ALLOW),
    SYSCALL(__NR_vfork, ALLOW),
    SYSCALL(__NR_execve, ALLOW),
    LOAD_SYSCALL_IP,
    IP(0x70000002, ALLOW),
    TRACE,
  };
  struct sock_fprog prog = {
    .filter = filter,
    .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
  };

  bpf_resolve_jumps(&l, filter, sizeof(filter)/sizeof(*filter));

  ThrowErrnoIfMinus(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog));
}
