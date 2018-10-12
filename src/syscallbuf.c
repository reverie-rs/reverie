#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

#include "syscallbuf.h"

#define untraced_syscall6(no, a0, a1, a2, a3, a4, a5)                          \
  untraced_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2,            \
		   (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5)

#define untraced_syscall5(no, a0, a1, a2, a3, a4)                              \
  untraced_syscall6(no, a0, a1, a2, a3, a4, 0)
#define untraced_syscall4(no, a0, a1, a2, a3)                                  \
  untraced_syscall5(no, a0, a1, a2, a3, 0)
#define untraced_syscall3(no, a0, a1, a2) untraced_syscall4(no, a0, a1, a2, 0)
#define untraced_syscall2(no, a0, a1) untraced_syscall3(no, a0, a1, 0)
#define untraced_syscall1(no, a0) untraced_syscall2(no, a0, 0)
#define untraced_syscall0(no) untraced_syscall1(no, 0)

#define traced_syscall6(no, a0, a1, a2, a3, a4, a5)                 \
  traced_syscall(no, (uintptr_t)a0, (uintptr_t)a1, (uintptr_t)a2,   \
		 (uintptr_t)a3, (uintptr_t)a4, (uintptr_t)a5)
#define traced_syscall5(no, a0, a1, a2, a3, a4)                     \
  traced_syscall6(no, a0, a1, a2, a3, a4, 0)
#define traced_syscall4(no, a0, a1, a2, a3)                         \
  traced_syscall5(no, a0, a1, a2, a3, 0)
#define traced_syscall3(no, a0, a1, a2)                             \
  traced_syscall4(no, a0, a1, a2, 0)
#define traced_syscall2(no, a0, a1)                                 \
  traced_syscall3(no, a0, a1, 0)
#define traced_syscall1(no, a0) traced_syscall2(no, a0, 0)
#define traced_syscall0(no) traced_syscall1(no, 0)

extern __attribute__((visibility("hidden")))
long _raw_syscall(int syscallno, long a0, long a1, long a2,
		  long a3, long a4, long a5,
		  void* syscall_instruction,
		  long stack_param_1, long stack_param_2);

/**
 * Make a raw traced syscall using the params in |call|.
 */
static long traced_raw_syscall(const struct syscall_info* call) {
  /* FIXME: pass |call| to avoid pushing these on the stack
   * again. */
  return _raw_syscall(call->no, call->args[0], call->args[1], call->args[2],
                      call->args[3], call->args[4], call->args[5],
                      SYSCALL_TRACED, 0, 0);
}

static int traced_syscall(int syscallno, long a0, long a1, long a2,
			  long a3, long a4, long a5) {
  return _raw_syscall(syscallno, a0, a1, a2, a3, a4, a5,
                      SYSCALL_TRACED, 0, 0);
}

/**
 * Make a raw traced syscall using the params in |call|.
 */
static long untraced_raw_syscall(const struct syscall_info* call) {
  /* FIXME: pass |call| to avoid pushing these on the stack
   * again. */
  return _raw_syscall(call->no, call->args[0], call->args[1], call->args[2],
                      call->args[3], call->args[4], call->args[5],
                      SYSCALL_UNTRACED, 0, 0);
}

static int untraced_syscall(int syscallno, long a0, long a1, long a2,
			    long a3, long a4, long a5) {
  return _raw_syscall(syscallno, a0, a1, a2, a3, a4, a5,
                      SYSCALL_UNTRACED, 0, 0);
}

__attribute__((visibility("hidden"))) long syscall_hook(const struct syscall_info* syscall)
{
  long rc = -1;
  switch (syscall->no) {
  case SYS_openat:
    {
    const char* file = (const char*)syscall->args[1];
    rc = untraced_syscall4(syscall->no, syscall->args[0], syscall->args[1], syscall->args[2], syscall->args[3]);
    printf("%s openat, file: %s = %ld\n", __func__, file, rc);
    }
    break;
  default:
    printf("[WARNING] unknown syscall: %u\n", (int)syscall->no);
    untraced_syscall6(syscall->no, syscall->args[0], syscall->args[1], syscall->args[2], syscall->args[3], syscall->args[4], syscall->args[5]);
    break;
  }
  return rc;
}

extern void _syscall_hook_trampoline(void);
extern void _syscall_hook_trampoline_48_3d_01_f0_ff_ff(void);
extern void _syscall_hook_trampoline_48_3d_00_f0_ff_ff(void);

static struct syscall_patch_hook syscall_patch_hooks[] = {
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed
     * by
     * cmp $-4095,%rax (in glibc-2.18-16.fc20.x86_64) */
    { 0,
      6,
      { 0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_48_3d_01_f0_ff_ff },
    /* Many glibc syscall wrappers (e.g. __libc_recv) have 'syscall'
     * followed by
     * cmp $-4096,%rax (in glibc-2.18-16.fc20.x86_64) */
    { 0,
      6,
      { 0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff },
      (uintptr_t)_syscall_hook_trampoline_48_3d_00_f0_ff_ff },
};

__attribute__((constructor, visibility("hidden"))) void __preload_init(void)
{
  unsigned long* tls = (unsigned long*)PRELOAD_THREAD_LOCALS_ADDR;
  tls[0] = sizeof(syscall_patch_hooks) / sizeof(syscall_patch_hooks[0]);
  tls[1] = (unsigned long)syscall_patch_hooks;
  tls[2] = (unsigned long)syscall_hook;
}
