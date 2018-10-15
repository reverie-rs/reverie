#include <sys/types.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

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

typedef long (*untraced_syscall6_pfn) (unsigned long, unsigned long, unsigned long, unsigned long,
				  unsigned long, unsigned long, unsigned long);
__attribute__((visibility("hidden"))) void* _syscall_table[1 + SYSCALL_MAX];
__attribute__((visibility("hidden"))) long syscall_hook(const struct syscall_info* syscall)
{
  if (_syscall_table[syscall->no] == 0) {
    return -ENOSYS;
  } else if ((unsigned long)_syscall_table[syscall->no] == DEFAULT_SYSCALL_HOOK) {
    return untraced_syscall6(syscall->no, syscall->args[0], syscall->args[1], syscall->args[2], syscall->args[3], syscall->args[4], syscall->args[5]);
  } else {
    untraced_syscall6_pfn do_syscall6 = (untraced_syscall6_pfn)_syscall_table[syscall->no];
    return do_syscall6(syscall->no, syscall->args[0], syscall->args[1], syscall->args[2], syscall->args[3], syscall->args[4], syscall->args[5]);
  }
}

int register_syscall_hook(int syscall, void* pfn)
{
  if (!(syscall >= 0 && syscall < SYSCALL_MAX)) return -1;

  if (_syscall_table[syscall]) {
    if (pfn) return -1;
  } else {
    if (!pfn) return -1;
  }

  _syscall_table[syscall] = pfn;

  return 0;
}

extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_48_3d_01_f0_ff_ff(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_48_3d_00_f0_ff_ff(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_48_8b_3c_24(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_5a_5e_c3(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_89_c2_f7_da(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_90_90_90(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_ba_01_00_00_00(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_89_c1_31_d2(void);
extern __attribute__((visibility("hidden"))) void _syscall_hook_trampoline_c3_nop(void);

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
    /* Many glibc syscall wrappers (e.g. read) have 'syscall' followed
     * by
     * mov (%rsp),%rdi (in glibc-2.18-16.fc20.x86_64) */
    { 0,
      4,
      { 0x48, 0x8b, 0x3c, 0x24 },
      (uintptr_t)_syscall_hook_trampoline_48_8b_3c_24 },
    /* __lll_unlock_wake has 'syscall' followed by
     * pop %rdx; pop %rsi; ret */
    { 1,
      3,
      { 0x5a, 0x5e, 0xc3 },
      (uintptr_t)_syscall_hook_trampoline_5a_5e_c3 },
    /* posix_fadvise64 has 'syscall' followed by
     * mov %eax,%edx; neg %edx (in glibc-2.22-11.fc23.x86_64) */
    { 1,
      4,
      { 0x89, 0xc2, 0xf7, 0xda },
      (uintptr_t)_syscall_hook_trampoline_89_c2_f7_da },
    /* Our VDSO vsyscall patches have 'syscall' followed by "nop; nop;
       nop" */
    { 1,
      3,
      { 0x90, 0x90, 0x90 },
      (uintptr_t)_syscall_hook_trampoline_90_90_90 },
    /* glibc-2.22-17.fc23.x86_64 has 'syscall' followed by 'mov $1,%rdx'
     * in
     * pthread_barrier_wait.
     */
    { 0,
      5,
      { 0xba, 0x01, 0x00, 0x00, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_ba_01_00_00_00 },
    /* pthread_sigmask has 'syscall' followed by 'mov %eax,%ecx; xor
       %edx,%edx' */
    { 1,
      4,
      { 0x89, 0xc1, 0x31, 0xd2 },
      (uintptr_t)_syscall_hook_trampoline_89_c1_31_d2 },
    /* getpid has 'syscall' followed by 'retq; nopl 0x0(%rax,%rax,1) */
    { 1,
      9,
      { 0xc3, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* liblsan internal_close has 'syscall' followed by 'retq; nopl 0x0(%rax,%rax,1) */
    { 1,
      6,
      { 0xc3, 0x0f, 0x1f, 0x44, 0x00, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* liblsan internal_open has 'syscall' followed by 'retq; nopl (%rax) */
    { 1,
      4,
      { 0xc3, 0x0f, 0x1f, 0x00 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
    /* liblsan internal_dup2 has 'syscall' followed by 'retq; xchg %ax,%ax */
    { 1,
      3,
      { 0xc3, 0x66, 0x90 },
      (uintptr_t)_syscall_hook_trampoline_c3_nop },
  };

__attribute__((constructor, visibility("hidden"))) void __preload_init(void)
{
  unsigned long* tls = (unsigned long*)PRELOAD_THREAD_LOCALS_ADDR;
  tls[0] = sizeof(syscall_patch_hooks) / sizeof(syscall_patch_hooks[0]);
  tls[1] = (unsigned long)syscall_patch_hooks;
  tls[2] = (unsigned long)syscall_hook;

  for (int i = 0; i < SYSCALL_MAX; i++) {
    _syscall_table[i] = (void*)DEFAULT_SYSCALL_HOOK;
  }
}
