#include <sys/types.h>

#include "scinfo.h"

static void* local_state_ptr;

extern long captured_syscall(void*, int, long, long, long, long, long, long);

__attribute__((visibility("hidden"))) long syscall_hook(const struct syscall_info* syscall)
{
  return captured_syscall(local_state_ptr, syscall->no, syscall->args[0], syscall->args[1], syscall->args[2], syscall->args[3], syscall->args[4], syscall->args[5]);
}

extern void _remote_syscall_helper();

__attribute__((constructor))
static void __trampoline_init(void)
{
  volatile unsigned long *trampoline_ready = (unsigned long*)0x70001020;
  *trampoline_ready = 1;

  volatile unsigned long *syscall_local_state_at = (unsigned long*)0x70001040;
  local_state_ptr = (void*)*syscall_local_state_at;

  volatile unsigned long *syscall_helper = (unsigned long*)0x70001048;
  *syscall_helper = (long)_remote_syscall_helper;
}
