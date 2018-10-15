#ifndef _MY_SYSCALLBUF_H
#define _MY_SYSCALLBUF_H

#include <sys/types.h>
#include <inttypes.h>

#ifndef SYSCALL_MAX
#define SYSCALL_MAX 1023
#endif

#define PRELOAD_PAGE_ADDR 0x70000000UL
#define PRELOAD_STUB_SCRATCH 0x70000100UL
#define PRELOAD_THREAD_LOCALS_ADDR 0x70001000UL

/* TLS offsets, start from PRELOAD_THREAD_LOCALS_ADDR */
#define TLS_SYSCALL_PATCH_SIZE (PRELOAD_THREAD_LOCALS_ADDR + 0 * sizeof(long))
#define TLS_SYSCALL_PATCH_ADDR (PRELOAD_THREAD_LOCALS_ADDR + 1 * sizeof(long))
#define TLS_SYSCALL_HOOK_ADDR  (PRELOAD_THREAD_LOCALS_ADDR + 2 * sizeof(long))

#define SYSCALL_UNTRACED (void*)(PRELOAD_PAGE_ADDR+0)
#define SYSCALL_TRACED   (void*)(PRELOAD_PAGE_ADDR+4)

struct syscall_info {
  unsigned long no;
  unsigned long args[6];
};

struct syscall_patch_hook {
  uint8_t is_multi_instruction;
  uint8_t next_instruction_length;
  /* Avoid any padding or anything that would make the layout arch-specific. */
  uint8_t next_instruction_bytes[14];
  uint64_t hook_address;
};

/* default syscall hook allows syscall to go through */
#define DEFAULT_SYSCALL_HOOK (-1UL)
#define NULL_SYSCALL_HOOK    0UL

int register_syscall_hook(int, void*);

#endif
