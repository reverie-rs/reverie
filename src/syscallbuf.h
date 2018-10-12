#ifndef _MY_SYSCALLBUF_H
#define _MY_SYSCALLBUF_H

#include <sys/types.h>
#include <inttypes.h>

#define PRELOAD_PAGE_ADDR 0x70000000UL
#define PRELOAD_STUB_SCRATCH 0x70000100UL
#define PRELOAD_THREAD_LOCALS_ADDR 0x70001000UL

/* TLS offsets, start from PRELOAD_THREAD_LOCALS_ADDR */
#define TLS_SYSCALL_PATCH_SIZE 0
#define TLS_SYSCALL_PATCH_ADDR 1
#define TLS_SYSCALL_HOOK_ADDR  2

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

#endif
