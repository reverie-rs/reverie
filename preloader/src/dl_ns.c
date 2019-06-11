#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <sys/types.h>
#include <sys/mman.h>
#include <stdio.h>
#include <link.h>
#include <dlfcn.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

/*
__libc_get_nprocs:
   0:	b8 02 00 00 00       	mov    $0x2,%eax
   5:	c3                   	retq
*/
static const char fixup_opcode[] = {0xb8, 0x02, 0x00, 0x00, 0x00, 0xc3};

extern int get_nprocs();

/*
 * Ok, bear with me here. rust `libstd` loves thread local storage (TLS).
 * even though we're using `dlmopen` to inject our tool dso into an new
 * namespace, it still use the same ld-linux.so as the tracee. As a result,
 * when `__tls_get_new` is called, it may call `__libc_malloc`, which then
 * could call `tcache_init` -> `arena_get2` -> `__get_nprocs`, the last one
 * may then cause recursive calls, like:

    (47543 frames skipped..)
    frame #47544: 0x00007ffff7deea28 ld-linux-x86-64.so.2`__tls_get_addr at tls_get_addr.S:55
    frame #47545: 0x00007ffff6ce800c
    frame #47546: 0x00007ffff73c790a libc.so.6`arena_get2(size=576, avoid_arena=0x00007ffff609e0d0) at arena.c:888
    frame #47547: 0x00007ffff73cc54d libc.so.6`tcache_init at arena.c:879
    frame #47548: 0x00007ffff73cc530 libc.so.6`tcache_init at malloc.c:2986
    frame #47549: 0x00007ffff73cd1cb libc.so.6`__GI___libc_malloc at malloc.c:2983
    frame #47550: 0x00007ffff73cd1b0 libc.so.6`__GI___libc_malloc(bytes=160) at malloc.c:3042
    frame #47551: 0x00007ffff7de7b90 ld-linux-x86-64.so.2`tls_get_addr_tail at dl-tls.c:594
    frame #47552: 0x00007ffff7de7b6c ld-linux-x86-64.so.2`tls_get_addr_tail at dl-tls.c:607
    frame #47553: 0x00007ffff7de7b5e ld-linux-x86-64.so.2`tls_get_addr_tail(ti=0x00007ffff6f14940, dtv=0x0000000000608330, the_map=0x0000000000602330) at dl-tls.c:787
    frame #47554: 0x00007ffff7deea28 ld-linux-x86-64.so.2`__tls_get_addr at tls_get_addr.S:55

 * hence we fixup `__get_nprocs`, by forcing it return 2.
 */
static void __libc_get_nprocs_fixup(void) {
  unsigned long addr = (unsigned long)get_nprocs;

  unsigned long start = addr & ~0xfffull;
  size_t len = 0x1000;

  if (addr + sizeof(fixup_opcode) > start + 0x1000) {
    len = 0x2000;
  }

  if (mprotect((void*)start, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
  }
  memcpy((void*)addr, fixup_opcode, sizeof(fixup_opcode));
  if (mprotect((void*)start, len, PROT_READ | PROT_EXEC) != 0) {
    fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
  }
}

void* _early_preload_dso(const char* dso) {
  void* handle = NULL;

  Lmid_t id = LM_ID_NEWLM;

  handle = dlmopen(id, dso, RTLD_NOW);
  assert(handle);
  assert(dlinfo(handle, RTLD_DI_LMID, &id) == 0);

  __libc_get_nprocs_fixup();

  return handle;
}
