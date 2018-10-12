#include <sys/types.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <inttypes.h>

#include "symbols.h"
#include "utils.h"

unsigned long find_spare_pages(struct mmap_entry* map, unsigned long address, int order) {
  struct mmap_entry* e;
  int i = 0;
  unsigned long rc = (address + 4095) & ~4095;
  
  if (order < 0 || order >= 10) {
    return -1UL;
  }

  for (i = 0; map[i].base && map[i].size; i++) {
    e = &map[i];

    /* find first entry with base+size <= address */
    if (e->base + e->size <= address) continue;
    if (rc + 4096*(1<<order) <= e->base) {
      return rc;
    }
    if (rc >= e->base && rc <= e->base + e->size) rc = e->base + e->size;
  }
  
  return rc;
}

struct mmap_entry* populate_memory_map(pid_t pid, int* nmemb) {
  int i = 0, rc;
  int allocated = 128;
  size_t nb = 0;
  char proc[64], *line = NULL;
  char* p, *q;
  struct mmap_entry* map = calloc(allocated, sizeof(*map)), *e;
  FILE* fp;

  Expect(map != NULL);
  snprintf(proc, 64, "/proc/%u/maps", pid);
  fp = fopen(proc, "rb");
  if (!fp) panic("unable to open file: %s, error: %s\n", proc, strerror(errno));

  while(!feof(fp)) {
    if (i >= (allocated-1)) {
      allocated += 128;
      map = realloc(map, allocated * sizeof(*map));
      Expect(map != NULL);
    }
    
    rc = getline(&line, &nb, fp);
    if (rc <= 0) break;
    line[rc-1] = '\0';

    e = &map[i++];
    
    e->base = strtoul(line, &p, 16);
    e->size = strtoul(1+p, &q, 16) - e->base;
    p       = 1 + q;
    if (*p++ == 'r') e->prot  |= PROT_READ;
    if (*p++ == 'w') e->prot  |= PROT_WRITE;
    if (*p++ == 'x') e->prot  |= PROT_EXEC;
    if (*p == 'p') e->flags |= MAP_PRIVATE;
    if (*p++ == 's') e->flags |= MAP_SHARED;
    e->offset = strtoul(1+p, &q, 16);
    p = strpbrk(1+q, " ");
    Expect(p != NULL);
    strtoul(1+p, &q, 10);
    p = strpbrk(1+q, "/[");
    if (p) strncpy(e->file, p, 95);
    else e->file[0] = 0;
  }

  free(line);
  fclose(fp);

  memset(&map[i], 0, sizeof(map[i]));

  if (nmemb) *nmemb = i;

  return map;
}

void free_mmap_entry(struct mmap_entry* map) {
  free(map);
}
