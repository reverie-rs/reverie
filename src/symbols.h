#ifndef _MY_SYMBOLS_H
#define _MY_SYMBOLS_H
#include <sys/types.h>
#include <stdio.h>

struct mmap_entry {
  unsigned long base;
  unsigned long size;
  unsigned int  prot;
  unsigned int  flags;
  unsigned long offset;
  char          file[96];
};

struct mmap_entry* populate_memory_map(pid_t, int*);
void free_mmap_entry(struct mmap_entry*);

#endif
