#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#define NTESTS 100000

#define ALIGN_UP(__x, __align) ( ( (__x) + (__align) - 1) & -(__align) )

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ( sizeof(x) / sizeof((x)[0]) )
#endif


static unsigned char time_body[] = {
  0x48, 0x31, 0xff,                              // xor %rdi, %rdi
  0xb8, 0xc9, 0x0, 0x0, 0x0,                     // mov %SYS_time, %eax
  0x0f, 0x05,                                    // syscall
  0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff,            // cmp $0xfffffffffffff000, %rax
};

static unsigned char time_return[] = {
  0xc3,                                           // retq
  0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax,%rax,1)
};

static long long diff_time(const struct timespec* begin,
                           const struct timespec* end) {
  long long r = 0;
  r = (end->tv_sec - begin->tv_sec) * 1000000000 + (end->tv_nsec - begin->tv_nsec);
  return r/1000;
}

typedef time_t (*gettime_many_pfn)(time_t*);

int main(int argc, char* argv[])
{
  int ntests = NTESTS;

  if (argc == 2) {
    ntests = atoi(argv[1]);
  }

  size_t alloc_size = ALIGN_UP(ntests * sizeof(time_body) + sizeof(time_return), 0x1000);

  void* pages = mmap(0, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC,
     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert (pages != (void*)-1);

  unsigned char* curr = pages;

  for (int i = 0; i < ntests; i++) {
    memcpy(curr, time_body, sizeof(time_body));
    curr += sizeof(time_body);
  }
  memcpy(curr, time_return, sizeof(time_return));

  gettime_many_pfn gettime_many = pages;

  struct timespec start, end;
  time_t time;

  clock_gettime(CLOCK_MONOTONIC, &end);
  clock_gettime(CLOCK_MONOTONIC, &start);
  time = gettime_many(NULL);
  clock_gettime(CLOCK_MONOTONIC, &end);

  long long diff = diff_time(&start, &end);
  double time_per_call = (double) diff / ntests;

  printf("gettime-many returned: %lu for %u times, total time: %lluus, time per-syscall: %gus\n", time, ntests, diff, time_per_call);

  munmap(pages, alloc_size);

  return 0;
}
