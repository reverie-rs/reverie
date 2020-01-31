#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <alloca.h>
#include <pthread.h>

#define NTESTS 10000
#define NTHREADS 16

typedef int (*getpid_many_pfn)(void);

struct thread_param {
  int ntests;
  int id;
  getpid_many_pfn pfn;
};

#define ALIGN_UP(__x, __align) ( ( (__x) + (__align) - 1) & -(__align) )

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ( sizeof(x) / sizeof((x)[0]) )
#endif

static unsigned char getpid_body[] = {
  0xb8, 0x27, 0x00, 0x00, 0x00,       // mov, $0x27, %eax
  0x0f, 0x05,                         // syscall
  0x48, 0x3d, 0x00, 0xf0, 0xff, 0xff, // cmp $0xfffffffffffff000, %rax
};

static unsigned char getpid_return[] = {
  0xc3,                                           // retq
  0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, // nopl 0x0(%rax,%rax,1)
};

static long long diff_time(const struct timespec* begin,
                           const struct timespec* end) {
  long long r = 0;
  r = (end->tv_sec - begin->tv_sec) * 1000000000 + (end->tv_nsec - begin->tv_nsec);
  return r/1000;
}

void* thread_routine(void* param) {
  struct thread_param* p = param;

  long ntests = p->ntests;
  long id = p->id;
  getpid_many_pfn getpid_many = p->pfn;

  struct timespec start, end;
  pid_t pid;

  clock_gettime(CLOCK_MONOTONIC, &end);
  clock_gettime(CLOCK_MONOTONIC, &start);
  pid = getpid_many();
  clock_gettime(CLOCK_MONOTONIC, &end);

  long long diff = diff_time(&start, &end);
  double time_per_call = (double) diff / ntests;

  printf("thread[#%lu]getpid-many returned: %u for %lu times, total time: %lluus, time per-syscall: %gus\n", id, pid, ntests, diff, time_per_call);

  return NULL;
}

int main(int argc, char* argv[])
{
  int ntests = NTESTS;
  int nthreads = NTHREADS;

  if (argc == 3) {
    nthreads = atoi(argv[1]);
    ntests = atoi(argv[2]);
  }

  size_t alloc_size = ALIGN_UP(ntests * sizeof(getpid_body) + sizeof(getpid_return), 0x1000);
  void* pages = mmap(0, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC,
     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert (pages != (void*)-1);

  unsigned char* curr = pages;

  for (int i = 0; i < ntests; i++) {
    memcpy(curr, getpid_body, sizeof(getpid_body));
    curr += sizeof(getpid_body);
  }
  memcpy(curr, getpid_return, sizeof(getpid_return));
  getpid_many_pfn getpid_many = pages;


  pthread_t *threads = malloc((1+nthreads) * sizeof(pthread_t));
  assert(threads);
  struct thread_param* params = malloc( (1+nthreads) * sizeof(struct thread_param));
  assert(params);

  for (int i = 0; i < nthreads; i++) {
    params[i].ntests = ntests;
    params[i].id = i;
    params[i].pfn = getpid_many;
    assert(pthread_create(&threads[i], NULL, thread_routine, (void*)&params[i]) == 0);
  }

  for (int i = 0; i < nthreads; i++) {
    pthread_join(threads[i], NULL);
  }

  munmap(pages, alloc_size);

  // free(params);
  // free(threads);

  return 0;
}
