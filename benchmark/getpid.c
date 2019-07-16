/**
 * test `reverie` syscall patching overhead
 * best case: patch happens the very first time a syscall site (based on
 * `PC` value) is reached. After patching, the original `syscall` sequence
 * got replaced, hence has minimum impact on performance. Unfortunately
 * This also make benchmark syscall patching overhead more difficult. we
 * cannot simply call the same syscall multiple times otherwise the costs
 * would be amortized.
 */
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static long long diff_time(const struct timespec* begin,
                           const struct timespec* end) {
  long long r = 0;
  r = (end->tv_sec - begin->tv_sec) * 1000000000 + (end->tv_nsec - begin->tv_nsec);
  return r;
}

int main(int argc, char* argv[])
{
  pid_t pid;
  struct timespec start, end;

  // ignore first clock_gettime call to avoid possible patching delays
  clock_gettime(CLOCK_MONOTONIC, &start);

  clock_gettime(CLOCK_MONOTONIC, &start);

  pid = getpid();

  clock_gettime(CLOCK_MONOTONIC, &end);

  printf("getpid returned: %u, time elapsed: %lluns\n", pid, diff_time(&start, &end));

  return 0;
}
