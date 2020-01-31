#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#define THREAD_LOOP_COUNT 1000
#define NR_THREADS 4L
#define TIME_100MS 100000000UL

static void test_clock_nanosleep(unsigned long ns) {
  struct timespec req = {
    .tv_sec = 0,
    .tv_nsec = ns,
  };
  struct timespec rem;
  int ret;

  do {
    ret = clock_nanosleep(CLOCK_REALTIME, 0, &req, &rem);
    memcpy(&req, &rem, sizeof(req));
  } while (ret != 0 && errno == EINTR);
}

static void* threaded(void* param) {
  long k = (long)param;
  char buf[32];
  int n;

  n = snprintf(buf, 32, "%lu", k);

  for (int i = 0; i < THREAD_LOOP_COUNT; i++) {
    write(STDERR_FILENO, buf, n);
  }

  return 0;
}

int main(int argc, char* argv[])
{
  pthread_attr_t attr;
  pthread_t threadid[NR_THREADS];

  assert(pthread_attr_init(&attr) == 0);

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_create(&threadid[i], &attr, threaded, (void*)i) == 0);
  }

  for (long i = 0; i < NR_THREADS; i++) {
    assert(pthread_join(threadid[i], NULL) == 0);
  }

  assert(pthread_attr_destroy(&attr) == 0);

  return 0;
}
