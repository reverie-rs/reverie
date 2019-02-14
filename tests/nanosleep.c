#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int main(int argc, char* argv[])
{
  struct timespec req = {
    .tv_sec = 0,
    .tv_nsec = 100000000,
  };
  struct timespec rem;
  int ret;
  
  for (int i = 0; i < 1000; i++) {
    printf("nanosleep, iteration: %u\n", i);
    do {
      ret = nanosleep(&req, &rem);
      memcpy(&req, &rem, sizeof(req));
    } while (ret != 0 && errno == EINTR);
  }

  return 0;
}

