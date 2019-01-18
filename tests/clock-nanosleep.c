#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[])
{
  const struct timespec req = {
    .tv_sec = 0,
    .tv_nsec = 100000000,
  };
  struct timespec rem;
  
  clock_nanosleep(CLOCK_REALTIME, 0, &req, &rem);

  return 0;
}

