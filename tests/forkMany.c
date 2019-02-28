#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define TESTS_NLOOPS 1000

static _Atomic unsigned long *counter;

int main(int argc, char* argv[]) {
  sigset_t oldset, set;
  pid_t pid;
  unsigned long c;
  int status;

  counter = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  assert((unsigned long)counter != -1UL);

  if (argc == 2 && strcmp(argv[1], "--block-sigchld") == 0) {
      sigprocmask(SIG_BLOCK, NULL, &set);
      sigaddset(&set, SIGCHLD);
      sigprocmask(SIG_BLOCK, &set, &oldset);
  }
  
  for (int i = 0; i < TESTS_NLOOPS; i++) {
    kill(getpid(), SIGCHLD);
    pid = fork();
    // Child
    if (pid == 0) {
      c = atomic_fetch_add(counter, 1);
      //fprintf(stderr, "counter: %lu\n", c);
      return 0;
    } else  if (pid > 0) {
      c = atomic_fetch_add(counter, 1);
      //fprintf(stderr, "counter: %lu\n", c);
    } else {
      perror("fork: ");
      exit(1);
    }
  }

  waitpid(pid, &status, 0);

  assert(*counter == 2 * TESTS_NLOOPS);

  return 0;
}
