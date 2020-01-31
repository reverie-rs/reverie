#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>

typedef int (*pfn)(void);

static void runAppDefault(void)
{
  printf("run without arguments, my pid: %u\n", getpid());
}

int main(int argc, char* argv[], char* envp[])
{
  pid_t pid;
  pfn f;

  if (argc == 2 && strcmp(argv[1], "fork") == 0) {
    f = fork;
  } else if (argc == 2 && strcmp(argv[1], "vfork") == 0) {
    f = vfork;
  } else if (argc == 1) {
    runAppDefault();
    return 0;
  } else {
    fprintf(stderr, "%s <fork | vfork>\n", argv[0]);
    exit(1);
  }

  pid = f();
  assert(pid >= 0);

  if (pid == 0) {
    char* const newArgv[] = {argv[0], NULL};
    printf("child pid: %u\n", getpid());
    execve(argv[0], newArgv, envp);
    printf("exec failed: %s\n", strerror(errno));
  } else {
    int status;
    printf("parent pid: %u\n", getpid());
    for (long i = 0; i < 1000000000; i++);
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
      printf("%u terminated by signal: %u\n", pid, WTERMSIG(status));
    }
  }
}
