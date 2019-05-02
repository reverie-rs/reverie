#include <sys/types.h>

#include "scinfo.h"

extern long captured_syscall(int, long, long, long, long, long, long);

__attribute__((visibility("hidden"))) long syscall_hook(const struct syscall_info* syscall)
{
    return captured_syscall(syscall->no, syscall->args[0], syscall->args[1], syscall->args[2], syscall->args[3], syscall->args[4], syscall->args[5]);
}
