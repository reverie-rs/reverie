#ifndef _MY_SYSTRACE_H
#define _MY_SYSTRACE_H

#include "syscallbuf.h"

/* syscall dispatcher, weak symbol, so that others can overrides */
extern long captured_syscall(int syscallno, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

/* initiate a syscall, traced by seccomp-bpf */
extern long traced_syscall(int syscallno, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);
/* initiate a syscall, untraced/allowed by seccomp-bpf */

extern long untraced_syscall(int syscallno, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

#endif
