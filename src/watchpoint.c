#include <sys/types.h>
#include <sys/ptrace.h>

#include <stdio.h>

#include "utils.h"
#include "watchpoint.h"

static struct watchpoint watchpoints[1024];

struct watchpoint* next_watchpoint(void)
{
  struct watchpoint* p;
  
  for (int i = 0; i < sizeof(watchpoints) / sizeof(watchpoints[0]); i++) {
    p = &watchpoints[i];
    if (p->ip == 0 && p->saved_insn == 0) return p;
  }
  return NULL;
}

struct watchpoint* find_watchpoint(unsigned long at)
{
  struct watchpoint* w;

  for (int i = 0; i < sizeof(watchpoints) / sizeof(watchpoints[0]); i++) {
    w = &watchpoints[i];
    if (w->ip == at) {
      return w;
    }
  }
  return NULL;
}

struct watchpoint* set_watchpoint(pid_t pid, unsigned long at)
{
  struct watchpoint* w = next_watchpoint();
  Expect(w);

  long insn = ptrace(PTRACE_PEEKTEXT, pid, at, 0);
  w->ip = at;
  w->saved_insn = insn;
  
  insn &=~ 0xffL;
  insn |= 0xccL;
  ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, at, insn));

  return w;
}

void remove_watchpoint(pid_t pid, unsigned long at)
{
  struct watchpoint* w = find_watchpoint(at);
  Expect(w);

  ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, at, w->saved_insn));
}

