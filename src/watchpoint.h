#ifndef _MY_WATCHPOINT_H
#define _MY_WATCHPOINT_H

#include <sys/types.h>

struct watchpoint {
  unsigned long ip;
  unsigned long saved_insn;
};

struct watchpoint* find_watchpoint(unsigned long at);
struct watchpoint* set_watchpoint(pid_t pid, unsigned long at);
void remove_watchpoint(pid_t pid, unsigned long at);

#endif
