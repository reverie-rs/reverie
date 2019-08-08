#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "bpf-helper.h"
#include "bpf_ll.h"

static const char* const lab_and_then[] = {
  "and_then#00", "and_then#01", "and_then#02", "and_then#03",
  "and_then#04", "and_then#05", "and_then#06", "and_then#07",
  "and_then#08", "and_then#09", "and_then#10", "and_then#11",
  "and_then#12", "and_then#13", "and_then#14", "and_then#15",
  "and_then#16", "and_then#17", "and_then#18", "and_then#19",
  "and_then#20", "and_then#21", "and_then#22", "and_then#23",
  "and_then#24", "and_then#25", "and_then#26", "and_then#27",
  "and_then#28", "and_then#29", "and_then#30", "and_then#31",
};

static const char* const lab_go_next[] = {
  "go_next#00", "go_next#01", "go_next#02", "go_next#03",
  "go_next#04", "go_next#05", "go_next#06", "go_next#07",
  "go_next#08", "go_next#09", "go_next#10", "go_next#11",
  "go_next#12", "go_next#13", "go_next#14", "go_next#15",
  "go_next#16", "go_next#17", "go_next#18", "go_next#19",
  "go_next#20", "go_next#21", "go_next#22", "go_next#23",
  "go_next#24", "go_next#25", "go_next#26", "go_next#27",
  "go_next#28", "go_next#29", "go_next#30", "go_next#31",
};

#define FIND_LABEL_INDEXED(labels, symbol, index) \
  seccomp_bpf_label((labels), (symbol)[index])

#define JUMP_INDEXED(labels, symbol, index)				\
  BPF_JUMP(BPF_JMP+BPF_JA, FIND_LABEL_INDEXED((labels), (symbol), (index)), \
	   JUMP_JT, JUMP_JF)

#define LABEL_INDEXED(labels, symbol, index)				\
  BPF_JUMP(BPF_JMP+BPF_JA, FIND_LABEL_INDEXED((labels), (symbol), (index)), \
		 LABEL_JT, LABEL_JF)

long bpf_ll_whitelist_ips(struct sock_filter* filter, struct range* ranges, size_t nranges)
{
  struct bpf_labels l = {
    .count = 0,
  };

  struct sock_filter prelude[] = {
    LOAD_SYSCALL_NR,
    SYSCALL(__NR_clone, ALLOW),
    SYSCALL(__NR_fork, ALLOW),
    SYSCALL(__NR_vfork, ALLOW),
    SYSCALL(__NR_rt_sigreturn, ALLOW),
    SYSCALL(__NR_clock_nanosleep, ALLOW),	// this syscall should not be patched
    LOAD_SYSCALL_IP,
  };
  long k = 0;
  long prelude_nb = sizeof(prelude) / sizeof(prelude[0]);

  if (prelude_nb >= SOCK_FILTER_MAX) return 0;
  memcpy(&filter[k], prelude, sizeof(prelude));
  k += prelude_nb;

  for (size_t i = 0; i < nranges; i++) {
    struct sock_filter f[] = {
      JGE(ranges[i].begin, JUMP_INDEXED(&l, lab_and_then, i)),
      JUMP_INDEXED(&l, lab_go_next, i),
      LABEL_INDEXED(&l, lab_and_then, i),
      JLE(ranges[i].end, ALLOW),
      LABEL_INDEXED(&l, lab_go_next, i),
    };
    int nb = sizeof(f) / sizeof(f[0]);
    assert(k + nb < SOCK_FILTER_MAX);
    if (k + nb >= SOCK_FILTER_MAX) {
      return 0;
    }
    memcpy(&filter[k], f, sizeof(f));
    k += nb;
  }

  struct sock_filter epilogue[] = {
    TRACE,
  };
  int epilogue_nb = sizeof(epilogue) / sizeof(epilogue[0]);
  assert(k + epilogue_nb < SOCK_FILTER_MAX);
  if (k + epilogue_nb >= SOCK_FILTER_MAX) {
    return 0;
  }
  memcpy(&filter[k], epilogue, sizeof(epilogue));
  k += epilogue_nb;

  bpf_resolve_jumps(&l, filter, k);

  return k;
}

// everyting is allowed, except the blacklisted ones
long bpf_ll_blacklist_ips(struct sock_filter* filter, struct range* ranges, size_t nranges)
{
  struct bpf_labels l = {
    .count = 0,
  };

  struct sock_filter prelude[] = {
    LOAD_SYSCALL_IP,
  };

  long k = 0;
  long prelude_nb = sizeof(prelude) / sizeof(prelude[0]);

  if (prelude_nb >= SOCK_FILTER_MAX) return 0;
  memcpy(&filter[k], prelude, sizeof(prelude));
  k += prelude_nb;

  for (size_t i = 0; i < nranges; i++) {
    struct sock_filter f[] = {
      JLE(ranges[i].end, TRACE),
      JGE(ranges[i].begin, TRACE),
    };
    int nb = sizeof(f) / sizeof(f[0]);
    assert(k + nb < SOCK_FILTER_MAX);
    if (k + nb >= SOCK_FILTER_MAX) {
      return 0;
    }
    memcpy(&filter[k], f, sizeof(f));
    k += nb;
  }

  struct sock_filter epilogue[] = {
    ALLOW,
  };
  int epilogue_nb = sizeof(epilogue) / sizeof(epilogue[0]);
  assert(k + epilogue_nb < SOCK_FILTER_MAX);
  if (k + epilogue_nb >= SOCK_FILTER_MAX) {
    return 0;
  }
  memcpy(&filter[k], epilogue, sizeof(epilogue));
  k += epilogue_nb;

  bpf_resolve_jumps(&l, filter, k);

  return k;
}
