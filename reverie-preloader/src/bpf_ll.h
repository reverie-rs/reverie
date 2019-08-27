#ifndef _MY_BPF_H
#define _MY_BPF_H

#include <sys/types.h>
#include <linux/filter.h>

#define SOCK_FILTER_MAX BPF_MAXINSNS

struct range {
  unsigned long begin;
  unsigned long end;
};

long bpf_ll_whitelist_ips(struct sock_filter* filter, struct range* ranges, size_t nranges);
long bpf_ll_blacklist_ips(struct sock_filter* filter, struct range* ranges, size_t nranges);

#endif
