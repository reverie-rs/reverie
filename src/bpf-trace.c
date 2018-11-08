/**
 * a bpf tracer demonstrates how to ptrace with seccomp-bpf
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/personality.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <unistd.h>
#include <signal.h>
#include <sched.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <inttypes.h>
#include <dlfcn.h>

#include "utils.h"
#include "watchpoint.h"
#include "syscallbuf.h"
#include "symbols.h"
#include "syscallT.h"
#include "bpf.h"

static void dump_user_regs(pid_t pid)
{
  struct user_regs_struct regs;
  long insn;

  ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));

  unsigned long stack, sp = (regs.rsp-128)&-16, ip = regs.rip & -8;
  info(  "dumping regisgter context\n"
	 "rax: %016llx, rbx: %016llx, rcx: %016llx, rdx: %016llx\n"
	 "rsi: %016llx, rdi: %016llx, rbp: %016llx, rsp: %016llx\n"
	 "r8 : %016llx, r9 : %016llx, r10: %016llx, r11: %016llx\n"
	 "r12: %016llx, r13: %016llx, r14: %016llx, r15: %016llx\n"
	 "rip: %016llx, eflags: %016llx\n",
	 regs.rax, regs.rbx, regs.rcx, regs.rdx,
	 regs.rsi, regs.rdi, regs.rbp, regs.rsp,
	 regs.r8,  regs.r9,  regs.r10, regs.r11,
	 regs.r12, regs.r13, regs.r14, regs.r15,
	 regs.rip, regs.eflags);

  info("instructun at: %lx\n", ip);
  for (int i = 0; i < 4; i++) {
    insn = ptrace(PTRACE_PEEKTEXT, pid, ip+i*sizeof(long), 0);
    info(  "%lx: %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx\n", ip+i*sizeof(long),
	   insn & 0xff, (insn >> 8) & 0xff, (insn >> 16) & 0xff, (insn >> 24) & 0xff,
	   (insn >> 32) & 0xff, (insn >> 40) & 0xff, (insn >> 48) & 0xff, (insn >> 56) & 0xff);
  }
  info("stack trace at: %lx\n", sp);
  for (int i = 0; i < 16; i++) {
    info_("%lx: ", sp);
    for (int j = 0; j < 4; j++) {
      stack = ptrace(PTRACE_PEEKDATA, pid, sp, 0);
      if (sp == regs.rsp)
	info_("<%016lx> ", stack);
      else
	info_(" %016lx  ", stack);
      sp += sizeof(long);
    }
    info_("\n");
  }
}

static struct syscall_patch_hook* syscall_patch_hooks;
static int nr_syscall_patch_hooks;

static void populate_syscall_patches(pid_t pid)
{
  unsigned long tn  = TLS_SYSCALL_PATCH_SIZE;
  unsigned long tp  = TLS_SYSCALL_PATCH_ADDR;
  unsigned long n;
  unsigned long p;

  ThrowErrnoIfMinus1((n = ptrace(PTRACE_PEEKDATA, pid, tn, 0)));
  ThrowErrnoIfMinus1((p = ptrace(PTRACE_PEEKDATA, pid, tp, 0)));

  nr_syscall_patch_hooks = n;
  syscall_patch_hooks = calloc(n, sizeof(struct syscall_patch_hook));
  Expect(syscall_patch_hooks != NULL);

  unsigned long size = (sizeof(struct syscall_patch_hook) + 7) & ~7UL;
  unsigned long* ptr = (unsigned long*)syscall_patch_hooks;
  unsigned long* pp  = (unsigned long*)p;

  for (int i = 0; i < n * size / sizeof(long); i++) {
    ptr[i] = ptrace(PTRACE_PEEKDATA, pid, &pp[i], 0);
    Expect(ptr[i] != -1UL);
  }
}

static void show_mappings(struct mmap_entry* map, int nb)
{
  char perm[5] = {0,};
  for (int i = 0; i < nb; i++) {
    perm[0] = map[i].prot & PROT_READ? 'r': '-';
    perm[1] = map[i].prot & PROT_WRITE? 'w': '-';
    perm[2] = map[i].prot & PROT_EXEC? 'x': '-';
    perm[3] = map[i].flags & MAP_PRIVATE? 'p': 's';
    perm[4] = 0;
    debug("%s: %lx-%lx %s\n", map[i].file[0]? map[i].file: "<noname>", map[i].base, map[i].base+map[i].size, perm);
  }
}

static bool patch_at(pid_t pid, struct user_regs_struct* regs, struct syscall_patch_hook* p)
{
  struct mmap_entry* map;
  unsigned long jmpAddr;
  int n;
  unsigned long insn, insn2 = 0;
  int target, status;
  const int jmpInsnSize = 5; /* jmpq/callq +/- 2GB */
  const int syscallInsnSize = 2;

  unsigned long ip = regs->rip - syscallInsnSize;
  struct user_regs_struct newRegs;

  map = populate_memory_map(pid, &n);
  Expect(map != NULL);
  show_mappings(map, n);

  int bytes = (int)(p->next_instruction_length);
  int remain = syscallInsnSize + bytes - jmpInsnSize;
  Expect(remain >= 0 && remain <= 8);

  jmpAddr = p->hook_address;
  Expect(jmpAddr - ip <= 1UL << 31 || ip - jmpAddr <= 1UL << 31);
  insn = ptrace(PTRACE_PEEKTEXT, pid, jmpAddr, 0);
  debug("jmp target addr: %lx, insn: %lx\n", jmpAddr, insn);

  target = (int)((long)jmpAddr - (long)ip - jmpInsnSize);
  insn = ptrace(PTRACE_PEEKTEXT, pid, ip, 0);
  insn2 = insn;

  /* 5 bytes jump +/- 2GB */
  for (int i = 0; i < jmpInsnSize; i++) {
    insn &=~ (0xffL << 8*i);
  }

  insn |= (0xe8L) << 0;
  insn |= ((long)target & 0xff) << 8;
  insn |= ((long)(target >> 8) & 0xff) << 16;
  insn |= ((long)(target >> 16) & 0xff) << 24;
  insn |= ((long)(target >> 24) & 0xff) << 32;

  switch(remain) {
  case 0:
    break;
  case 1: insn &=~ (0xffL << 40); insn |= 0x90L << 40; break;
  case 2: insn &=~ (0xffffL << 40); insn |= 909090L << 40; break;
  case 3: default: insn &=~ (0xffffffL << 40); insn |= 0x001f0fL << 40; break;
  }

  debug("ip = %p, instruction length: %d, before/after patching: %lx/%lx, jmp addr: %x\n", (void*)ip, bytes, insn2, insn, target);

  if (remain > 3) {
    insn2 = ptrace(PTRACE_PEEKTEXT, pid, ip+sizeof(long), 0);
    switch(remain-3) {
    case 1: insn2 &=~ 0xffL; insn2 |= 0x90L; break;
    case 2: insn2 &=~ 0xffffL; insn2 |= 0x9090L; break;
    case 3: insn2 &=~ 0xffffffL; insn2 |= 0x001f0fL; break;
    case 4: insn2 &=~ 0xffffffffL; insn2 |= 0x00401f0fL; break;
    case 5: insn2 &= ~0xffffffffffL; insn2 |= 0x0000441f0fL; break;
    default: Expect(remain <= 8); break;
    }
  }

  do { /* single step until we're safe to patch the syscall */
    ThrowErrnoIfMinus(ptrace(PTRACE_SINGLESTEP, pid, 0, 0));
    Expect(waitpid(pid, &status, 0) == pid);
    //Expect(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
    Expect(WIFSTOPPED(status));
    switch(WSTOPSIG(status)) {
    case SIGTRAP:
      ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &newRegs));
      break;
    case SIGCHLD:
      //waitpid(pid, &status, 0);
      ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, SIGCHLD));
      return false;
      break;
    default:
      panic("unknown signal: %d\n", WSTOPSIG(status));
      break;
    }
  } while (newRegs.rip >= ip && newRegs.rip < ip + syscallInsnSize + bytes);

  /* now patch our syscall */
  ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, ip, insn));
  /* patch second instruction word */
  if (remain > 3) ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, ip+sizeof(long), insn2));
  dump_user_regs(pid);
  insn = ptrace(PTRACE_PEEKTEXT, pid, ip, 0);
  debug("after patching: %lx, resume from rip: %llx\n", insn, newRegs.rip);
  free_mmap_entry(map);

  return true;
}

static int ptrace_peek_cstring(pid_t pid, char* buf, int n, const void* remotePtr)
{
  long data;
  int i = 0, k;
  bool null = 0;

  while (i < n && !null) {
    errno = 0;
    data = ptrace(PTRACE_PEEKDATA, pid, remotePtr, 0);
    if (data == -1 && errno != 0) {
      crit("ptrace peekdata failed: %s\n", strerror(errno));
      exit(1);
    }
    remotePtr += sizeof(long);
    for(k = 0; k < sizeof(long) && i < n; i++, k++) {
      buf[i] = (data >> (8*k)) & 0xff;
      if (buf[i] == '\0') null = true;
    }
  }
  return i;
}

static bool ensureSyscallInsn(int pid, unsigned long rip)
{
  unsigned long insn;
  
  insn = ptrace(PTRACE_PEEKTEXT, pid, rip, 0);
  Expect((insn&0xffffL) == 0x050f);
  return ((insn &0xffffL) == 0x050f);
}

static void may_patch_syscall(int pid, struct user_regs_struct* regs)
{
  unsigned char bytes[17] = {0,};
  ensureSyscallInsn(pid, regs->rip - 2);
  unsigned long insn, ip = regs->rip;
  int found, no;

  insn = ptrace(PTRACE_PEEKTEXT, pid, ip, 0);
  memcpy(bytes, &insn, sizeof(insn));
  insn = ptrace(PTRACE_PEEKTEXT, pid, ip+sizeof(insn), 0);
  memcpy(bytes+sizeof(insn), &insn, sizeof(insn));

  no = regs->orig_rax;
  populate_syscall_patches(pid);
  for (int i = 0; i < nr_syscall_patch_hooks; i++) {
    found = true;
    for (unsigned j = 0; j < (unsigned) syscall_patch_hooks[i].next_instruction_length; j++) {
      if ((bytes[j] & 0xff) != syscall_patch_hooks[i].next_instruction_bytes[j]) {
	found = false;
	continue;
      }
    }
    if (found) {
      bool rc = patch_at(pid, regs, &syscall_patch_hooks[i]);
      log("found patchable syscall (%s) instruction at %lx, patch status: %d\n", syscall_lookup(no), ip-2, rc);
      return;
    }
  }
  if (!found) {
    log("not able to patch syscall %s, pc = %llx\n", syscall_lookup(no), regs->rip);
  }
}

static void openat_enter(int pid, struct user_regs_struct* regs)
{
  char path[1 + PATH_MAX];
  const void* remotePtr = (const void*)regs->rsi;
  ptrace_peek_cstring(pid, path, PATH_MAX, remotePtr);
  info("(seccomp) openat: %s\n", path);
}

static void access_enter(int pid, struct user_regs_struct* regs)
{
  char path[1 + PATH_MAX];
  const void* remotePtr = (const void*)regs->rdi;
  ptrace_peek_cstring(pid, path, PATH_MAX, remotePtr);
  info("(seccomp) access file: %s\n", path);
}

static int syscall_enter(int pid, int syscall, struct user_regs_struct* regs)
{
  errno = 0;
  unsigned long hook = ptrace(PTRACE_PEEKDATA, pid, TLS_SYSCALL_HOOK_ADDR, 0);
  
  if (hook == -1UL) {
	  if (errno) {
		  info("ptrace failed for addr: %lx, error: %s\n", TLS_SYSCALL_HOOK_ADDR, strerror(errno));
		  return 0;
	  }
  }

  debug("seccomp syscall enter: %s\n", syscall_lookup(syscall));
  /* syscall hooks installed, patch syscall instruction, 
   * otherwise allow syscall go through seccomp
   * NB: even we patched syscall, we still allow it fall
   * through because the patched instruction only taken
   * effects on next run */
  if (hook != 0 && hook != -1UL){
    may_patch_syscall(pid, regs);
  } else {
    switch(syscall) {
    case SYS_openat:
      openat_enter(pid, regs);
      break;
    case SYS_access:
      access_enter(pid, regs);
      break;
    default:
      break;
    }
  }
  return 0;
}

static void do_ptrace_seccomp(pid_t pid)
{
  struct user_regs_struct regs;
  long msg;
  int syscall;
  
  ThrowErrnoIfMinus(ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg));
  ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
  
  if (msg == 0x7fff) {
    int unfiltered = regs.orig_rax;
    fprintf(stderr, "unfiltered syscall: %u\n", unfiltered);
    exit(1);
  }

  syscall = (int)regs.orig_rax;
  log("%u seccomp trapped intercept syscall: %s\n", pid, syscall_lookup(syscall));
  syscall_enter(pid, syscall, &regs);

  ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, 0));
}

static void usage(const char* prog) {
  fprintf(stderr, "%s <program> [program_arguments]\n", prog);
}

static void load_syscall_pages(pid_t pid) {
  struct user_regs_struct regs, oldregs;
  int status;
  
  ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
  memcpy(&oldregs, &regs, sizeof(regs));

  regs.orig_rax = SYS_mmap;
  regs.rax = SYS_mmap;
  regs.rdi = 0x70000000UL;
  regs.rsi = 0x2000;
  regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
  regs.r10 = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS;
  regs.r8 = -1;
  regs.r9 = 0;

  unsigned long insn = 0x90c3050f90c3050f;
  ThrowErrnoIfMinus(ptrace(PTRACE_SETREGS, pid, 0, &regs));
  ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, 0));
  Expect(waitpid(pid, &status, 0) == pid);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { /* breakpoint hits */
    ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
    if ((long)regs.rax < 0) {
      panic("unable to inject syscall pages at 0x70000000, error: %s\n", strerror((long)-regs.rax));
    } else {
      ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, 0x70000000UL, insn));
      ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, 0x70000000UL + sizeof(insn), insn));
      oldregs.rip = regs.rip-4; /* 0xcc, syscall, 0xcc = 4 bytes */
      memcpy(&regs, &oldregs, sizeof(regs));
      ThrowErrnoIfMinus(ptrace(PTRACE_SETREGS, pid, 0, &regs));
    }
  } else {
    ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
    fprintf(stderr, "expect breakpoint stop, but got: %x, rip: %llx\n", status, regs.rip);
    exit(1);
  }
}

/* now tracee is stopped and exec has replaced old 
   program with new program context */
static void tracee_preinit(pid_t pid) {
  load_syscall_pages(pid);
}

/* reached ptrace_event_exec, but the new progrma isn't actually running */
static void do_ptrace_exec(pid_t pid) {
  struct user_regs_struct regs;
  int status;
  unsigned long stub = 0xcc050fcc;
  unsigned long ripAligned;
  
  ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
  unsigned long saved_insn;

  /* rip must be word aligned */
  assert((regs.rip & 0x7) == 0);
  ripAligned = regs.rip & (-8);
  saved_insn = ptrace(PTRACE_PEEKTEXT, pid, ripAligned, 0);
  assert(saved_insn != -1);
  /* bp/syscall/bp */
  ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, ripAligned, (saved_insn & ~0xffffffffUL) | stub));
  ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, 0));
  assert(waitpid(pid, &status, 0) == pid);

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { /* breakpoint hits */
    tracee_preinit(pid);
    assert(ptrace(PTRACE_POKETEXT, pid, ripAligned, saved_insn) == 0);
    assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);
  } else {
    fprintf(stderr, "expect breakpoint hits.\n");
    exit(1);
  }
}

static void handle_ptrace_signal(pid_t pid, unsigned status)
{
  if (WSTOPSIG(status) == SIGSEGV || WSTOPSIG(status) == SIGILL) {
    siginfo_t info;
    ThrowErrnoIfMinus(ptrace(PTRACE_GETSIGINFO, pid, 0, (void*)&info));
    printf("tracee received sigsegv, signo: %d, errno: %d, code: %d, addr: %p\n", info.si_signo, info.si_errno, info.si_code, info.si_addr);
    dump_user_regs(pid);
    ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)));
    sleep(1);
  } else if (WSTOPSIG(status) == SIGCHLD) {
    log("%u got SIGCHLD\n", pid);
    ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)));
  } else {
    ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)));
  }
}

static void handle_ptrace_event(pid_t pid, unsigned event)
{
  switch(event) {
  case PTRACE_EVENT_EXEC:
    /* wait for our expected PTRACE_EVENT_EXEC */
    do_ptrace_exec(pid);
    break;
  case PTRACE_EVENT_SECCOMP:
    do_ptrace_seccomp(pid);
    break;
  default:
    panic("%u unknown ptrace event: %u\n", pid, event);
    break;
  }
}

static int run_tracer(pid_t pid) {
  int status;
  
  assert(waitpid(pid, &status, 0) == pid);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) { /* intial sigstop */
    ;
  } else {
    fprintf(stderr, "expected SIGSTOP to be raised, but got: %x\n", status);
    return -1;
  }

  assert(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD ) == 0);
  assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);

  while ((pid = waitpid(-1, &status, 0)) != -1) {
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      log("signaled: status=%x\n", status);
      continue;
    } else if (WIFCONTINUED(status)) {
      panic("continued: status=%x\n", status);
    } else if (WIFSTOPPED(status)) {
      switch(WSTOPSIG(status)) {
      case SIGTRAP:
	handle_ptrace_event(pid, status >> 16);
	break;
      default:
	handle_ptrace_signal(pid, status);
	break;
      }
    } else {
      log("waitpid %u unknown status: %x\n", pid, status);
    }
  }
  return -1;
}

extern void bpf_patch_all(void);
static int run_app(int argc, char* argv[])
{
  pid_t pid;
  int ret = -1;

  pid = fork();
  
  if (pid > 0) {
    ret = run_tracer(pid);
  } else if (pid == 0) {
    ThrowErrnoIfMinus(personality(ADDR_NO_RANDOMIZE));
    assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
    raise(SIGSTOP);
    bpf_patch_all();
    char* const envp[] = {
      "PATH=/bin:/usr/bin",
      "LD_PRELOAD=./libpreload.so",
      NULL,
    };
    execvpe(argv[0], argv, envp);
    fprintf(stderr, "unable to run child: %s\n", argv[1]);
    exit(1);
  }

  return ret;
}

int main(int argc, char* argv[])
{
  int nargs = argc - 1;
  int optIndex = 1;
  int debugLevel;
  
  if (argc < 2) {
    usage(argv[0]);
    exit(1);
  }

  for (int i = 1; i < argc; i++) {
    if (strncmp(argv[i], "--debug=", 8) == 0) {
      debugLevel = (int)strtol(&argv[1][8], NULL, 10);
      debug_init(debugLevel);
      ++optIndex;
      --nargs;
    } else {
      break;
    }
  }

  return run_app(nargs, &argv[optIndex]);
}
