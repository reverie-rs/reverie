# Syscall patching

This document explains how `reverie` patches system calls.  It patches syscall
instructions in the user's program at runtime, with the help of seccomp and ptrace. A
syscall site is a assembly sequence contains a `syscall` instruction (x86_64), and a
pattern right after the very `syscall` instruction.

## The role of seccomp
`reverie` is a *ptrace* based tracer, information about ptrace can be mostly found in `man 2 ptrace`.
Since kernel 3.5, seccomp can be used together with `ptrace`, with option of `PTRACE_O_TRACESECCOMP`. 
By default we setup seccomp to filter most syscalls except few blacklisted ones (such as `rt_sigreturn`), 
in a way the filtered syscalls will enter ptrace stop, please see `man 2 seccomp`, section `SECCOMP_RET_TRACE`
for more details; we also allow syscall going through (without any stop) based on program counter
(*PC*, or *rip* in x86_64).
```
                                         +---------------+
                         blacklisted?    | going through |
                      +----------------->+---------------+
					  |
  +---------+         |  PC=<predefined> +---------------+
  | syscall | --------+----------------->| going through |
  +---------+         |                  +---------------+
                      | otherwise
                      +----------------->+---------------+
                                         | *ptraced*     |
                                         +---------------+
```
## Seccomp stops
With above setup, we'll enter syscall enter stop, that is *PC*=`rip_at_syscal+2`, but the `syscall`
is yet to run by the kernel; there two most sensible options to resume control flow: either by
`PTRACE_CONT`, which allows the *ptraced* program to continue, without syscall exit stop; or 
`PTRACE_SYSCALL`, to allow the *ptraced* program to stop at syscall exit stop. hence the syscall 
exit stop has *PC*=`rip_at_syscall+2`, and the very syscall has returned from kernel. The idea of
syscall enter/exit stops is that we can modify syscall arguments on enter, and/or change syscall 
arguments/return values on exit. One notable aspect is on syscall enter stop, if we change the 
syscall number to `-1`, then the syscall will be ignored (or skipped) by kernel.

## Patchable syscall site
`syscall` instruction is only 2-byte long in x86_64, however, we need 5-byte relative jump within
*PC*+/- 2GB into our trampoline stub, from where we have a long jump so that we can access anywhere
within the entire 64-bit address space. So we need a pattern to replace the `syscall` sequence, the
good news is most syscall sequences (we also name it as syscall site) have a pattern, such as:

```assembly
   3ee73:       0f 05                   syscall 
   3ee75:       48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
```

We can replace above syscall site, with a single jump, i.e.: `callq <stub_pcrel32>`, and pad the extra
3-byte as *NOPs*. The bad news are:

* some syscall site cannot be patched in this manor, there could be a
  local jump who jumps between address of `syscall` and `syscall+0x5`, namely `clock_nanosleep` in
  glibc has the issue.

* we may not have enough pre-defined patterns, so some syscalls might fail to match any of them,
  leaving them unpatched.
  
* some syscall site especially hand-crafted assembly, can be something like below:

```assembly
00: syscall           ; two-byte
02: retq              ; one-byte
03: <a_new_function>: ; a new function prologe
```
  This have a similar impact as the first case.

Afer patching, the syscall instruction will be relocated into a special page with a specific address,
so that it won't trigger further seccomp event.

## Two level jumping to the trampoline
After we identify patchable syscall site, we can generate stub page(s) to jump into, the stub page(s)
must resides within *PCRel32* so that we'll have the right *5-byte* assembly instruction. This can be 
done by search `/proc/<pid>/maps` and find the spare page(s). Please note this is only the stub page,
because the address space is *64-bit*, there're could be multiple stub pages, but they can jump into the
 same trampoline. we place our trampoline at a fixed address, so stub page can generate a absolute jump
 to the trampoline easily.

## Patch in a multi threaded context
Even though `reverie` is the only tracer, it can resume any ptrace stopped tracee, so the tracees run
 in a multi threaded context; The *tracer* uses a pseudo read write lock to keep track of which thread 
entered/exited or tried to apply patch, the tracer chooses whether or not a thread should take a
read/write lock based on the recoards.
 

0) once the thread enters syscall enter stop, it checks *rip_minus_two*, to see if it is still a `syscall`
  instruction.
  
  If not, we may run into a cache coherency issue, the tracer will modify the thread/tracee *PC* 
  and return adress, forcing the tracee to do a synchronization, by doing a `cpuid` sequence, then resume
  from original *PC*, in this case the syscall site is already patched, we simply cancel the seccomp syscall
  and resume from *rip_minus_two* after the synchronization;

1) thread takes a read lock upon syscall enter stop, or busy waits the lock, then check whether or not we
  can safely patch the syscall site

2a) if we can patch the syscall site, the *tracer* record the thread have taken the write lock.

  please note the write lock cannot be token when there *reader*s, because it is not safe to patch while 
  there're other threads is doing the very same syscall. After the patching is done, we cancel the seccomp
  syscall, and resume from *rip_minus_two*, and release the write lock.

2b) if we cannot patch the syscall site, we simply resume to syscall exit stop, please note this might change
  in the future.

3) releasing of read locks

   some syscall such as `epoll`/`select`/`futex` can be blocking for arbitrary time, it is very possible multiple
   threads have taken read locks. we release the read lock by using `PTRACE_SYSCALL` to resume the tracee, and
   do single steps until after tracee have leaved the syscall sequence. In this way, we don't have to block the
   tracer.

## Optimizations
* We keep track of unpatchable syscalls, so that we don't have to redo the check everytime;
* the tracer mimic the unix semantics:

  - for threads, we share the data such as locks, stub pages, trampoline, as well as unpatchable syscalls, etc.
  - for processes, we start simply copy the address from parent process, and abuse unix's COW (copy-on-write) nature.

  This bends quite well with `rust`, i.e.:

  for `clone` syscall:
  ```rust
      fn cloned(&self) -> Self {
        let pid_raw = self.getevent().expect(&format!("{:?} ptrace getevent", self));
        let child = Pid::from_raw(pid_raw as libc::pid_t);
        TracedTask {
		    // snip
            memory_map: self.memory_map.clone(),
            stub_pages: self.stub_pages.clone(),
            trampoline_hooks: &SYSCALL_HOOKS,
            injected_mmap_page: self.injected_mmap_page.clone(),
            unpatchable_syscalls: self.unpatchable_syscalls.clone(),
            patched_syscalls: self.patched_syscalls.clone(),
  ```
  while for `fork` syscall:
  ```rust
    fn forked(&self) -> Self {
        let pid_raw = self.getevent().expect(&format!("{:?} ptrace getevent", self));
        let child = Pid::from_raw(pid_raw as libc::pid_t);
        TracedTask {
			// snip
            stub_pages: {
                let stubs = self.stub_pages.borrow().clone();
                Rc::new(RefCell::new(stubs))
            },
            trampoline_hooks: &SYSCALL_HOOKS,
            ldpreload_address: self.ldpreload_address,
            injected_mmap_page: self.injected_mmap_page,
            unpatchable_syscalls: {
                let unpatchables = self.unpatchable_syscalls.borrow().clone();
                Rc::new(RefCell::new(unpatchables))
            },
            patched_syscalls: {
                let patched = self.patched_syscalls.borrow().clone();
                Rc::new(RefCell::new(patched))
            },
  ```
