*reverie* allows using a tool shared library (tool) with `--tool` switch.
A tool basically implements `captured_syscall` C API, so after *reverie* 
successfully patched a syscall site, it can generate trampoline and can jump
to `captured_syscall`, so that we can intercerpt the original syscalls.

The tool is loaded by *reverie* using `LD_PRELOAD`, hence it is not usable 
after `LD_PRELOAD` is finished. There're already about 20+ syscalls called
by `ld-linux.so` and they're not catchable. For now this is a hard limitation,
however, we can still catch them by `SECCOMP`. once the tool is
(LD_PRE)loaded, *reverie* tries to patch any syscall with predefined rules
(in `src/bpf.c`). please note we only apply patching when the `syscall` and
following instructions match our predefined pattern, hence, if there's no 
pattern match, patching would not occur. This makes write interception code
cumbersome, because not all syscalls are catchable into `captured_syscall`
function call in tracee's memory space. The plan is when such case happens,
we could use ptrace SECCOMP stop to inject `captured_syscall`, forcing tracee
to do this very function call. It is relatively easy to inject real syscalls,
and we've done that in the past many times. however `captured_syscall` is a
regular C function (written in rust), and it could use mmx/sse registers, hence
it would be more difficult to inject it in the tracer, nonetheless, it should
be possible with proper `xsave/xrestore` instructions.

In the future, we might install a second seccomp rule in tool's init function,
so that we can patch the syscall either in tracee's memory space, or intercept 
the syscall in `SIGSYS` signal handler, but this also have risks such as the
decoding of `ucontext` from the signal handler seems complicated, and redicting
control flow in the same task seems more difficult than ptrace.

The tool library is running in tracee's memory space, however, because we
intercept raw syscall, we must be very careful to avoid dead locks. i.e.: doing
allocations could be dangrous, *drop* (inserted by rust) could be dangerous 
as well, because it may call `pthread_xxx`, which then may call `futex` syscall.
Even there's no dead lock, doing the extra syscalls can cause performance 
degration. Thus the tool must be written in a very strong constrait. We also 
have a choice to use `std` or `no_std`. using `no_std` allows the tool not to
have dependencies on any external library (including libc), because of that, we
can rewrite the seccomp filters, allowing all syscalls inside tool memory
range (by checking procfs). however, `no_std` variant is a lot more difficult
to write, less documented, and have less libraries and features.

After serveral discussion, our `captured_syscall` could be look like:

```rust
pub extern "C" fn captured_syscall(
    p: &mut ProcessState,
    t: &mut ThreadState,
	a: &Args);
```

`ProcessState` holds resources sharing among threads, such as unix file
descriptor, signal handlers, etc. while `ThreadState` holds resources local
to any threads. The hard part is our trampoline, like a reguar syscall,
doesn't know anything, except the syscall no and six arguments. We could 
allocate `ProcessState` during ptrace exec event; and allocate `ThreadState`
both in exec event and *fork*/*vfork*/*clone* event. however, because the
heap belongs to the tracee only, it could be quite difficult to prepare
those data structures in the tracer, even with help of `Serialize/Deserialize`.
It could be possible to abuse *inject* function calls once again, or we could
rewrite all tracees' global allocator, forcing them use the same heap
preallocated by the tracer. This isn't any easier by any means, i.e.: the
tracer will need to expose some APIs to claim/reclaim memory to the tracees;
so that tracees could use the exposed API to implements their own Global
Allocator; It also seems very unsafe, because any tracee have access to the
global heap, shared among the tracer and all tracees.
