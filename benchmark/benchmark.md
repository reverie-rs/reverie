On ubuntu-18.04, i5-4670 (4-core), using benchmark `getpid-many.c`, `getpid-many-threaded2.c`, `systrace` built with release mode.

The benchmark focuses on the worse case metrics, that is, every syscalls
are getting patched. i.e.: `getpid-many` create a big chunk of `getpid`
syscall sequence and each sequence will cause patching.

* `getpid` syscall takes about 260ns

* patched `getpid` (including the syscall itself) takes about 20us
  which has an overhead of ~77x
  
* patched `getpid` with 16-thread, takes about ~215us

* without patching, w.r.t run syscall via `seccomp` `ptrace` stops takes about 13us
  which has an overhead of ~1.5x (over `seccomp`/`ptrace`)

the performance metric as of now (doing simplest syscall such as `getpid` or `time`) is:


 |name     |time      | slow down |
 |----------|----------|----------|
 |raw syscall | ~260ns |   1x     |
 | seccomp (no patch) | ~13us | 50x |
 | patch (with seccomp) | ~20us| 77x |
 | patch (16 pthreads) w contention  | ~212us| 825x |
