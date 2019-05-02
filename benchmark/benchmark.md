On ubuntu-18.04, i5-4670 (4-core), using benchmark `getpid-many.c`:

* `getpid` syscall takes about 260ns

* patched `getpid` (including the syscall itself) takes about 80us
  which has an overhead of ~300x
  
* patched `getpid` with 16-thread, takes about ~1315us

* without patching, w.r.t run syscall via `seccomp` `ptrace` stops takes about 13us
  which has an overhead of ~6x (over `seccomp`/`ptrace`)

the performance metric as of now (doing simplest syscall such as `getpid` or `time`) is:


 |name     |time      | slow down |
 |----------|----------|----------|
 |raw syscall | ~260ns |   1x     |
 | seccomp (no patch) | ~13us | 50x |
 | patch (with seccomp) | ~80us| 300x |
 | patch (multi-threaded) | ~1315us| 5050x |
