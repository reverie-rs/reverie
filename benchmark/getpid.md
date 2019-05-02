On ubuntu-18.04, i5-4670 (4-core):

`getpid()` takes about 260ns
patched `getpid()` (including the syscall itself) takes about 80us
which has an overhead of ~300x

the performance metric as of now (doing simplest syscall such as `getpid` or `time`) is:

 +--------------------+
 |name     |time      |
 +--------------------+
 |raw syscall | ~260ns |
 +----------------------+
 | seccomp (no patch) | ~13us |
 +----------------------+
 | patch (with seccomp) | ~80us|
 +----------------------+
