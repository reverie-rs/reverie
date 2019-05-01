On ubuntu-18.04, i5-4670 (4-core):

`getpid()` takes about 4us
patched `getpid()` (including the syscall itself) takes about 90 - 100us
which has an overhead of ~25x
