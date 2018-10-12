## get rid of hard coded offsets from `libpreload.so`

This requires an ELF parser, which C lacks of. higher level languages such as haskell/rust have existing ELF parser.

## need a better way to known shared libraries are loaded

It is not a good idea to patch syscalls unless `libpreload.so` and/or `libc.so.6` are loaded. This could work by setting a
breakpoint at tracee's `main` function, but again this requires symbol lookup, hence depends on #1.

For `PIE` executable (default in ubuntu 18.04 while build with GCC), it is even harder.

## copy/relocate trampoline to all 4GB regions in tracee's memory map

Right now we load `libpreload.so` by `LD_PRELOAD`, which will be loaded into similar addresses as `libc.so.6`, but it might not work
when there're `syscall` instructions beyond +/- 2GB where `libpreload.so` is loaded.

## get rid of `LD_PRELOAD`

Should load `libpreload.so` by ourself, instead of using `LD_PRELOAD`. one reason is stated in above section; others include `LD_PRELOAD`
does not work with static binaries, such as go executables.
