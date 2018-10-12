## copy/relocate trampoline to all 4GB regions in tracee's memory map

Right now we load `libpreload.so` by `LD_PRELOAD`, which will be loaded into similar addresses as `libc.so.6`, but it might not work
when there're `syscall` instructions beyond +/- 2GB where `libpreload.so` is loaded.

## get rid of `LD_PRELOAD`

Should load `libpreload.so` by ourself, instead of using `LD_PRELOAD`. one reason is stated in above section; others include `LD_PRELOAD`
does not work with static binaries, such as go executables.
