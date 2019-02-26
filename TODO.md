## get rid of `LD_PRELOAD`

Should load `libpreload.so` by ourself, instead of using `LD_PRELOAD`. one reason is stated in above section; others include `LD_PRELOAD`
does not work with static binaries, such as go executables.
