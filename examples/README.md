
# examples/

Example instrumentation tools built on top of systrace.

Copying one of these examples is the recommended way to get started
using systrace.

 * echotool (Rust) - echo each intercepted event, similar to `strace`.


## TODO / Coming Soon

 * counttool (Rust) - count the intercepted events and print a summary
   on exit.

 * echotool_c (C) - like echotool, but implemented in C rather than
   Rust.  An example of how to build an instrumentation tool without
   Rust.
