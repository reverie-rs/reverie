# systrace

[![Build Status](https://dev.azure.com/iu-parfunc/systrace/_apis/build/status/iu-parfunc.systrace?branchName=master)](https://dev.azure.com/iu-parfunc/systrace/_build/latest?definitionId=1&branchName=master)

A library to intercept Linux syscalls (and select x86_64
instructions), and convert them into function calls.
The user of this library provides a shared library containing the
callbacks that are triggered on intercepted events.

See <TODO FINISHME> for Documentation.

## Build
We use rust nightly to build systrace and the tool libraries. To install, please follow instructions from: https://rustup.rs

After nightly rust and cargo are installed, systrace (and tool libraries) can be built by:

```
cargo build       # build `systrace` only
```

or

```
cargo build --all # build `systrace` and tool libraries
```

## Run

`systrace` needs both `libsystrace-trampoline.so` and a tool, such as `libecho.so`, to run command *X*, you can do it by:

```
systrace --library-path=/path/to/libsystrace-trampoline_so/ --tool=/path/to/libecho.so -- /path/to/X [X_command_arguments]
```

Tool log can be enabled by pass `TOOL_LOG=<level>` as environment variables (with `systrace`).

## Test
tests are under `tests` directory, you can run `make test` to run them.
