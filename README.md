**🚨 This project has been rewritten and is superseded by https://github.com/facebookexperimental/reverie. This version is archived and will remain for posterity. 🚨**

# Reverie

[![Build Status](https://dev.azure.com/iu-parfunc/reverie/_apis/build/status/iu-parfunc.reverie?branchName=master)](https://dev.azure.com/iu-parfunc/reverie/_build/latest?definitionId=2&branchName=master)

A library to intercept Linux syscalls (and select x86_64
instructions), and convert them into function calls.
The user of this library provides a shared library containing the
callbacks that are triggered on intercepted events.

See <TODO FINISHME> for Documentation.

## Build
We use rust nightly to build reveri and the tool libraries. To install, please follow instructions from: https://rustup.rs

After nightly rust and cargo are installed, reverie (and tool libraries) can be built by:

```
cargo build       # build `reverie` only
```

or

```
cargo build --all # build `reverie` and tool libraries
```

## Run


```
./target/debug/reverie --tool=target/debug/libecho.so --preloader=target/debug/libpreloader.so -- /path/to/X [X_command_arguments]
```

Tool log can be enabled by pass `TOOL_LOG=<level>` as environment variables (with `reverie`).

## Test
tests are under `tests` directory, you can run `make test` to run them.
