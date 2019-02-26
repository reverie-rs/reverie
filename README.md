# systrace

[![Build Status](https://dev.azure.com/iu-parfunc/systrace/_build/status/iu-parfunc.systrace?branchName=master)](https://dev.azure.com/iu-parfunc/systrace/_build/latest?definitionId=1&branchName=master)

A library to intercept Linux syscalls (and select x86_64
instructions), and convert them into function calls.
The user of this library provides a shared library containing the
callbacks that are triggered on intercepted events.

See <TODO FINISHME> for Documentation.

