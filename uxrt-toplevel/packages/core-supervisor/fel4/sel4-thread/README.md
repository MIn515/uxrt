# sel4-thread

A thread management library for [seL4](https://sel4.systems). Creation of local
threads running closures is supported (this requires sel4-alloc), and there is
also a generic thread struct that can be used with threads in other address
spaces (which can be used without a kernel object allocator).

## Status

Seems to work, but has only been tested with a few basic test cases.
