# sel4-thread-park

Provides support for parking and unparking threads, with the same semantics as std::thread::park() and std::thread::Thread::unpark(). This is separate from sel4-thread because including this there would create an `sel4_alloc->usync->sel4_thread->sel4_alloc` dependency cycle.

## Status

Basically complete, although it could maybe use more testing.
