# sel4-alloc

You can use this crate to manage CSpace, VSpace, and untyped regions. An 
optional slab heap allocator implemented on top of the kernel object allocators 
is also provided.

Resource allocation on seL4 is entirely delegated to userspace. The kernel has
no internal dynamic memory at all, and relies on userspace to provide it
memory (in the form of untyped capabilities) where it can store objects.

There are two main resources that need management: capability slots and
untyped memory objects.  There is a delicate interplay between these - in
order to make more capability slots available, more `CNode`s may need to be
created, which needs untyped memory and some slots to store capabilities.

Implicit is the assumption that there is also some way to acquire blocks of
memory to store bookkeeping information for the allocators. These dependencies
are also fundamentally cyclic - if you need a slot, you may need to allocate a
new CNode, which may need more memory to store bitmaps or soforth, which in
turn may require a new untyped to be mapped, which might need some slots.

Thus, while the strategies for managing these resources can be distinct, the
managers themselves often need some amount of interaction. Some strategies are
defined by this crate.  Others may be created externally by implementing the
various `*Manager` traits. When aggregated together into a single `Allocator`,
the amount of resources that must be maintained for guaranteed availability
can be determined. It is the responsibility of the user to determine that at
least that many resources are available before making an allocation.

# Design

This library tries to not impose policy, but instead provide the mechanisms
for easily implementing policy.

## CSpace layout

There are two base CSpace allocators defined. One is a simple bump allocator
which supports free's only if a strict stack discipline is followed (that is,
every time you free a slot allocation, you free the most recently allocated
slot). The other uses a sparse bitmap to track used entries, and a combination 
of a red-black tree and a linear scan to find free slots.

There are two higher-level allocators implemented on top of the bitmap 
allocator. The first is a two-level dynamic bitmap allocator that uses a
top-level CNode from which second-level CNodes are automatically allocated and
deallocated as needed. The sizes of both the top-level CNode and the
second-level CNodes allocated from it are set when a dynamic CSpace allocator is
created. The second is a wrapper around both a regular single-level bitmap
allocator and a dynamic bitmap allocator, with only the regular bitmap allocator
being present when the wrapper is created. The dynamic bitmap allocator can be 
added at some point after initial allocator bootstrapping is finished. This is
intended to be used as the underlying CSpace allocator for the heap, since it
refills the dynamic bitmap allocator before trying to allocate anything in order
to prevent issues arising from dependency cycles.

## Untyped management

The lowest-level UTSpace allocator is `UtBucket`, which is a bump allocator that
mirrors the kernel's watermark bookkeeping. This is typically only used 
internally and not by client code.

On top of this is `Split`, which functions as a buddy allocator for RAM and a
simple free list allocator for device memory. Both sub-allocators use
sparse associative arrays based on red-black trees for tracking objects. RAM is
divided into multiple zones to support devices with restricted DMA address
ranges on systems without an IOMMU (which zones are supported depends on the
architecture). 

On top of `Split` is `UtSlabAllocator`, which manages kernel objects smaller
than a page using a collection of `UtBucket`s with each bucket dedicated to one
object type (there are multiple buckets for each type, allocated and deallocated
as needed. All allocations/deallocations for CNodes, untyped objects, and
objects that are page-sized or larger are passed through to the underlying
`Split` allocator. Objects are recycled as necessary, without retyping. This is
somewhat prone to fragmentation, in that a worst-case access pattern could cause
mostly-empty buckets except for one object, causing excessive resource
consumption. This is not a fundamental limitation of the kernel - an intelligent
userspace could make it possible to revoke objects and re-create the object
graph, with the objects living in new, more compact untyped memory objects. The
current implementation provides no mechanism for this.

## Memory management

The entire memory management scheme is ad-hoc right now. Eventually, it should
provide a flexible base for implementing things like demand paging and
efficient shared memory.

### Reservation Trees

The core of virtual address space management is the "reservation tree". At its
heart is a binary search tree (in particular, an intrusive red-black tree).
This is used to provide best-fit reservation: when a range of N bytes is
requested, the node to service the request from is selected such that its
available range of bytes M minimizes M-N, minimizing fragmentation. This node
is then split. The red-black tree guarantees logN worst-case operations.

Reservations in no way reflect the actual structure of the page table, they
just ensure that when requesting virtual memory only free memory is returned.

Adjacent blocks are eagerly coalesced on free and reservations can be shrunk,
or expanded if there is available space after it.

### Page table management

Page table management is provided as a hierarchical tree, mirroring the
hardware layout in spirit. It provides for large pages. It doesn't care about
where pages are mapped - it will lazily create paging structures as needed as
the address space fills. Currently, there is no facility for coalescing small
pages into large pages, although it can split large pages into small pages
where necessary due to changing mappings.

In the future, a paging daemon could be responsible for coalescing small
pages, freeing unused paging structures, and implementing demand paging
maintenance tasks. Right now, a small amount of bookkeeping is tracked that
would be useful for such a daemon to determine when cleanup should be
performed.

## Heap management

A global heap allocator based on the slab-allocator-core crate is provided. This
allocator provides a set of generic power-of-two slabs as well as custom slabs
for user-defined objects (custom slabs for all internal metadata objects are
automatically added when the allocators are fully initialized). The heap
automatically grows and shrinks as needed, with multiple slabs of each size that
are dynamically allocated and deallocated.

## Bootstrapping

The most challenging part of this entire setup is initialization of
bookkeeping structures for these allocators. There is a certain amount of
magic and handwaving involved - before these structures are set up, there is
no reasonable malloc. The current solution is to sidestep the problem and use
resources from a fixed-size pool (using the self-bootstrapping support in
slab-allocator-core along with a bitmap allocator managing the initial CNode) to
bring up these structures to satisfaction. The resources allocated during bootstrap are never freed.

After the allocators have been bootstrapped, dynamic allocation of heap slabs, 
untyped slabs, and CSpace sub-levels may be initialized. These are all
initialized separately for flexibility. The UX/RT process server provides an
example of how to fully initialize the allocators (specifically in
src/vm/mod.rs).

# Status

Functional, still needs polish and testing.
