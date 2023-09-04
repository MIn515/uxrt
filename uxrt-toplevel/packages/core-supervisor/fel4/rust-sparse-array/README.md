# rust-sparse-array

This crate provides a sparse associative array with usize keys (based on a 
red-black tree of small fixed-size arrays) intended for use in allocators. It is
possible to hide items from the "regular" accessor methods. This allows an
allocator to track which items are free and used without having to use multiple 
arrays (which incurs extra allocations).

All mutability is internal using cells, so all methods take &self regardless of 
whether they mutate the array. Heap allocation occurs only while no mutable
borrows are active, so this is safe to use in heap allocators (as long as they
separate refilling/dropping from actually fulfilling allocations/deallocations).
`OuterMutableSparseArray` is a version of this with mutation methods that take 
&mut self.

Also provided (built on top of the associative array) is a generic struct for
building allocators that manage multiple sub-allocators, each of which manages a
sub-window of an address space. Sub-allocators are automatically allocated and
deallocated as required. Addresses are of type usize, and the only requirement
imposed on them is that each sub-window must have a unique address. Separation
of phases for allocation/deallocation within sub-windows and
allocation/deallocation of new subwindows is supported in order to limit
dependency cycles is supported.


