# slab-allocator-core

This crate provides a generic slab heap allocator. A target-specific wrapper is required to use it.

Dynamically growing and shrinking the heap, as well as slabs with custom block
sizes are supported.

## Usage

An example of a wrapper for this is provided in the heap module of the 
sel4-alloc crate.

## License
This crate is licensed under MIT. See LICENSE for details.
