/*
 * Copyright (c) 2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This is a UTSpace allocator that tries to swap out pages when memory is low
 */

use sel4::{
	CNodeInfo,
	SlotRef,
	Window,
};

use sel4_alloc::{
	AllocatorBundle,
	utspace::{
	UTSpaceError,
	UTSpaceManager,
	UtSlabAllocator,
	UtZone,
	}
};

///UTSpace manager that swaps when necessary; currently this just passes 
///everything to the underlying buddy allocator as-is.
#[derive(Debug)]
pub struct SwappingUtAllocator {
	slab_alloc: UtSlabAllocator,
}

impl SwappingUtAllocator {
	pub fn new(slab_alloc: UtSlabAllocator) -> Result<SwappingUtAllocator, ()> {
	Ok(SwappingUtAllocator {
		slab_alloc,
	})
	}
}

impl UTSpaceManager for SwappingUtAllocator {
	fn init_slabs<A: AllocatorBundle>(&self, slab_size_overrides: &[(u32, u32)], alloc: &A) {
	self.slab_alloc.init_slabs(slab_size_overrides, alloc)
	}
	fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
		&self,
		alloc: &A,
		dest: Window,
		dest_info: CNodeInfo,
		size_bits: usize,
		zone: UtZone,
	) -> Result<(), (usize, UTSpaceError)> {
	self.slab_alloc.allocate::<T, A>(alloc, dest, dest_info, size_bits, zone)
	}
	fn allocate_raw<A: AllocatorBundle>(
		&self,
		alloc: &A,
		dest: Window,
		dest_info: CNodeInfo,
		size_bits: usize,
		objtype: usize,
		zone: UtZone,
	) -> Result<(), (usize, UTSpaceError)> {
	self.slab_alloc.allocate_raw(alloc, dest, dest_info, size_bits, objtype, zone)
	}
	fn deallocate_raw<A: AllocatorBundle>(&self,
		alloc: &A,
		window: Window,
		info: CNodeInfo,
		objtype: usize,
		size_bits: usize,
	) -> Result<(), UTSpaceError> {
	self.slab_alloc.deallocate_raw(alloc, window, info, objtype, size_bits)
	}

	fn slot_to_paddr(&self, cnode: SlotRef, slot_idx: usize) -> Result<usize, ()> {
	self.slab_alloc.slot_to_paddr(cnode, slot_idx)
	}

	fn minimum_slots(&self) -> usize {
		0
	}

	fn minimum_untyped(&self) -> usize {
		0
	}

	fn minimum_vspace(&self) -> usize {
		0
	}
}
/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
