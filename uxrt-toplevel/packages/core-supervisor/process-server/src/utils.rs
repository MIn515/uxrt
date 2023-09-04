/*
 * Copyright (c) 2022-2023 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * Miscellaneous utility functions, structs, and traits
 */

use core::mem::size_of;
use custom_slab_allocator::CustomSlabAllocator;
use crate::global_heap_alloc::get_kobj_alloc;

///An allocator for global IDs (e.g. process and thread IDs)
pub trait GlobalIDAllocator {
	///Allocates an ID
	fn allocate_id(&self) -> Result<i32, ()>{
		let last_id = self.get_next_id();
		loop {
			let id = self.increment_id();
			if id < 0 {
				continue;
			}
			if !self.has_id(id){
				return Ok(id);
			}
			if id == last_id {
				return Err(());
			}
		}
	}
	///Returns true if `id` is allocated
	fn has_id(&self, id: i32) -> bool;
	///Get the next available ID to allocate
	fn get_next_id(&self) -> i32;
	///Increment the current ID
	fn increment_id(&self) -> i32;
}

///Adds a slab size for an Arc of the given type
///
///This is a macro since it uses a fixed array as a substitute, and it is not
///possible to use the size of a generic type as a constant to define/initialize
///an array (which would require generic statics)
#[macro_export]
macro_rules! add_arc_slab {
	($slab_type: ty, $slab_size: expr, $min_free:expr, $max_dealloc_slabs: expr, $max_drop_rounds: expr) => {
		{
		fn add_arc_slab() -> Result<(), ()>{
			use core::mem::size_of;
			use alloc::sync::Arc;
			use crate::global_heap_alloc::get_kobj_alloc;

			const BLOCK_SIZE: usize = size_of::<$slab_type>();
			let array: [u8; BLOCK_SIZE] = [0; BLOCK_SIZE];
			let kobj_alloc = get_kobj_alloc();
			if kobj_alloc.add_next_custom_slab($slab_size, $min_free, $max_dealloc_slabs, $max_drop_rounds).is_ok(){
				let arc = Arc::new(array);
				drop(arc);
				Ok(())
			}else{
				Err(())
			}
		}
		add_arc_slab()
		}
	}
}

///Adds a slab to the heap allocator
pub fn add_slab<T: Sized>(slab_size: usize, min_free: usize, max_dealloc_slabs: usize, max_drop_rounds: usize) -> Result<(), ()>{
	let kobj_alloc = get_kobj_alloc();
	kobj_alloc.add_custom_slab(size_of::<T>(), slab_size, min_free, max_dealloc_slabs, max_drop_rounds)
}

/* vim: set softtabstop=8 tabstop=8 noexpandtab:: */
