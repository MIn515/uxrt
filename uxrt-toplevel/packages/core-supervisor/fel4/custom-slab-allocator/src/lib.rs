#![no_std]

pub trait CustomSlabAllocator {
    fn add_custom_slab(&self, block_size: usize, slab_size: usize, min_free: usize, dealloc_slots: usize, max_dealloc_rounds: usize) -> Result<(), ()>;
} 


