// Copyright 2019-2021 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright 2016 Robigalia Project Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

const BITMAP_SIZE_BITS: u8 = 10;

use core::cell::{Cell, RefCell};
use custom_slab_allocator::CustomSlabAllocator;

use sel4::{CNode, Window, CNodeInfo, seL4_CPtr, SlotRef, ToCap};

use bitmap::Treemap;

use crate::{
    AllocatorBundle,
    cspace::{
        CSpaceError,
        CSpaceManager,
        CopyableCSpaceManager, 
        MovableCSpaceManager,
        SingleLevelCSpaceManager,
    },
    cspace_debug_println,
};

/// A "bitmap allocator" for slots in a window of a `CNode`.
///
/// This tracks precisely which slots have been allocated using a single bit per slot.
#[derive(Debug)]
pub struct BitmapAllocator {
    window: RefCell<Window>,
    info: RefCell<CNodeInfo>,
    bitmap: RefCell<Treemap>,
    remaining: Cell<usize>,
    parent_root: CNode,
}

impl BitmapAllocator {
    /// Create a new `BitmapAllocator` for `window` encoded with `info`.
    ///
    /// Can panic if allocation of the underlying bitmap panics. In the future, may return `None`
    /// in that case. Currently will never return `None`.
    pub fn new(window: Window, info: CNodeInfo, parent_root: CNode) -> Option<BitmapAllocator> {
        cspace_debug_println!("BitmapAllocator::new");
        cspace_debug_println!("window.cnode.root: {:x}", window.cnode.root.to_cap());
        cspace_debug_println!("window.cnode.cptr: {:x}", window.cnode.cptr);
        cspace_debug_println!("window.cnode.depth: {}", window.cnode.depth);
        cspace_debug_println!("window.first_slot_idx: {}", window.first_slot_idx);
        cspace_debug_println!("window.num_slots: {}", window.num_slots);
        cspace_debug_println!("info.guard_val: {:x}", info.guard_val);
        cspace_debug_println!("info.radix_bits: {}", info.radix_bits);
        cspace_debug_println!("info.guard_bits: {}", info.guard_bits);
        cspace_debug_println!("info.prefix_bits: {}", info.prefix_bits);
        cspace_debug_println!("parent_root: {:x}", parent_root.to_cap());

        if let Some(bitmap) = Treemap::new(window.num_slots, BITMAP_SIZE_BITS){
            Some(BitmapAllocator {
                window: RefCell::new(window),
                info: RefCell::new(info),
                bitmap: RefCell::new(bitmap),
                remaining: Cell::new(window.num_slots),
                parent_root,
            })
        }else{
            //this will never happen with the current Treemap version
            None
        }
    }
}

impl SingleLevelCSpaceManager for BitmapAllocator {
    fn allocate_idx<A: AllocatorBundle>(&self, _: &A) -> Result<usize, ()> {
        cspace_debug_println!("BitmapAllocator::allocate_idx: {:p}", self);
        cspace_debug_println!("window.cnode.root: {:x}", self.window.borrow().cnode.root.to_cap());
        cspace_debug_println!("window.cnode.cptr: {:x}", self.window.borrow().cnode.cptr);
        cspace_debug_println!("window.cnode.depth: {}", self.window.borrow().cnode.depth);
        cspace_debug_println!("window.first_slot_idx: {}", self.window.borrow().first_slot_idx);
        cspace_debug_println!("window.num_slots: {}", self.window.borrow().num_slots);
                                                                        
        cspace_debug_println!("info.guard_val: {}", self.info.borrow().guard_val);    
        cspace_debug_println!("info.radix_bits: {}", self.info.borrow().radix_bits);   
        cspace_debug_println!("info.guard_bits: {}", self.info.borrow().guard_bits);   
        cspace_debug_println!("info.prefix_bits: {}", self.info.borrow().prefix_bits);

        let mut bm = self.bitmap.borrow_mut();
        cspace_debug_println!("slot found: {}, remaining: {}", bm.first_set().is_some(), self.remaining.get());
        let idx = bm.first_set().ok_or(())?;

        bm.set(idx, 0);
        cspace_debug_println!("remaining: {} idx: {}", self.remaining.get(), idx);
        self.remaining.set(self.remaining.get() - 1);

        Ok(idx)
    }

    fn free_idx<A: AllocatorBundle>(&self, idx: usize, _: &A) -> Result<(), ()> {
        let mut bm = self.bitmap.borrow_mut();
        match bm.get(idx) {
            Some(1) => panic!("Double free of slot {:?} in {:?}", idx, self),
            Some(_) => (),
            None => panic!("Free of out-of-bounds slot {:?} in {:?}", idx, self),
        }

        bm.set(idx, 1);
        self.remaining.set(self.remaining.get() + 1);

        Ok(())
    }
}


impl CSpaceManager for BitmapAllocator {
    fn allocate_slot_raw<A: AllocatorBundle>(&self, alloc: &A) -> Result<seL4_CPtr, CSpaceError> {
        cspace_debug_println!("BitmapAllocator::allocate_slot_raw");
        self.allocate_slot_raw_single_level(alloc)
    }

    fn allocate_slot<A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError> {
        cspace_debug_println!("BitmapAllocator::allocate_slot");
        self.allocate_slot_single_level(alloc)
    }

    fn free_slot_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError> {
        cspace_debug_println!("BitmapAllocator::free_slot_raw");
        self.free_slot_raw_single_level(cptr, alloc)
    }

    fn slot_info_raw(&self, cptr: seL4_CPtr) -> Option<CNodeInfo> {
        self.slot_info_raw_single_level(cptr)
    }

    fn slot_window_raw(&self, cptr: seL4_CPtr) -> Option<Window> {
        cspace_debug_println!("BitmapAllocator::slot_window_raw");
        self.slot_window_raw_single_level(cptr)
    }

    // this manager uses a constant amount of resources.

    fn minimum_slots(&self) -> usize {
        0
    }

    fn minimum_untyped(&self) -> usize {
        0
    }

    fn minimum_vspace(&self) -> usize {
        0
    }
    fn parent_root(&self) -> Option<CNode> {
        Some(self.parent_root)
    }
    
    /// The window managed by this allocator.
    fn window(&self) -> Option<Window> {
        Some(self.window.borrow().clone())
    }
    
    /// The CNodeInfo for this allocator.
    fn info(&self) -> Option<CNodeInfo> {
        Some(self.info.borrow().clone())
    }
    fn slots_remaining(&self) -> usize {
        cspace_debug_println!("BitmapAllocator::slots_remaining: {:p} {}", self, self.remaining.get());
        self.remaining.get()
    }
    fn num_slots(&self) -> usize {
        self.window.borrow().num_slots
    }
}

impl CopyableCSpaceManager for BitmapAllocator {
}

impl MovableCSpaceManager for BitmapAllocator {
    fn set_slot(&self, slot: SlotRef) -> Result<(), ()> {
        let mut new_window = self.window().unwrap().clone();
        new_window.cnode = slot;
        self.window.replace(new_window);
        Ok(())
    }
    fn set_info(&self, info: CNodeInfo) -> Result<(), ()> {
        self.info.replace(info);
        Ok(())
    }
}

impl PartialEq for BitmapAllocator {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl Drop for BitmapAllocator {
    fn drop(&mut self) {
        let window = self.window().unwrap();
        if self.slots_remaining() != window.num_slots {
            panic!("attempted to drop BitmapAllocator for cptr {:x} root {:x} dpth {} with {} slots remaining out of {}", window.cnode.cptr, window.cnode.root.to_cap(), window.cnode.depth, self.slots_remaining(), window.num_slots);
        }
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    cspace_debug_println!("cspace::bitmap::add_custom_slabs");
    bitmap::add_custom_slabs(alloc)
}
