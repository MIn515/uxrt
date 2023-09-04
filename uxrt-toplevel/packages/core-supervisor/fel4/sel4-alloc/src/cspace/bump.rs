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

use core::ops;
use core::cell::{Cell, RefCell};

use sel4::{CNode, Window, CNodeInfo, SlotRef, seL4_CPtr, ToCap};

use crate::{
    AllocatorBundle,
    cspace::{
        BulkCSpaceManager,
        CSpaceError,
        CSpaceManager,
        CopyableCSpaceManager,
        MovableCSpaceManager,
        SingleLevelCSpaceManager,
    },
    cspace_debug_println,
};


/// A "bump allocator" for slots in a window of a `CNode`.
///
/// This records the maximum slot index allocated so far. If a slot is requested, and the `CNode` is
/// not yet full, the index is incremented. It is possible to free only the most recently requested
/// slot or group of slots.
#[derive(Debug)]
pub struct BumpAllocator {
    /// The portion of CSpace and the `CNode` which slots are allocated from.
    window: RefCell<Window>,
    info: RefCell<CNodeInfo>,
    /// The watermark number of slots allocated so far.
    watermark: Cell<usize>,
    /// The root CNode of the thread associated with this allocator
    parent_root: CNode,
}

/// Slots allocated in bulk from this allocator.
pub struct BumpToken {
    slots: Window,
    watermark: usize,
}

impl ops::Deref for BumpToken {
    type Target = Window;

    fn deref(&self) -> &Window {
        &self.slots
    }
}

impl BumpAllocator {
    /// Create a new `BumpAllocator` for `window` encoded with `info`.
    pub fn new(window: Window, info: CNodeInfo, parent_root: CNode) -> BumpAllocator {
        BumpAllocator {
            window: RefCell::new(window),
            info: RefCell::new(info),
            watermark: Cell::new(0),
            parent_root,
        }
    }
}

impl SingleLevelCSpaceManager for BumpAllocator {
    fn allocate_idx<A: AllocatorBundle>(&self, _: &A) -> Result<usize, ()> {
        if self.slots_remaining() > 0 {
            let index = self.watermark.get();
            self.watermark.set(index + 1);
            Ok(index)
        } else {
            Err(())
        }
    }
    fn free_idx<A: AllocatorBundle>(&self, idx: usize, _: &A) -> Result<(), ()> {
        if idx + 1 == self.watermark.get() {
            self.watermark.set(self.watermark.get() - 1);
            Ok(())
        } else {
            Err(())
        }
    }
}


impl CSpaceManager for BumpAllocator {
    fn allocate_slot_raw<A: AllocatorBundle>(&self, alloc: &A) -> Result<seL4_CPtr, CSpaceError> {
        cspace_debug_println!("BumpAllocator::allocate_slot_raw");
        self.allocate_slot_raw_single_level(alloc)
    }

    fn allocate_slot<A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError> {
        cspace_debug_println!("BumpAllocator::allocate_slot");
        self.allocate_slot_single_level(alloc)
    }

    fn free_slot_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError> {
        cspace_debug_println!("BumpAllocator::free_slot_raw");
        self.free_slot_raw_single_level(cptr, alloc)
    }

    fn slot_info_raw(&self, cptr: seL4_CPtr) -> Option<CNodeInfo> {
        self.slot_info_raw_single_level(cptr)
    }

    fn slot_window_raw(&self, cptr: seL4_CPtr) -> Option<Window> {
        cspace_debug_println!("BumpAllocator::slot_window_raw");
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
        let slots = self.window.borrow().num_slots - self.watermark.get();
        cspace_debug_println!("BumpAllocator::slots_remaining: {:p} {}", self, slots);
        slots
    }
    fn num_slots(&self) -> usize {
        self.window.borrow().num_slots
    }
}

impl BulkCSpaceManager for BumpAllocator {
    type Token = BumpToken;

    fn allocate_slots<A: AllocatorBundle>(&self, count: usize, _: &A) -> Result<BumpToken, ()> {
        if count <= self.slots_remaining() {
            let mut new = *self.window.borrow_mut();
            new.first_slot_idx += self.watermark.get();
            new.num_slots = count;
            self.watermark.set(self.watermark.get() + count);
            Ok(BumpToken {
                slots: new,
                watermark: self.watermark.get(),
            })
        } else {
            Err(())
        }
    }

    fn free_slots<A: AllocatorBundle>(&self, token: BumpToken, _: &A) -> Result<(), ()> {
        if token.slots.cnode == self.window.borrow().cnode && token.watermark == self.watermark.get() {
            self.watermark.set(
                self.watermark.get() - token.slots.num_slots,
            );
            Ok(())
        } else {
            Err(())
        }
    }

    fn slots_info(&self, _: &Self::Token) -> Option<CNodeInfo> {
        Some(self.info.borrow().clone())
    }
}

impl CopyableCSpaceManager for BumpAllocator {
}

impl MovableCSpaceManager for BumpAllocator {
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

impl Drop for BumpAllocator {
    fn drop(&mut self) {
        let window = self.window().unwrap();
        if self.slots_remaining() != window.num_slots {
            panic!("attempted to drop BumpAllocator for cptr {:x} root {:x} dpth {} with {} slots remaining out of {}", window.cnode.cptr, window.cnode.root.to_cap(), window.cnode.depth, self.slots_remaining(), window.num_slots);
        }
    }
}
