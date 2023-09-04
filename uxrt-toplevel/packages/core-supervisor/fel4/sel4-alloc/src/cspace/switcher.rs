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

use sel4::{CNode, CNodeInfo, Error, ErrorDetails, SlotRef, ToCap, Window, seL4_CPtr, cptr_shl, seL4_Word};

use crate::{
    AllocatorBundle,
    cspace::{
        BitmapAllocator,
        CSpaceManager,
        CSpaceError,
        CopyableCSpaceManager,
        DynamicBitmapAllocator,
        MovableCSpaceManager,
    },
    cspace_debug_println,
    utspace::UtZone,
};

///An allocator that switches between two inner allocators (allocating from
///the first until it is filled and then switching over to the second), for
///use in bootstrapping. Also locks and unlocks the allocator bundle passed to
///it.
///
///This is required because creating a multi-node CSpace requires UTSpace
///allocation, which already requires a working CSpace allocator. This allows
///the UTSpace allocator to use a dynamic CSpace allocator while still being
///able to free CPtrs from the initial allocator.
///
///The first inner allocator is normally the initial one. Once a dynamic
///allocator has been initialized, it can be added with add_second().
#[derive(Debug)]
pub struct SwitchingAllocator {
    first: BitmapAllocator,
    second: Option<DynamicBitmapAllocator>,
}

//TODO?: support wrapping any allocator implementing CSpaceManager and managing
//a single window (which would require checking the return of the window()
//method)
impl SwitchingAllocator {
    /// Create a new `SwitchingAllocator.
    ///
    pub fn new(first: BitmapAllocator) -> SwitchingAllocator {
        SwitchingAllocator { first,
            second: None
        }
    }
    pub fn add_second(&mut self, second: DynamicBitmapAllocator) -> Result<(), ()>{
        if second.parent_root().unwrap().to_cap() !=
                self.first.parent_root().unwrap().to_cap() ||
                !second.is_implicitly_addressable() {
            Err(())
        }else{
            self.second = Some(second);
            Ok(())
        }
    }
    pub fn is_first(&self, slot: SlotRef) -> bool{
        cspace_debug_println!("SwitchingAllocator::is_first: {:x} {:x} {}", slot.root.to_cap(), slot.cptr, slot.depth);
        self.is_first_raw(cptr_shl(slot.cptr, slot.depth))
    }
    pub fn is_first_raw(&self, cptr: seL4_CPtr) -> bool{
        //unwrap will never panic here because the sub-allocator is guaranteed
        //to manage a contiguous window
        let first_window = self.first.window().unwrap();
        let first_info = self.first.info().unwrap();
        let decoded = first_info.decode(cptr);
        let first_start_cptr = first_window.cptr_to(&first_info, 0);
        if first_start_cptr.is_none(){
            false
        }else{
            let first_start_decoded = first_info.decode(first_start_cptr.unwrap());
            cspace_debug_println!("SwitchingAllocator::is_first_raw: {:x} {:x} {:x} {:x} {:x} {:x}", decoded.prefix, decoded.guard, decoded.leftover, decoded.radix, first_window.first_slot_idx, first_window.first_slot_idx + first_window.num_slots);

            decoded.radix >= first_window.first_slot_idx &&
                decoded.radix < first_window.first_slot_idx + first_window.num_slots &&
                decoded.prefix == first_start_decoded.prefix &&
                decoded.guard == first_start_decoded.guard &&
                decoded.leftover == first_start_decoded.leftover
        }
    }
}

impl CSpaceManager for SwitchingAllocator {
    fn allocate_slot_raw<A: AllocatorBundle>(&self, alloc: &A) -> Result<seL4_CPtr, CSpaceError> {
        if alloc.lock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot_raw: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        let ret = if self.first.slots_remaining() > 0 {
            self.first.allocate_slot_raw(alloc)
        }else{
            if let Some(second) = &self.second {
                second.allocate_slot_raw(alloc)
            }else{
                Err(CSpaceError::InternalError)
            }
        };
        if alloc.unlock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot_raw: unlocking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        ret
    }

    fn allocate_slot<A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError> {
        if alloc.lock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        let ret = if self.first.slots_remaining() > 0 {
            self.first.allocate_slot(alloc)
        }else{
            if let Some(second) = &self.second {
                second.allocate_slot(alloc)
            }else{
                Err(CSpaceError::InternalError)
            }
        };
        if alloc.unlock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot: unlocking allocators failed");
            return Err(CSpaceError::InternalError)
        }
        ret
    }

    fn free_slot_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError> {
        if alloc.lock_dealloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::free_slot_raw: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        cspace_debug_println!("SwitchingAllocator::free_slot_raw: {:x}", cptr);
        let ret = if self.is_first_raw(cptr){
            cspace_debug_println!("cptr from first allocator");
            self.first.free_slot_raw(cptr, alloc)
        }else{
            cspace_debug_println!("cptr not from first allocator");
            if let Some(second) = &self.second {
                second.free_slot_raw(cptr, alloc)
            }else{
                Err(CSpaceError::InternalError)
            }
        };
        if alloc.unlock_dealloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::free_slot_raw: unlocking allocators failed");
            return Err(CSpaceError::InternalError)
        }
        ret
    }

    fn slot_info_raw(&self, cptr: seL4_CPtr) -> Option<CNodeInfo> {
        cspace_debug_println!("SwitchingAllocator::slot_info_raw: {:x}", cptr);
        if self.is_first_raw(cptr){
            cspace_debug_println!("cptr from first allocator");
            self.first.slot_info_raw(cptr)
        }else{
            cspace_debug_println!("cptr not from first allocator");
            if let Some(second) = &self.second {
                second.slot_info_raw(cptr)
            }else{
                None
            }
        }
    }

    fn parent_root(&self) -> Option<CNode> {
        self.first.parent_root()
    }

    /// The window managed by this allocator.
    fn window(&self) -> Option<Window> {
        if self.second.is_some() {
            None
        }else{
            self.first.window()
        }
    }

    /// The CNodeInfo for this allocator.
    fn info(&self) -> Option<CNodeInfo> {
        if self.second.is_some() {
            None
        }else{
            self.first.info()
        }
    }
    fn num_slots(&self) -> usize {
        let mut slots = self.first.num_slots();
        if let Some(second) = &self.second {
            slots += second.num_slots();
        }
        slots
    }
    fn slots_remaining(&self) -> usize {
        let mut slots = self.first.slots_remaining();
        if let Some(second) = &self.second {
            slots += second.slots_remaining();
        }
        slots
    }

    fn cptr_to_slot(&self, cptr: seL4_CPtr) -> Result<SlotRef, ()> {
        cspace_debug_println!("SwitchingAllocator::cptr_to_slot: {:x}", cptr);
        if self.is_first_raw(cptr){
            cspace_debug_println!("cptr from first allocator");
            self.first.cptr_to_slot(cptr)
        }else{
            cspace_debug_println!("cptr not from first allocator");
            if let Some(second) = &self.second {
                second.cptr_to_slot(cptr)
            }else{
                Err(())
            }
        }
    }

    fn slot_window_raw(&self, cptr: seL4_CPtr) -> Option<Window>{
        cspace_debug_println!("SwitchingAllocator::slot_window_raw: {:x}", cptr);
        if self.is_first_raw(cptr){
            cspace_debug_println!("cptr from first allocator");
            self.first.slot_window_raw(cptr)
        }else{
            cspace_debug_println!("cptr not from first allocator");
            if let Some(second) = &self.second {
                second.slot_window_raw(cptr)
            }else{
                None
            }
        }
    }

    fn slot_window_utspace(&self, slot: SlotRef) -> Result<Window, CSpaceError> {
        cspace_debug_println!("SwitchingAllocator::slot_window_utspace: {:x} {:x} {}", slot.root.to_cap(), slot.cptr, slot.depth);
        if self.is_first(slot){
            cspace_debug_println!("slot from first allocator");
            self.first.slot_window_utspace(slot)
        }else{
            cspace_debug_println!("slot not from first allocator");
            if let Some(second) = &self.second {
                second.slot_window_utspace(slot)
            }else{
                Err(CSpaceError::InternalError)
            }
        }
    }

    fn allocate_slot_with_object<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, size_bits: usize, zone: UtZone, alloc: &A) -> Result<T, CSpaceError>{
        if alloc.lock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot_with_object: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        let ret = if self.first.slots_remaining() > 0 {
            self.first.allocate_slot_with_object(size_bits, zone, alloc)
        }else{
            if let Some(second) = &self.second {
                second.allocate_slot_with_object(size_bits, zone, alloc)
            }else{
                Err(CSpaceError::CSpaceExhausted)
            }
        };
        let _ = alloc.unlock_alloc();
        ret
    }

    fn allocate_slot_with_object_ref<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, size_bits: usize, zone: UtZone, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if alloc.lock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot_with_object_ref: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        let ret = if self.first.slots_remaining() > 0 {
            self.first.allocate_slot_with_object_ref::<T, _>(size_bits, zone, alloc)
        }else{
            if let Some(second) = &self.second {
                second.allocate_slot_with_object_ref::<T, _>(size_bits, zone, alloc)
            }else{
                Err(CSpaceError::CSpaceExhausted)
            }
        };
        let _ = alloc.unlock_alloc();
        ret
    }

    fn allocate_slot_with_object_raw<A: AllocatorBundle>(&self, size_bits: usize, objtype: usize, zone: UtZone, alloc: &A) -> Result<seL4_CPtr, CSpaceError>{
        if alloc.lock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot_with_object_raw: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }


        let ret = if self.first.slots_remaining() > 0 {
            self.first.allocate_slot_with_object_raw(size_bits, objtype, zone, alloc)
        }else{
            if let Some(second) = &self.second {
                second.allocate_slot_with_object_raw(size_bits, objtype, zone, alloc)
            }else{
                Err(CSpaceError::CSpaceExhausted)
            }
        };
        let _ = alloc.unlock_alloc();
        ret
    }

    fn allocate_slot_with_object_raw_ref<A: AllocatorBundle>(&self, size_bits: usize, objtype: usize, zone: UtZone, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if alloc.lock_alloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::allocate_slot_with_object_raw_ref: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        let ret = if self.first.slots_remaining() > 0{
            self.first.allocate_slot_with_object_raw_ref(size_bits, objtype, zone, alloc)
        }else{
            if let Some(second) = &self.second {
                second.allocate_slot_with_object_raw_ref(size_bits, objtype, zone, alloc)
            }else{
                Err(CSpaceError::CSpaceExhausted)
            }
        };
        let _ = alloc.unlock_alloc();
        ret
    }

    fn free_and_delete_slot_with_object_ref<T: sel4::Allocatable + sel4::ToCap, A: AllocatorBundle>(&self, slot: SlotRef, size_bits: usize, alloc: &A) -> Result<(), CSpaceError>{
        if alloc.lock_dealloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::free_and_delete_slot_with_object_ref: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }

        cspace_debug_println!("SwitchingAllocator::free_and_delete_slot_with_object_ref: {:x} {:x} {}", slot.root.to_cap(), slot.cptr, slot.depth);
        let ret = if self.is_first(slot){
            cspace_debug_println!("slot from first allocator");

            self.first.free_and_delete_slot_with_object_ref::<T, _>(slot, size_bits, alloc)
        }else{
            cspace_debug_println!("slot not from first allocator");
            if let Some(second) = &self.second {
                second.free_and_delete_slot_with_object_ref::<T, _>(slot, size_bits, alloc)
            }else{
                Err(CSpaceError::InternalError)
            }
        };
        let _ = alloc.unlock_dealloc();
        ret
    }

    fn free_and_delete_slot_with_object_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, objtype: usize, size_bits: usize, alloc: &A) -> Result<(), CSpaceError>{
        if alloc.lock_dealloc().is_err(){
            cspace_debug_println!("SwitchingAllocator::free_and_delete_slot_with_object_raw: locking allocators failed");
            return Err(CSpaceError::InternalError)
        }


        cspace_debug_println!("SwitchingAllocator::free_and_delete_slot_with_object_raw: {:x}", cptr);
        let ret = if self.is_first_raw(cptr){
            cspace_debug_println!("cptr from first allocator");
            self.first.free_and_delete_slot_with_object_raw(cptr, objtype, size_bits, alloc)
        }else{
            cspace_debug_println!("cptr not from first allocator");
            if let Some(second) = &self.second {
                second.free_and_delete_slot_with_object_raw(cptr, objtype, size_bits, alloc)
            }else{
                Err(CSpaceError::InternalError)
            }
        };
        let _ = alloc.unlock_dealloc();
        ret
    }

    fn lock_alloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        let mut res = self.first.lock_alloc(alloc);
        if res.is_ok() && self.second.is_some() {
            res = self.second.as_ref().unwrap().lock_alloc(alloc);
        }
        res
    }

    fn unlock_alloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        let mut res = self.first.unlock_alloc(alloc);
        if res.is_ok() && self.second.is_some() {
            res = self.second.as_ref().unwrap().unlock_alloc(alloc);
        }
        res
    }

    fn lock_dealloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        let mut res = self.first.lock_dealloc(alloc);
        if res.is_ok() && self.second.is_some() {
            res = self.second.as_ref().unwrap().lock_dealloc(alloc);
        }
        res
    }

    fn unlock_dealloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        let mut res = self.first.unlock_alloc(alloc);
        if res.is_ok() && self.second.is_some() {
            res = self.second.as_ref().unwrap().unlock_alloc(alloc);
        }
        res
    }

    fn delete_hook<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError> {
        Err(CSpaceError::InternalError)
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

}
impl CopyableCSpaceManager for SwitchingAllocator {
    fn copy(&self, dest: SlotRef, rights: sel4::CapRights) -> Result<(), sel4::Error> {
        if self.second.is_some() {
            Err(Error::from_details(ErrorDetails::InvalidCapability {
                which: 0
            }))
        }else{
            self.first.copy(dest, rights)
        }
    }
    fn copy_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, alloc: &A) -> Result<SlotRef, CSpaceError> {
        if self.second.is_some() {
            Err(CSpaceError::InvalidArgument)
        }else{
            self.first.copy_to_new(dest, rights, alloc)
        }
    }
    fn mint(&self, dest: SlotRef, rights: sel4::CapRights, guard_val: seL4_Word, guard_bits: u8) -> Result<(), sel4::Error>{
        if self.second.is_some() {
            Err(Error::from_details(ErrorDetails::InvalidArgument {
                which: 0
            }))
        }else{
            self.first.mint(dest, rights, guard_val, guard_bits)
        }
    }
    fn mint_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, guard_val: seL4_Word, guard_bits: u8, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if self.second.is_some() {
            Err(CSpaceError::InvalidArgument)
        }else{
            self.first.mint_to_new(dest, rights, guard_val, guard_bits, alloc)
        }
    }
}

impl MovableCSpaceManager for SwitchingAllocator {
    fn move_(&self, dest: SlotRef, is_root: bool) -> Result<(), CSpaceError>{
        if self.second.is_some(){
            Err(CSpaceError::InvalidArgument)
        }else{
            self.first.move_(dest, is_root)
        }
    }
    fn move_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, is_root: bool, alloc: &A) -> Result<(), CSpaceError>{
        if self.second.is_some() {
            Err(CSpaceError::InvalidArgument)
        }else{
            self.first.move_to_new(dest, is_root, alloc)
        }
    }
    fn mutate(&self, dest: SlotRef, is_root: bool, guard_val: seL4_Word, guard_bits: u8) -> Result<(), CSpaceError>{
        if self.second.is_some(){
            Err(CSpaceError::InvalidArgument)
        }else{
            self.first.mutate(dest, is_root, guard_val, guard_bits)
        }
    }
    fn mutate_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, is_root: bool, alloc: &A, guard_val: seL4_Word, guard_bits: u8) -> Result<(), CSpaceError>{
        if self.second.is_some(){
            Err(CSpaceError::InvalidArgument)
        }else{
            self.first.mutate_to_new(dest, is_root, alloc, guard_val, guard_bits)
        }
    }
    fn set_slot(&self, slot: SlotRef) -> Result<(), ()> {
        if self.second.is_some(){
            Err(())
        }else{
            self.first.set_slot(slot)
        }
    }
    fn set_info(&self, info: CNodeInfo) -> Result<(), ()> {
        if self.second.is_some(){
            Err(())
        }else{
            self.first.set_info(info)
        }
    }
    fn set_slot_and_info(&self, slot: SlotRef, info: CNodeInfo) -> Result<(), ()>{
        if self.second.is_some(){
            Err(())
        }else{
            self.first.set_slot_and_info(slot, info)
        }
    }
}
