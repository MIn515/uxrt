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

//! Capability allocation.
//!

mod bitmap;
mod bump;
mod dynamic_bitmap;
mod switcher;

#[macro_export]
macro_rules! cspace_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_cspace")]
        debug!($($toks)*);
    })
}

pub use self::bitmap::BitmapAllocator;
pub use self::bump::{BumpAllocator, BumpToken};
pub use self::dynamic_bitmap::DynamicBitmapAllocator;
pub use self::switcher::SwitchingAllocator;

use custom_slab_allocator::CustomSlabAllocator;
use core::ops::Deref;

use sel4::{
    WORD_BITS, FromCap, ToCap, seL4_CPtr, SlotRef, CNode, Window, CNodeInfo, Badge, 
    seL4_Word, cptr_shl, cptr_shr
};

use crate::{
    AllocatorBundle,
    utspace::{
        UTSpaceManager,
        UTSpaceError, 
        UtZone,
    },
};

#[derive(Clone, Copy, Debug, Fail)]
pub enum CSpaceError {
    #[fail(display = "CSpace slots exhausted")]
    CSpaceExhausted,
    #[fail(display = "failed to retype memory")]
    RetypeFailure { details: UTSpaceError },
    #[fail(display = "system call failure")]
    SyscallError { details: sel4::Error },
    #[fail(display = "failed to transfer capability")]
    SlotTransferError { details: Option<sel4::Error> },
    #[fail(display = "invalid argument")]
    InvalidArgument,
    #[fail(display = "internal error")]
    InternalError
}

///Internal helper function to get the internal SlotRef and CNodeInfo to create
///a sub-level CSpaceManager
fn cnode_slot_and_info(dest: SlotRef, size_bits: usize, is_root: bool, guard_val: seL4_Word, guard_bits: usize, parent_directly_addressable: bool) -> Result<(sel4::SlotRef, sel4::CNodeInfo), CSpaceError>{
    let mut root = dest.root.clone();
    let mut depth = size_bits + guard_bits + dest.depth as usize; 
    let mut prefix_bits = dest.depth;
    let mut cptr = dest.cptr;
    if is_root {
        if !parent_directly_addressable {
            cspace_debug_println!("parent of new root is not directly addressable");
            return Err(CSpaceError::InvalidArgument);
        }
        root = CNode::from_cap(cptr);
        depth = size_bits + guard_bits;
        prefix_bits = 0;
    }else if depth > WORD_BITS as usize {
        cspace_debug_println!("depth {} exceeds the size of a CPtr", depth);
        return Err(CSpaceError::InvalidArgument);
    }else{
        cptr = cptr_shl(cptr, prefix_bits);
    }
    let slot = SlotRef {
        root,
        cptr,
        depth: depth as u8,
    };
    let info = CNodeInfo {
        guard_val,
        radix_bits: size_bits as u8,
        guard_bits: guard_bits as u8,
        prefix_bits: prefix_bits as u8,
    };
    cspace_debug_println!("cnode_slot_and_info");
    cspace_debug_println!("slot: {:x} {:x} {}", slot.root.to_cap(), slot.cptr, slot.depth);
    cspace_debug_println!("info: {:x} {} {} {}", info.guard_val, info.radix_bits, info.guard_bits, info.prefix_bits);

    return Ok((slot, info));
}

/// Manager of individual slots in a `CSpace`. Allows creating sub-levels managed by their own allocators.
pub trait CSpaceManager {
    /// Allocate a single slot from this manager.
    fn allocate_slot<A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError>;
    /// Free a previously allocated slot.
    ///
    /// If the named slot has already been freed, or isn't managed by this manager, there may be
    /// unexpected consequences, such as a panic.
    fn free_slot<A: AllocatorBundle>(&self, slot: SlotRef, alloc: &A) -> Result<(), CSpaceError> {
        self.free_slot_raw(cptr_shl(slot.cptr, slot.depth), alloc)
    }

    /// Allocate a single slot from this manager, returning a raw CPtr.
    fn allocate_slot_raw<A: AllocatorBundle>(&self, alloc: &A) -> Result<seL4_CPtr, CSpaceError>;

    /// Free a previously allocated slot.
    ///
    /// If the named slot has already been freed, or isn't managed by this manager, there may be
    /// unexpected consequences, such as a panic.
    fn free_slot_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError>;

    /// Return a `CNodeInfo` which can be used to decode the given CPtr.
    ///
    /// Can return `None` if the CPtr is not managed by this manager, but is not required to do so.
    fn slot_info_raw(&self, cptr: seL4_CPtr) -> Option<CNodeInfo>;

    fn slot_info(&self, slot: SlotRef) -> Option<CNodeInfo>{
        self.slot_info_raw(cptr_shl(slot.cptr, slot.depth))
    }

    /// Get a window containing only the slot indicated by `cptr`.
    ///
    /// If the named slot has already been freed, or isn't managed by this manager, there may be
    /// unexpected consequences, such as a panic.
    fn slot_window_raw(&self, cptr: seL4_CPtr) -> Option<Window>;

    /// Get a window containing only the slot indicated by `slot`.
    ///
    /// If the named slot has already been freed, or isn't managed by this
    /// manager, there may be unexpected consequences, such as a panic.
    fn slot_window(&self, slot: SlotRef) -> Option<Window> {
        self.slot_window_raw(cptr_shl(slot.cptr, slot.depth))
    }

    ///Gets the entire window of this manager. 
    ///
    ///May return None for a manager that isn't associated with a single window
    fn window(&self) -> Option<Window>;

    ///Gets the CNodeInfo for this manager.
    ///
    ///May return None for a manager that isn't associated with a single window
    fn info(&self) -> Option<CNodeInfo>;

    ///Gets the number of slots still available for allocation.
    fn slots_remaining(&self) -> usize;

    ///Gets the total number of slots.
    fn num_slots(&self) -> usize;

    ///Gets the physical address of the object associated with a SlotRef from
    ///this manager.
    fn slot_to_paddr<A: AllocatorBundle>(&self, slot: SlotRef, alloc: &A) -> Result<usize, CSpaceError> {
        match self.slot_window_utspace(slot){
            Ok(window) => {
                if let Ok(paddr) = alloc.utspace().slot_to_paddr(window.cnode, window.first_slot_idx) {
                    Ok(paddr)
                }else{
                    Err(CSpaceError::InvalidArgument)
                }
            },
            Err(err) => { Err(err) },
        }
    }

    ///Gets the physical address of the object associated with a CPtr from 
    ///this manager.
    fn cptr_to_paddr<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<usize, CSpaceError> {
        if let Ok(slot) = self.cptr_to_slot(cptr) {
            self.slot_to_paddr(slot, alloc)
        }else{
            Err(CSpaceError::InvalidArgument)
        }
    }

    /// Get a window containing only the slot indicated by `slot` suitable for 
    /// allocation by a UTSpace manager.
    ///
    /// If the named slot has already been freed, or isn't managed by this
    /// manager, there may be unexpected consequences, such as a panic.
    fn slot_window_utspace(&self, slot: SlotRef) -> Result<Window, CSpaceError> {
        if let Some(mut window) = self.slot_window(slot){
            if self.is_root() {
                if self.is_implicitly_addressable(){
                    window.cnode.cptr = 0;
                    window.cnode.depth = 0;
                }else if window.cnode.depth == WORD_BITS as u8 {
                    window.cnode.root = CNode::from_cap(window.cnode.cptr);
                    window.cnode.cptr = 0;
                    window.cnode.depth = 0;
                }else{
                    //allocation into root CNodes is done by using their CPtr as
                    //the root argument and both the depth and destination set
                    //to 0, meaning it is not possible to allocate into a root
                    //CNode that is not at full-word depth

                    cspace_debug_println!("attempting to allocate or deallocate from an invalid root CNode");
                    return Err(CSpaceError::InvalidArgument);
                }
            }
            Ok(window)
        }else{
            Err(CSpaceError::InternalError)
        }
    }

    /// Returns the slot of the underlying CNode associated with this 
    /// allocator, guaranteed to be usable for copying/moving even for CNodes 
    /// that aren't implicitly addressable (unlike the slot of the window). Moving
    /// an allocator's CNode with a slot from this method may break it (the 
    /// move_()/mutate() methods of this trait will both move the CNode and
    /// update the window/info to match).
    ///
    /// Returns None for an allocator that doesn't have a single root CNode 
    /// associated with it.
    fn to_slot(&self) -> Option<SlotRef> {
        if self.window().is_none(){
            return None;
        }
        let window_slot = self.window().unwrap().cnode;
        let slot = if self.is_root() {
            let root = self.parent_root().unwrap();
            let cptr = if self.is_implicitly_addressable(){
                root.to_cap()
            }else{
                window_slot.cptr
            };
            cspace_debug_println!("to_slot: root");
            SlotRef::new(self.parent_root().unwrap(), cptr, WORD_BITS as u8)
        }else{
            cspace_debug_println!("to_slot: non-root");
            window_slot
        };
        cspace_debug_println!("root: {:x}, cptr: {:x}, depth {}", slot.root.to_cap(), slot.cptr, slot.depth);
        Some(slot)
    }

    fn to_cnode(&self) -> Option<CNode> {
        if let Some(slot) = self.to_slot(){
            Some(CNode::from_cap(slot.to_cap()))
        }else{
            None
        }
    }

    /// Returns a SlotRef for a CPtr from this manager
    ///
    /// If the CPtr was from a different manager the SlotRef will probably not work properly.
    fn cptr_to_slot(&self, cptr: seL4_CPtr) -> Result<SlotRef, ()> {
        if self.window().is_none() || self.info().is_none() {
            return Err(());
        }
        let window = self.window().unwrap();
        let info = self.info().unwrap();
        let decoded = self.info().unwrap().decode(cptr);

        if decoded.radix < window.first_slot_idx {
            return Err(());
        }

        Ok(window.slotref_to(&info, decoded.radix - window.first_slot_idx).unwrap())
    }

    /// Returns a SlotRef for a ToCap-implementing object from this manager
    ///
    /// If the object was from a different manager the SlotRef will probably not work properly.
    fn obj_to_slot<T: ToCap>(&self, obj: &T) -> Result<SlotRef, ()> {
        self.cptr_to_slot(obj.to_cap())
    }

    /// Allocate a single slot from this manager and allocate an object into the slot, returning a wrapper object of the specified type
    fn allocate_slot_with_object<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, size_bits: usize, zone: UtZone, alloc: &A) -> Result<T, CSpaceError>{
        cspace_debug_println!("allocate_slot_with_object: {} {}", T::object_type(), size_bits);
        if !self.is_implicitly_addressable(){
            cspace_debug_println!("CNode not implicitly addressable");
            return Err(CSpaceError::InvalidArgument);
        }
        match self.allocate_slot_with_object_ref::<T, A>(size_bits, zone, alloc){
            Ok(slot) => {
                let cptr = cptr_shl(slot.cptr, slot.depth);
                cspace_debug_println!("allocate_slot_with_object {:x} {:x} {}", cptr, slot.cptr, WORD_BITS as u32 - slot.depth as u32);
                Ok(T::from_cap(cptr))
            },
            Err(err) => Err(err),
        }
    }
    /// Allocate a single slot from this manager and allocate an object from 
    /// RAM into it, returning a wrapper object
    fn allocate_slot_with_object_ram<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, size_bits: usize, alloc: &A) -> Result<T, CSpaceError>{
        self.allocate_slot_with_object::<T, A>(size_bits, UtZone::RamAny, alloc)
    }
    /// Allocate a single slot from this manager and allocate an object of 
    /// fixed size (i.e. any object for which 0 is a valid size) from RAM into
    /// it, returning a wrapper object
    fn allocate_slot_with_object_fixed<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, alloc: &A) -> Result<T, CSpaceError>{
        self.allocate_slot_with_object::<T, A>(0, UtZone::RamAny, alloc)
    }
    /// Allocate a single slot from this manager and allocate an object into the slot, returning a SlotRef
    fn allocate_slot_with_object_ref<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, size_bits: usize, zone: UtZone, alloc: &A) -> Result<SlotRef, CSpaceError>{
        cspace_debug_println!("allocate_slot_with_object_ref: {} {}", T::object_type(), size_bits);
        if let Ok(slot) = self.allocate_slot(alloc) {
            match self.slot_window_utspace(slot) {
                Ok(window) => {
                    cspace_debug_println!("allocate_slot_with_object_ref");
                    cspace_debug_println!("slot.root: {:x}", slot.root.to_cap());
                    cspace_debug_println!("slot.cptr: {:x}", slot.cptr);
                    cspace_debug_println!("slot.depth: {}", slot.depth);
                    cspace_debug_println!("window.cnode.depth: {}", window.cnode.depth);
                    cspace_debug_println!("window.cnode.cptr: {:x}", window.cnode.cptr);
                    cspace_debug_println!("window.cnode.root: {:x}", window.cnode.root.to_cap());
                    cspace_debug_println!("window.num_slots: {}", window.num_slots);
                    cspace_debug_println!("window.first_slot_idx: {}", window.first_slot_idx);
                    if let Err(err) = alloc.utspace().allocate::<T, A>(alloc, window, self.slot_info(slot).unwrap(), size_bits, zone) {
                        return Err(CSpaceError::RetypeFailure { details: err.1 })
                    }
                    Ok(slot)
                },
                Err(err) => Err(err),
            }
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }

    /// Allocate a single slot from this manager and allocate an object from 
    /// RAM into it, returning a SlotRef
    fn allocate_slot_with_object_ref_ram<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, size_bits: usize, alloc: &A) -> Result<SlotRef, CSpaceError>{

        self.allocate_slot_with_object_ref::<T, A>(size_bits, UtZone::RamAny, alloc)
    }
    /// Allocate a single slot from this manager and allocate an object of 
    /// fixed size (i.e. any object for which 0 is a valid size) from RAM into
    /// it, returning a SlotRef
    fn allocate_slot_with_object_ref_fixed<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError>{

        self.allocate_slot_with_object_ref::<T, A>(0, UtZone::RamAny, alloc)
    }

    /// Allocate a single slot from this manager of the given type (specified as a raw type code) and allocate an object into the slot, returning a raw CPtr
    fn allocate_slot_with_object_raw<A: AllocatorBundle>(&self, size_bits: usize, objtype: usize, zone: UtZone, alloc: &A) -> Result<seL4_CPtr, CSpaceError>{
        cspace_debug_println!("allocate_slot_with_object_raw: {} {}", objtype, size_bits);
        if !self.is_implicitly_addressable(){
            cspace_debug_println!("CNode not directly addressable");
            return Err(CSpaceError::InvalidArgument);
        }
        match self.allocate_slot_with_object_raw_ref(size_bits, objtype, zone, alloc){
            Ok(slot) => {
                let cptr = cptr_shl(slot.cptr, slot.depth);
                cspace_debug_println!("allocate_slot_with_object_raw {:x} {:x} {}", cptr, slot.cptr, WORD_BITS as u32 - slot.depth as u32);
                Ok(cptr)
            },
            Err(err) => Err(err),
        }
    }
    /// Allocate a single slot from this manager and allocate an object of 
    /// fixed size (i.e. any object for which 0 is a valid size) from RAM into
    /// it, returning a raw CPtr
    fn allocate_slot_with_object_raw_fixed<A: AllocatorBundle>(&self, objtype: usize, alloc: &A) -> Result<seL4_CPtr, CSpaceError>{
        self.allocate_slot_with_object_raw(0, objtype, UtZone::RamAny, alloc)
    }
    /// Allocate a single slot from this manager of the given type (specified as a raw type code) and allocate an object into the slot, returning a SlotRef
    fn allocate_slot_with_object_raw_ref<A: AllocatorBundle>(&self, size_bits: usize, objtype: usize, zone: UtZone, alloc: &A) -> Result<SlotRef, CSpaceError>{
        cspace_debug_println!("allocate_slot_with_object_raw_ref: {} {}", objtype, size_bits);
        if let Ok(slot) = self.allocate_slot(alloc) {
            match self.slot_window_utspace(slot) {
                Ok(window) => {
                    let info = self.slot_info(slot).unwrap();
                    cspace_debug_println!("allocate_slot_with_object_raw_ref");
                    cspace_debug_println!("slot.root: {:x}", slot.root.to_cap());
                    cspace_debug_println!("slot.cptr: {:x}", slot.cptr);
                    cspace_debug_println!("slot.depth: {}", slot.depth);
                    cspace_debug_println!("window.cnode.depth: {}", window.cnode.depth);
                    cspace_debug_println!("window.cnode.cptr: {:x}", window.cnode.cptr);
                    cspace_debug_println!("window.cnode.root: {:x}", window.cnode.root.to_cap());
                    cspace_debug_println!("window.num_slots: {}", window.num_slots);
                    cspace_debug_println!("window.first_slot_idx: {}", window.first_slot_idx);
                    cspace_debug_println!("info.guard_val: {:x}", info.guard_val);
                    cspace_debug_println!("info.prefix_bits: {:x}", info.prefix_bits);
                    cspace_debug_println!("info.guard_bits: {:x}", info.guard_bits);
                    cspace_debug_println!("info.radix_bits: {:x}", info.radix_bits);
                    if let Err(err) = alloc.utspace().allocate_raw(alloc, window, info, size_bits, objtype, zone) {
                        return Err(CSpaceError::RetypeFailure { details: err.1 })
                    }
                    Ok(slot)
                },
                Err(err) => Err(err),
            }
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    /// Allocate a single slot from this manager and allocate an object of 
    /// fixed size (i.e. any object for which 0 is a valid size) from RAM into
    /// it, returning a raw CPtr
    fn allocate_slot_with_object_raw_ref_ram<A: AllocatorBundle>(&self, size_bits: usize, objtype: usize, alloc: &A) -> Result<SlotRef, CSpaceError>{
        self.allocate_slot_with_object_raw_ref(size_bits, objtype, UtZone::RamAny, alloc)
    }
    /// Allocate a single slot from this manager and allocate an object of 
    /// fixed size (i.e. any object for which 0 is a valid size) from RAM into
    /// it, returning a raw CPtr
    fn allocate_slot_with_object_raw_ref_fixed<A: AllocatorBundle>(&self, objtype: usize, alloc: &A) -> Result<SlotRef, CSpaceError>{
        self.allocate_slot_with_object_raw_ref(0, objtype, UtZone::RamAny, alloc)
    }
    ///Frees an object (given as a wrapper, so the type is inferred) from the UTSpace manager and then frees and deletes its slot from the CSpace manager (only works with objects from this CSpace manager)
    fn free_and_delete_slot_with_object<T: sel4::Allocatable + sel4::ToCap, A: AllocatorBundle>(&self, object: &T, size_bits: usize, alloc: &A) -> Result<(), CSpaceError>{
        if let Ok(slot) = self.obj_to_slot(object){
            self.free_and_delete_slot_with_object_ref::<T, A>(slot, size_bits, alloc)
        }else{
            Err(CSpaceError::InvalidArgument)
        }
    }
    ///Frees an object of fixed size (given as a wrapper, so the type is inferred) from the UTSpace manager and then frees and deletes its slot from the CSpace manager (only works with objects from this CSpace manager)
    fn free_and_delete_slot_with_object_fixed<T: sel4::Allocatable + sel4::ToCap, A: AllocatorBundle>(&self, object: &T, alloc: &A) -> Result<(), CSpaceError>{
        self.free_and_delete_slot_with_object(object, 0, alloc)
    }

    ///Frees an object (given as a SlotRef) from the UTSpace manager and then
    ///frees and deletes its slot from the CSpace manager (only works with
    ///objects from this CSpace manager)
    ///
    ///`T` is a wrapper object specifying the type; it cannot be inferred since
    ///the SlotRef carries no type information.
    fn free_and_delete_slot_with_object_ref<T: sel4::Allocatable + sel4::ToCap, A: AllocatorBundle>(&self, slot: SlotRef, size_bits: usize, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("free_and_delete_slot_with_object_ref {:x} {:x} {} {}", slot.root.to_cap(), slot.cptr, slot.depth, size_bits);

        match self.slot_window_utspace(slot){
            Ok(window) => {
                if let Err(err) = alloc.utspace().deallocate::<T, _>(alloc, window, self.slot_info(slot).unwrap(), size_bits) {
                    cspace_debug_println!("utspace.deallocate failed");
                    return Err(CSpaceError::RetypeFailure { details: err }) 
                }
                if self.free_and_delete_slot(slot, alloc).is_ok() {
                    Ok(())
                }else{
                    cspace_debug_println!("free_and_delete_slot failed");
                    Err(CSpaceError::CSpaceExhausted)
                }
            }
            Err(err) => { 
                cspace_debug_println!("slot_window_utspace failed");
                Err(err) 
            },
        }
    }
    ///Frees an object of fixed size (given as a SlotRef) from the UTSpace
    ///manager and then frees and deletes its slot from the CSpace manager
    ///(only works with objects from this CSpace manager)
    ///
    ///`T` is a wrapper object specifying the type; it cannot be inferred since
    ///the SlotRef carries no type information.
    fn free_and_delete_slot_with_object_ref_fixed<T: sel4::Allocatable + sel4::ToCap, A: AllocatorBundle>(&self, slot: SlotRef, alloc: &A) -> Result<(), CSpaceError>{
        self.free_and_delete_slot_with_object_ref::<T, A>(slot, 0, alloc)
    }
    ///Frees an object (given as a raw CPtr and type code) from the UTSpace
    ///manager and then frees and deletes its slot from the CSpace manager (only
    ///works with objects from this CSpace manager)
    fn free_and_delete_slot_with_object_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, objtype: usize, size_bits: usize, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("free_and_delete_slot_with_object_raw {:x} {}", cptr, size_bits);
        if let Ok(slot) = self.cptr_to_slot(cptr) {
            self.free_and_delete_slot_with_object_raw_ref(slot, objtype, size_bits, alloc)
        }else{
            Err(CSpaceError::InvalidArgument)
        }
    }
    ///Frees an object of fixed size (given as a raw CPtr and type code) from
    ///the UTSpace
    ///manager and then frees and deletes its slot from the CSpace manager (only
    ///works with objects from this CSpace manager)
    fn free_and_delete_slot_with_object_raw_fixed<A: AllocatorBundle>(&self, cptr: seL4_CPtr, objtype: usize, alloc: &A) -> Result<(), CSpaceError>{
        self.free_and_delete_slot_with_object_raw(cptr, objtype, 0, alloc)
    }

    ///Frees an object (given as a SlotRef and raw type code) from the UTSpace
    ///manager and then frees and deletes its slot from the CSpace manager (only
    ///works with objects from this CSpace manager)
    fn free_and_delete_slot_with_object_raw_ref<A: AllocatorBundle>(&self, slot: SlotRef, objtype: usize, size_bits: usize, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("free_and_delete_slot_with_object_raw_ref {:x} {:x} {} {}", slot.root.to_cap(), slot.cptr, slot.depth, size_bits);
        match self.slot_window_utspace(slot){
            Ok(window) => {
                if let Err(err) = alloc.utspace().deallocate_raw(alloc, window, self.slot_info(slot).unwrap(), objtype, size_bits) {
                    cspace_debug_println!("RetypeFailure");
                    return Err(CSpaceError::RetypeFailure { details: err }) 
                }
                if self.free_and_delete_slot(slot, alloc).is_ok() {
                    Ok(())
                }else{
                    cspace_debug_println!("CSpaceExhausted");
                    Err(CSpaceError::CSpaceExhausted)
                }
            }
            Err(err) => { 
                cspace_debug_println!("slot_window_utspace failed");
                Err(err) 
            },
        }
    }

    fn free_and_delete_slot_with_object_raw_ref_fixed<A: AllocatorBundle>(&self, slot: SlotRef, objtype: usize, alloc: &A) -> Result<(), CSpaceError>{
        self.free_and_delete_slot_with_object_raw_ref(slot, objtype, 0, alloc)
    }

    ///Hook method called when the manager is deleted
    fn delete_hook<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError> {
        Ok(())
    }
    ///Free and delete a sub-level CNode
    fn free_and_delete_sublevel<T: CSpaceManager, A: AllocatorBundle>(&self, sublevel: T, alloc: &A) -> Result<(), CSpaceError> where Self: Sized{
        self.free_and_deinitialize_sublevel(&sublevel, alloc)
    }
    ///Free and deinitialize a sub-level CNode
    ///
    ///This is equivalent to free_and_delete_sublevel(), but it takes a 
    ///reference and is only really intended for deinitializing struct fields in
    ///drop methods and the like
    fn free_and_deinitialize_sublevel<T: CSpaceManager, A: AllocatorBundle>(&self, sublevel: &T, alloc: &A) -> Result<(), CSpaceError> where Self: Sized{
        if let Err(err) = sublevel.delete_hook(alloc){
            return Err(err);
        }
        self.free_and_delete_slot_with_object_ref::<CNode, _>(sublevel.to_slot().unwrap(), sublevel.info().unwrap().radix_bits.into(), alloc)
    }
    ///Deletes the capability in a slot and then frees the slot
    fn free_and_delete_slot<A: AllocatorBundle>(&self, slot: SlotRef, alloc: &A) -> Result<(), CSpaceError> {
        if let Err(err) = slot.delete() {
            cspace_debug_println!("slot.delete failed");
            return Err(CSpaceError::SyscallError { details: err } ) 
        }
        if self.free_slot(slot, alloc).is_ok() {
            Ok(())
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }

    ///Deletes the capability in a slot and then frees the slot
    fn free_and_delete_slot_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError> {
        if let Ok(slot) = self.cptr_to_slot(cptr) {
            self.free_and_delete_slot(slot, alloc)
        }else{
            Err(CSpaceError::InvalidArgument)
        }
    }

    ///Allocate a sublevel CNode but do not create a manager for it
    ///
    ///Intended mostly for internal use by methods that create managers
    fn allocate_sublevel_base<A: AllocatorBundle>(&self, size_bits: usize, is_root: bool, alloc: &A) -> Result<(sel4::Window, sel4::CNodeInfo), CSpaceError>{ 
        match self.allocate_slot_with_object_ref::<CNode, _>(size_bits, UtZone::RamAny, alloc) {
            Ok(dest) => {
                cspace_debug_println!("allocate_sublevel_base {:x} {:x} {}", dest.root.to_cap(), dest.cptr, dest.depth);
                match cnode_slot_and_info(dest, size_bits, is_root, 0, 0, self.is_implicitly_addressable()) {
                    Ok((orig_slot, info)) => {

                        let slot = SlotRef::new(
                            orig_slot.root, 
                            cptr_shr(orig_slot.cptr, info.prefix_bits), 
                            info.prefix_bits
                        );
                        let window = Window {
                            cnode: slot,
                            first_slot_idx: 0,
                            num_slots: 1 << size_bits,
                        };
                        Ok((window, info))
                    },
                    Err(err) => Err(err),
                }
            },
            Err(err) => Err(err),
        }
    }
    /// Allocates a new child CNode and creates a bitmap allocator for it
    fn allocate_sublevel_bitmap<A: AllocatorBundle>(&self, size_bits: usize, is_root: bool, alloc: &A) -> Result<BitmapAllocator, CSpaceError>{
        match self.allocate_sublevel_base(size_bits, is_root, alloc){
            Ok((window, info)) => {
                if let Some(bitmap) = BitmapAllocator::new(window, info, self.parent_root().unwrap()){
                    Ok(bitmap)
                }else{
                    Err(CSpaceError::InternalError)
                }
            }
            Err(err) => {
                Err(err)
            }
        }
    }
    /// Allocates a new child CNode and creates a bitmap allocator for it
    fn allocate_sublevel_dynamic_bitmap<A: AllocatorBundle>(&self, size_bits: usize, is_root: bool, bottom_size_bits: usize, min_free: usize, dealloc_slots: usize, max_dealloc_rounds: usize, alloc: &A) -> Result<DynamicBitmapAllocator, CSpaceError>{
        match self.allocate_sublevel_base(size_bits, is_root, alloc){
            Ok((window, info)) => {
                if let Some(bitmap) = DynamicBitmapAllocator::new(window, info, self.parent_root().unwrap(), bottom_size_bits, min_free, dealloc_slots, max_dealloc_rounds, alloc){
                    Ok(bitmap)
                }else{
                    Err(CSpaceError::InternalError)
                }
            }
            Err(err) => {
                Err(err)
            }
        }
    }
    /// Allocates a new child CNode and creates a bump allocator for it
    fn allocate_sublevel_bump<A: AllocatorBundle>(&self, size_bits: usize, is_root: bool, alloc: &A) -> Result<BumpAllocator, CSpaceError>{
        match self.allocate_sublevel_base(size_bits, is_root, alloc){
            Ok((window, info)) => {
                Ok(BumpAllocator::new(window, info, self.parent_root().unwrap()))
            }
            Err(err) => {
                Err(err)
            }
        }
    }

    ///Acquires the recursion lock (if it has one) for this manager before
    ///allocating, refilling if necessary
    fn lock_alloc<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Acquires the recursion lock (if it has one) for this manager before
    ///deallocating, refilling if necessary
    fn lock_dealloc<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }


    ///Acquires the recursion lock (if it has one) for this manager before
    ///allocating without refilling
    fn lock_alloc_no_refill<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Acquires the recursion lock (if it has one) for this manager before
    ///deallocating without refilling
    fn lock_dealloc_no_refill<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Refills this manager if necessary
    fn refill<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Drops any deallocated internal metadata if necessary
    fn drop_unused<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Releases the recursion lock (if it has one) for this manager after
    ///allocating without dropping deallocated metadata
    fn unlock_alloc_no_drop<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Releases the recursion lock (if it has one) for this manager after
    ///deallocating without dropping deallocated metadata
    fn unlock_dealloc_no_drop<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Releases the recursion lock (if it has one) for this manager after
    ///allocating, dropping deallocated metadata as necessary
    fn unlock_alloc<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    ///Releases the recursion lock (if it has one) for this manager after
    ///deallocating, dropping deallocated metadata as necessary
    fn unlock_dealloc<A: AllocatorBundle>(&self, _: &A) -> Result<(), CSpaceError>{
        Ok(())
    }

    /// Returns true if this CNode is intended to be used as a root (either the
    /// calling thread's configured root or a sub-level inteneded to be used as 
    /// a root)
    fn is_root(&self) -> bool {
        if let Some(info) = self.info() {
            info.prefix_bits == 0
        }else{
            false
        }
    }

    /// Returns true if this CNode is addressable from the thread's configured
    /// root. Any implementation that doesn't have a single root CNode must 
    /// override this.
    fn is_implicitly_addressable(&self) -> bool {
        self.window().unwrap().cnode.root.to_cap() == self.parent_root().unwrap().to_cap()
    }

    ///Returns a capability wrapper for the root CNode containing this manager's
    ///CNode
    ///
    ///If this is the root CNode for the calling thread this will normally be
    ///the manager's own CNode
    fn parent_root(&self) -> Option<CNode>;

    fn minimum_slots(&self) -> usize;

    fn minimum_untyped(&self) -> usize;

    fn minimum_vspace(&self) -> usize;
}

//TODO: add a PartialBulkCSpaceManager trait with methods that allocate up to a certain number of slots, but may return a smaller window, as well as methods that allocate into a slice/vector

/// Manager of sub-Windows of a `CSpace`.
pub trait BulkCSpaceManager: CSpaceManager {
    /// This token represents any additional information necessary for later freeing a range.
    type Token: Deref<Target = Window>;

    /// Allocate `count` slots.
    fn allocate_slots<A: AllocatorBundle>(
        &self,
        count: usize,
        alloc: &A,
    ) -> Result<Self::Token, ()>;

    /// Free a previously allocated range.
    ///
    /// If the named range has already been freed, or isn't managed by this manager, there may be
    /// unexpected consequences, such as a panic.
    fn free_slots<A: AllocatorBundle>(&self, token: Self::Token, alloc: &A) -> Result<(), ()>;

    /// Return a `CNodeInfo` which can be used to encode CPtrs from the given window.
    ///
    /// Can return `None` if the window is not managed by this manager, but is not required to do
    /// so.
    fn slots_info(&self, token: &Self::Token) -> Option<CNodeInfo>;

    /// Return a bitmap allocator that manages a window of this CNode
    fn allocate_subwindow_bitmap<A: AllocatorBundle>(&self, count: usize, alloc: &A) -> Result<(BitmapAllocator, Self::Token), CSpaceError>{
        if let Ok(token) = self.allocate_slots(count, alloc){
            if let Some(bitmap) = BitmapAllocator::new(*token, self.slots_info(&token).expect("slots_info returned None for a window managed by this allocator (this should not happen)"), self.parent_root().unwrap()) {
                Ok((bitmap, token))
            }else{
                Err(CSpaceError::InternalError)
            }
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    /// Return a bump allocator that manages a window of this CNode
    fn allocate_subwindow_bump<A: AllocatorBundle>(&self, count: usize, alloc: &A) -> Result<(BumpAllocator, Self::Token), CSpaceError>{
        if let Ok(token) = self.allocate_slots(count, alloc){
            let bump = BumpAllocator::new(*token, self.slots_info(&token).expect("slots_info returned None for a window managed by this allocator (this should not happen)"), self.parent_root().unwrap());
            Ok((bump, token))
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    //TODO: implement methods that allocate objects into a vector
}

/// CSpace manager with a CNode capability that can be copied (only the
/// CNode capability gets copied, not the allocator or the underlying CNode 
/// itself)
pub trait CopyableCSpaceManager: CSpaceManager {
    ///Copies the CNode of this manager to an existing slot
    fn copy(&self, dest: SlotRef, rights: sel4::CapRights) -> Result<(), sel4::Error> {
        self.to_slot().unwrap().copy(dest, rights)
    }
    ///Copies the CNode of this manager to a new slot in the given manager
    fn copy_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, alloc: &A) -> Result<SlotRef, CSpaceError> {
        if let Ok(slot) = dest.allocate_slot(alloc) {
            if let Err(err) = self.copy(slot, rights) {
                let _ = dest.free_slot(slot, alloc);
                return Err(CSpaceError::SlotTransferError { details: Some(err) })
            }
            Ok(slot)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    ///Mints the CNode of this manager to an existing slot
    fn mint(&self, dest: SlotRef, rights: sel4::CapRights, guard_val: seL4_Word, guard_bits: u8) -> Result<(), sel4::Error>{
        self.to_slot().unwrap().mint(dest, rights, Badge::new_guard(guard_val, guard_bits))
    }
    ///Mints the CNode of this manager to a new slot in the given manager
    fn mint_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, guard_val: seL4_Word, guard_bits: u8, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if let Ok(slot) = dest.allocate_slot(alloc) {
            if let Err(err) = self.mint(slot, rights, guard_val, guard_bits) {
                let _ = dest.free_slot(slot, alloc);
                return Err(CSpaceError::SlotTransferError { details: Some(err) }); 
            }
            Ok(slot)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
}

/// CSpace manager with a CNode capability that can be moved and updated
pub trait MovableCSpaceManager: CSpaceManager {
    ///Moves the CNode of this manager to an existing slot
    fn move_(&self, dest: SlotRef, is_root: bool) -> Result<(), CSpaceError>{
        let size_bits = self.info().unwrap().radix_bits;
        if let Ok((slot, info)) = cnode_slot_and_info(dest, size_bits.into(), is_root, 0, 0, self.is_implicitly_addressable()){
            if let Err(err) = self.to_slot().unwrap().move_(dest) {
                return Err(CSpaceError::SlotTransferError { details: Some(err) })
            }
            self.set_slot_and_info(slot, info)
                .and_then(|_|{Ok(())})
                .or_else(|_|{Err(CSpaceError::SlotTransferError { details: None })})
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    ///Moves the CNode of this manager to a new slot in the given manager
    fn move_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, is_root: bool, alloc: &A) -> Result<(), CSpaceError>{
        if let Ok(slot) = dest.allocate_slot(alloc) {
            self.move_(slot, is_root)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    ///Mutates the CNode of this manager to an existing slot
    fn mutate(&self, dest: SlotRef, is_root: bool, guard_val: seL4_Word, guard_bits: u8) -> Result<(), CSpaceError>{
        let size_bits = self.info().unwrap().radix_bits;
        if let Ok((slot, info)) = cnode_slot_and_info(dest, size_bits.into(), is_root, 0, 0, self.is_implicitly_addressable()){
            if let Err(err) = self.to_slot().unwrap().mutate(dest, Badge::new_guard(guard_val, guard_bits)) {
                return Err(CSpaceError::SlotTransferError { details: Some(err) })
            }
            self.set_slot_and_info(slot, info)
                    .and_then(|_|{Ok(())})
                    .or_else(|_|{Err(CSpaceError::SlotTransferError { details: None })})
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    ///Mutates the CNode of this manager to a new slot in the given manager
    fn mutate_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, is_root: bool, alloc: &A, guard_val: seL4_Word, guard_bits: u8) -> Result<(), CSpaceError>{
        if let Ok(slot) = dest.allocate_slot(alloc) {
            if let Err(err) = self.mutate(slot, is_root, guard_val, guard_bits) {
                let _ = dest.free_slot(slot, alloc);
                return Err(err)
            }
            Ok(())
        }else{ 
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    fn set_slot(&self, slot: SlotRef) -> Result<(), ()>;
    fn set_info(&self, info: CNodeInfo) -> Result<(), ()>;
    fn set_slot_and_info(&self, slot: SlotRef, info: CNodeInfo) -> Result<(), ()>{
        if self.set_slot(slot).is_ok() && self.set_info(info).is_ok() {
            Ok(())
        }else{
            Err(())
        }
    }
}

pub trait AllocatableSlotRef {
    /// Allocates a new slot and copies this slot into it
    fn copy_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, alloc: &A) -> Result<SlotRef, CSpaceError>;
    /// Allocates a new slot and mints this slot into it
    fn mint_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, badge: sel4::Badge, alloc: &A) -> Result<SlotRef, CSpaceError>;
    /// Allocates a new slot and mutates this slot into it
    fn mutate_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, badge: sel4::Badge, alloc: &A) -> Result<SlotRef, CSpaceError>;
    /// Allocates a new slot and moves this slot into it
    fn move_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, alloc: &A) -> Result<SlotRef, CSpaceError>;
}

impl AllocatableSlotRef for sel4::SlotRef {
    fn copy_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if let Ok(slot) = dest.allocate_slot(alloc) {
            cspace_debug_println!("copy_to_new {:x} {} {:x} {:x} {} {:x}", self.root.to_cap(), self.depth, self.cptr, slot.root.to_cap(), slot.depth, slot.cptr);
            if let Err(err) = self.copy(slot, rights) {
                return Err(CSpaceError::SlotTransferError { details: Some(err) })
            }
            Ok(slot)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    /// Allocates a new slot and mints this slot into it
    fn mint_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, rights: sel4::CapRights, badge: sel4::Badge, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if let Ok(slot) = dest.allocate_slot(alloc) {
            if let Err(err) = self.mint(slot, rights, badge) { 
                return Err(CSpaceError::SlotTransferError { details: Some(err) })
            }
            Ok(slot)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    /// Allocates a new slot and mutates this slot into it
    fn mutate_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, badge: sel4::Badge, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if let Ok(slot) = dest.allocate_slot(alloc) {
            if let Err(err) = self.mutate(slot, badge) {
                return Err(CSpaceError::SlotTransferError { details: Some(err) })
            }
            Ok(slot)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    /// Allocates a new slot and moves this slot into it
    fn move_to_new<C: CSpaceManager, A: AllocatorBundle>(&self, dest: &C, alloc: &A) -> Result<SlotRef, CSpaceError>{
        if let Ok(slot) = dest.allocate_slot(alloc) {
            if let Err(err) = self.move_(slot) {
                return Err(CSpaceError::SlotTransferError { details: Some(err) })
            }
            Ok(slot)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
}

///A CSpace allocator that manages a single CNode
trait SingleLevelCSpaceManager: CSpaceManager {
    ///Allocates a new index from this manager
    fn allocate_idx<A: AllocatorBundle>(&self, alloc: &A) -> Result<usize, ()>;
    ///Frees an index from this manager
    fn free_idx<A: AllocatorBundle>(&self, idx: usize, _: &A) -> Result<(), ()>;

    ///Implementation of allocate_slot_raw for single-level CSpace managers
    fn allocate_slot_raw_single_level<A: AllocatorBundle>(&self, alloc: &A) -> Result<seL4_CPtr, CSpaceError> {
        if let Ok(index) = self.allocate_idx(alloc) {
            cspace_debug_println!("SingleLevelCspaceManager::allocate_slot_raw_single_level: {}", index);
            let ret = self.window().unwrap().cptr_to(&self.info().unwrap(), index).expect(
                "tried to allocate a slot out of bounds; should not happen",
            );
            cspace_debug_println!("allocated slot: {:x}", ret); 
            Ok(ret)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }

    ///Implementation of allocate_slot for single-level CSpace managers
    fn allocate_slot_single_level<A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError> {
        if let Ok(index) = self.allocate_idx(alloc) {
            #[cfg(feature = "debug_cspace")]{
                let window = self.window().unwrap();
                let info = self.info().unwrap();
                cspace_debug_println!("SingleLevelCspaceManager::allocate_slot_single_level");
                cspace_debug_println!("window.cnode.root: {:x}", window.cnode.root.to_cap());
                cspace_debug_println!("window.cnode.cptr: {:x}", window.cnode.cptr);
                cspace_debug_println!("window.cnode.depth: {}", window.cnode.depth);
                cspace_debug_println!("window.first_slot_idx: {}", window.first_slot_idx);
                cspace_debug_println!("window.num_slots: {}", window.num_slots);
                cspace_debug_println!("info.guard_val: {:x}", info.guard_val);
                cspace_debug_println!("info.radix_bits: {}", info.radix_bits);
                cspace_debug_println!("info.guard_bits: {}", info.guard_bits);
                cspace_debug_println!("info.prefix_bits: {}", info.prefix_bits);
            }
            let slot = self.window().unwrap().slotref_to(&self.info().unwrap(), index).expect(
                "tried to allocate a slot out of bounds; should not happen",
            );
            cspace_debug_println!("allocated slot: {:x} {:x} {}", slot.root.to_cap(), slot.cptr, slot.depth);

            Ok(slot)
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }

    ///Implementation of free_slot_raw for single-level CSpace managers
    fn free_slot_raw_single_level<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError> {
        let idx = self.info().unwrap().decode(cptr).radix - self.window().unwrap().first_slot_idx;
        
        cspace_debug_println!("SingleLevelCSpaceManager::free_slot_raw_single_level {:x} {}", cptr, idx);
        if self.free_idx(idx, alloc).is_ok(){
            Ok(())
        }else{
            Err(CSpaceError::CSpaceExhausted)
        }
    }
    ///Implementation of slot_info_raw for single-level CSpace managers
    fn slot_info_raw_single_level(&self, _: seL4_CPtr) -> Option<CNodeInfo> {
        Some(self.info().unwrap())
    }
    ///Implementation of slot_window_raw for single-level CSpace managers
    fn slot_window_raw_single_level(&self, cptr: seL4_CPtr) -> Option<Window> {
        cspace_debug_println!("SingleLevelCSpaceManager::slot_window_raw_single_level {:?}\n{:x}\n{:x} decodes into {:?}", self.info(), self.info().unwrap().decode(cptr).radix, cptr, self.info().unwrap().decode(cptr));
        Some(Window {
            first_slot_idx: self.info().unwrap().decode(cptr).radix,
            num_slots: 1,
            cnode: self.to_slot().unwrap(),
        })
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    bitmap::add_custom_slabs(alloc)?;
    dynamic_bitmap::add_custom_slabs(alloc)
}
