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


//TODO: support more than two levels
//  - this can be done by switching to an array of SubAllocatorManagers for every level but the top (which will remain a single BitmapAllocator)
//  - when a new CNode needs to be allocated from the bottom level, a new CNode will be allocated from each level starting from the lowest one with free slots
//  - there will still only be one set of recursion limits exposed, and that will be for the bottom level (the limits for all other levels will be all 0)
//  - change new() and allocate_sublevel_dynamic_bitmap() to take a slice of widths, one per level
//TODO: also make sure to update the README as well after support for more
//than one level has been added!

use core::fmt;
use core::cell::Cell;
use alloc::boxed::Box;

use sparse_array::{SubAllocatorManager, UnsafeRef};
use sel4::{CNode, Window, CNodeInfo, seL4_CPtr, SlotRef, ToCap};
use custom_slab_allocator::CustomSlabAllocator;

use crate::{
    AllocatorBundle, 
    cspace::{
        BitmapAllocator,
        CSpaceError, 
        CSpaceManager, 
        CopyableCSpaceManager,
    },
    cspace_debug_println,
    utspace::UtZone,
};

///A bitmap allocator that uses two levels of CNodes internally in order to 
///save memory
///
///This is a wrapper that uses multiple single-level bitmap allocators 
///internally.
pub struct DynamicBitmapAllocator {
    top: BitmapAllocator,
    bottom_size_bits: usize,
    bottom: SubAllocatorManager<BitmapAllocator>,
    remaining: Cell<usize>,
    first_idx: usize,
}

impl DynamicBitmapAllocator {
    /// Create a new `DynamicBitmapAllocator` for `window` encoded with `info`.
    ///
    /// Can panic if allocation of the underlying bitmap panics. In the future, may return `None`
    /// in that case. Currently will never return `None`.
    pub fn new<A: AllocatorBundle>(window: Window, info: CNodeInfo, parent_root: CNode, bottom_size_bits: usize, min_free: usize, dealloc_slots: usize, max_dealloc_rounds: usize, alloc: &A) -> Option<DynamicBitmapAllocator> {
        let bottom_slots = 1 << bottom_size_bits;
        BitmapAllocator::new(window, info, parent_root).and_then(|top| {
            top.allocate_sublevel_bitmap(bottom_size_bits, false, alloc
            ).ok().and_then(|sublevel| {
                let index = top.slot_window(sublevel.to_slot().unwrap())
                    .expect("allocator failed to return window for slot from itself (this should never happen)")
                    .first_slot_idx;
                cspace_debug_println!("DynamicBitmapAllocator::new: {:x} {} {}", index, sublevel.num_slots(), sublevel.slots_remaining());
                let bottom = SubAllocatorManager::new(UnsafeRef::from_box(Box::new(sublevel)), index, bottom_slots, 0, min_free, dealloc_slots, max_dealloc_rounds, true);
                Some(DynamicBitmapAllocator {
                    top,
                    bottom,
                    bottom_size_bits,
                    remaining: Cell::new(window.num_slots * bottom_slots),
                    first_idx: index,
                })
            })
        })
    }
    ///Get a sublevel
    fn bottom_get(&self, index: usize) -> Option<(UnsafeRef<BitmapAllocator>, usize, bool)>{
        self.bottom.get_any(index)
    }
    ///Get a sublevel in order to deallocate from it
    fn bottom_get_dealloc(&self, index: usize) -> Option<(UnsafeRef<BitmapAllocator>, usize, bool)> {
        self.bottom.get_dealloc(index,
            &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
                (sublevel.num_slots(), sublevel.slots_remaining()) 
            })
    }
    ///Allocates a new sublevel (for use in closures)
    fn allocate_sublevel<A: AllocatorBundle>(&self, alloc: &A) -> Result<(BitmapAllocator, usize, usize), CSpaceError> {
        self.top.allocate_sublevel_bitmap(self.bottom_size_bits, false, alloc).and_then(|sublevel| {
            let index = self.top.slot_window(sublevel.to_slot().unwrap())
                .expect("allocator failed to return window for slot from itself (this should never happen)")
                .first_slot_idx - self.first_idx;
            let num_slots = sublevel.num_slots();
            Ok((sublevel, index, num_slots))
        })
    }
    ///Get a (possibly new) free sublevel in order to allocate from it
    fn get_sublevel_alloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<UnsafeRef<BitmapAllocator>, CSpaceError>{
        let mut err_ret = CSpaceError::InternalError;
        self.bottom.get_alloc(&mut || {
            self.allocate_sublevel(alloc).or_else(|err| { 
                warn!("DynamicBitmapAllocator::get_sublevel_alloc: allocating new sub-level failed with {:?}", err);
                err_ret = err;
                Err(()) }
            )
        },
        &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
            (sublevel.num_slots(), sublevel.slots_remaining())
        }).or_else(|_| {
            warn!("DynamicBitmapAllocator::get_sublevel_alloc: getting sub-level failed with {:?}", err_ret);
            Err(err_ret)
        })
    }
    ///Check whether the last sublevel returned from get_sublevel_alloc needs to be marked full
    fn check_alloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        let mut err_ret = CSpaceError::InternalError;
        self.bottom.check_alloc(&mut || {
            self.allocate_sublevel(alloc).or_else(|err| { 
                warn!("DynamicBitmapAllocator::check_alloc: allocating new sub-level failed with {:?}", err);
                err_ret = err;
                Err(()) }
            )
        },
        &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
            (sublevel.num_slots(), sublevel.slots_remaining())
        }).or_else(|_| {
            warn!("DynamicBitmapAllocator::check_alloc: getting sub-level failed with {:?}", err_ret);
            Err(err_ret)
        })
    }
    ///Gets an index into the top-level CNode from the given CPtr
    fn cptr_to_index(&self, cptr: seL4_CPtr) -> usize {
        self.top.info().unwrap().decode(cptr).radix - self.first_idx
    }
    ///Gets the second-level CNode from which the given CPtr was allocated
    fn get_sublevel_cptr(&self, cptr: seL4_CPtr) -> Result<(UnsafeRef<BitmapAllocator>, usize), ()>{
        let index = self.cptr_to_index(cptr);
        cspace_debug_println!("DynamicBitmapAllocator::get_sublevel_cptr: index: {}", index);
        if let Some(res) = self.bottom_get(index) {
            Ok((res.0, index))
        }else{
            Err(())
        }
    }
    ///Gets the second-level CNode from which the given CPtr was allocated in
    ///order to deallocate the CPtr
    fn get_sublevel_cptr_dealloc(&self, cptr: seL4_CPtr) -> Result<(UnsafeRef<BitmapAllocator>, usize), CSpaceError>{
        let index = self.cptr_to_index(cptr);

        cspace_debug_println!("DynamicBitmapAllocator::get_sublevel_cptr_dealloc: index: {}", index);
        if let Some(res) = self.bottom_get_dealloc(index) {
            Ok((res.0, index))
        }else{
            Err(CSpaceError::InvalidArgument)
        }
    }
    ///Deallocates the sublevel at the given top index if necessary
    fn check_dealloc<A: AllocatorBundle>(&self, index: usize, alloc: &A) -> Result<(), CSpaceError>{
        let mut err0 = CSpaceError::InternalError;
        let mut err1 = CSpaceError::InternalError;
        let res = self.bottom.check_dealloc(index, 
            &mut |sublevel_opt, _| {
                if let Err(err) = self.drop_unused_inner(sublevel_opt, alloc) {
                    warn!("DynamicBitmapAllocator::check_dealloc: freeing sub-level failed with {:?}", err0);
                    err0 = err;
                    Err(())
                }else{
                    Ok(())
                }
            },
            &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
                (sublevel.num_slots(), sublevel.slots_remaining())
            },
            &mut || {
                self.allocate_sublevel(alloc).or_else(|err| {
                    warn!("DynamicBitmapAllocator::check_dealloc: allocating new sub-level failed with {:?}", err1);
                    err1 = err;
                    Err(()) 
                })
            });
        if res.is_ok(){
            Ok(())
        }else{
            match err0 {
               CSpaceError::InternalError => Err(err0),
               _ => Err(err1),
            }
        }
    }
    ///Internal method used in dealloc_fn closures 
    fn drop_unused_inner<A: AllocatorBundle>(&self, sublevel_opt: Option<UnsafeRef<BitmapAllocator>>, alloc: &A) -> Result<(), CSpaceError>{
        if sublevel_opt.is_none(){
            return Ok(());
        }
        let sublevel = sublevel_opt.unwrap();

        let ret = self.top.free_and_delete_slot_with_object_ref::<CNode, _>(sublevel.to_slot().unwrap(), sublevel.info().unwrap().radix_bits.into(), alloc);
        if ret.is_err(){
            warn!("DynamicBitmapAllocator::drop_unused_inner: freeing sub-level {:?} failed for {:?}", sublevel.window().unwrap(), self.window().unwrap());
        }
        ret
    }
}

impl CSpaceManager for DynamicBitmapAllocator {
    fn allocate_slot_raw<A: AllocatorBundle>(&self, alloc: &A) -> Result<seL4_CPtr, CSpaceError> {
        cspace_debug_println!("DynamicBitmapAllocator::allocate_slot_raw");

        match self.get_sublevel_alloc(alloc){
            Ok(sublevel) => {
                let ret = sublevel.allocate_slot_raw(alloc);
                if ret.is_ok() {
                    self.remaining.set(self.remaining.get() - 1);
                    cspace_debug_println!("{:x}", ret.unwrap());
                    if let Err(err) = self.check_alloc(alloc) {
                        warn!("DynamicBitmapAllocator::allocate_slot_raw: checking status of sub-level {:?} after allocation failed with {:?}; total free slots available: {}", sublevel.window().unwrap(), ret, self.bottom.get_free_slots());
                        return Err(err); 
                    }
                }else{
                    warn!("DynamicBitmapAllocator::allocate_slot_raw: allocation from sub-level {:?} failed with {:?}; total free slots available: {}", sublevel.window().unwrap(), ret, self.bottom.get_free_slots());
                }
                ret
            },
            Err(err) => {
                warn!("DynamicBitmapAllocator::allocate_slot: getting sub-level failed with {:?}; total free slots available: {}", err, self.bottom.get_free_slots());
                Err(err)
            },
        }
    }

    fn allocate_slot<A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError> {
        cspace_debug_println!("DynamicBitmapAllocator::allocate_slot");

        match self.get_sublevel_alloc(alloc){
            Ok(sublevel) => {
                let ret = sublevel.allocate_slot(alloc);
                if ret.is_ok() {
                    self.remaining.set(self.remaining.get() - 1);
                    let ret = ret.unwrap();
                    cspace_debug_println!("{:x} {} {:x}", ret.root.to_cap(), ret.depth, ret.cptr);
                    if let Err(err) = self.check_alloc(alloc) {
                        warn!("DynamicBitmapAllocator::allocate_slot: checking status of sub-level {:?} after allocation failed with {:?}; total free slots available: {}", sublevel.window().unwrap(), ret, self.bottom.get_free_slots());
                        return Err(err); 
                    }
                }else{
                    warn!("DynamicBitmapAllocator::allocate_slot: allocation from sub-level {:?} failed with {:?}; total free slots available: {}", sublevel.window().unwrap(), ret, self.bottom.get_free_slots());
                }
                ret
            },
            Err(err) => { 
                warn!("DynamicBitmapAllocator::allocate_slot: getting sub-level failed with {:?}; total free slots available: {}", err, self.bottom.get_free_slots());
                Err(err) 
            },
        }
    }

    fn free_slot_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError> {
        cspace_debug_println!("DynamicBitmapAllocator::free_slot_raw: {:x}", cptr);
        match self.get_sublevel_cptr_dealloc(cptr){
            Ok((sublevel, index)) => {
                match sublevel.free_slot_raw(cptr, alloc) {
                    Ok(_) => {
                        self.remaining.set(self.remaining.get() + 1);
                        let ret = self.check_dealloc(index, alloc);
                        if ret.is_err(){
                            warn!("DynamicBitmapAllocator::free_slot_raw: freeing slot returned error: {:?}", ret.unwrap_err());
                        }
                        ret
                    },
                    Err(err) => {
                        warn!("DynamicBitmapAllocator::free_slot_raw: freeing cptr {:x} from sub-level {:?} failed for {:?} with {:?}", cptr, sublevel.window().unwrap(), self.window().unwrap(), err);
                        Err(err)
                    },
                }
            },
            Err(err) => {
                warn!("DynamicBitmapAllocator::free_slot_raw: get_sublevel_cptr for cptr {:x} from {:?} with {:?}", cptr, self.window().unwrap(), err);
                Err(err)
            },
        }
    }
    
    fn lock_alloc_no_refill<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        self.top.lock_alloc_no_refill(alloc)?;
        self.bottom.lock_raw();
        Ok(())
    }

    fn lock_dealloc_no_refill<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        self.top.lock_dealloc_no_refill(alloc)?;
        self.bottom.lock_raw();
        Ok(())
    }

    fn refill<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("DynamicBitmapAllocator::refill");
        let mut err_ret = CSpaceError::InternalError;
        let mut res = self.top.refill(alloc);
        if res.is_ok() {
            res = self.bottom.refill(&mut || {
                self.allocate_sublevel(alloc).or_else(|err| {
                    warn!("DynamicBitmapAllocator::refill: allocating new sub-level for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                    err_ret = err;
                    Err(()) 
                })
            },
            &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
                (sublevel.num_slots(), sublevel.slots_remaining())
            }).or_else(|_| {
                warn!("DynamicBitmapAllocator::refill: refill for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                Err(err_ret)
            })
        }
        res
    }

    fn lock_alloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("DynamicBitmapAllocator::lock_alloc");
        let mut err_ret = CSpaceError::InternalError;
        let mut res = self.top.lock_alloc(alloc);
        if res.is_ok() {
            res = self.bottom.lock_alloc(&mut || {
                self.allocate_sublevel(alloc).or_else(|err| {
                    warn!("DynamicBitmapAllocator::lock_alloc: allocating new sub-level for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                    err_ret = err;
                    Err(()) 
                })
            },
            &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
                (sublevel.num_slots(), sublevel.slots_remaining())
            }).or_else(|_| {
                warn!("DynamicBitmapAllocator::lock_alloc: locking for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                Err(err_ret)
            })
        }
        res
    }
    fn drop_unused<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("DynamicBitmapAllocator::drop_unused");
        let mut err_ret = CSpaceError::InternalError;
        let mut res = self.top.drop_unused(alloc);
        if res.is_ok() {
            res = self.bottom.drop_unused(&mut |sublevel_opt, _| {
                if let Err(err) = self.drop_unused_inner(sublevel_opt, alloc) {
                    warn!("DynamicBitmapAllocator::drop_unused: freeing sub-level failed with {:?}", err_ret);
                    err_ret = err;
                    Err(())
                }else{
                    Ok(())
                }
            }).or_else(|_| {
                warn!("DynamicBitmapAllocator::drop_unused: dropping unused sub-levels for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                Err(err_ret)
            })
        }
        res
    }


    fn unlock_alloc_no_drop<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        self.top.unlock_alloc_no_drop(alloc)?;
        self.bottom.unlock_raw();
        Ok(())
    }

    fn unlock_dealloc_no_drop<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        self.top.unlock_dealloc_no_drop(alloc)?;
        self.bottom.lock_raw();
        Ok(())
    }

    fn unlock_alloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("DynamicBitmapAllocator::unlock_alloc");
        let mut err_ret = CSpaceError::InternalError;
        let mut res = self.top.unlock_alloc(alloc);
        if res.is_ok() {
            res = self.bottom.unlock_alloc(&mut |sublevel_opt, _| {
                if let Err(err) = self.drop_unused_inner(sublevel_opt, alloc) {
                    warn!("DynamicBitmapAllocator::unlock_alloc: freeing sub-level failed with {:?}", err_ret);
                    err_ret = err;
                    Err(())
                }else{
                    Ok(())
                }
            },
            &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
                (sublevel.num_slots(), sublevel.slots_remaining())
            }).or_else(|_| {
                warn!("DynamicBitmapAllocator::unlock_alloc: dropping unused sub-levels for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                Err(err_ret)
            })
        }
        res
    }

    fn lock_dealloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("DynamicBitmapAllocator::lock_dealloc");
        let mut err_ret = CSpaceError::InternalError;
        let mut res = self.top.lock_dealloc(alloc);
        if res.is_ok() {
            res = self.bottom.lock_dealloc(&mut || {
                self.allocate_sublevel(alloc).or_else(|err| { 
                    warn!("DynamicBitmapAllocator::lock_dealloc: allocating new sub-level for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                    err_ret = err;
                    Err(()) 
                })
            },
            &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
                (sublevel.num_slots(), sublevel.slots_remaining())
            }).or_else(|_| {
                warn!("DynamicBitmapAllocator::lock_dealloc: locking for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                Err(err_ret)
            })
        }
        res
    }

    fn unlock_dealloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError>{
        cspace_debug_println!("DynamicBitmapAllocator::unlock_dealloc");
        let mut err_ret = CSpaceError::InternalError;
        let mut res = self.top.unlock_dealloc(alloc);
        if res.is_ok() {
            res = self.bottom.unlock_dealloc(&mut |sublevel_opt, _| {
                if let Err(err) = self.drop_unused_inner(sublevel_opt, alloc){
                    warn!("DynamicBitmapAllocator::unlock_dealloc: freeing sub-level failed with {:?}", err_ret);
                    err_ret = err;
                    Err(())
                }else{
                    Ok(())
                }
            },
            &mut |sublevel: UnsafeRef<BitmapAllocator>, _: usize| {
                (sublevel.num_slots(), sublevel.slots_remaining())
            }).or_else(|_| {
                warn!("DynamicBitmapAllocator::unlock_dealloc: dropping unused sub-levels for {:?} failed with {:?}", self.window().unwrap(), err_ret);
                Err(err_ret)
            })
        }
        res
    }

    fn slot_info_raw(&self, cptr: seL4_CPtr) -> Option<CNodeInfo> {
        if let Ok((sublevel, _)) = self.get_sublevel_cptr(cptr){
            sublevel.slot_info_raw(cptr)
        }else{
            None
        }
    }

    fn slot_window_raw(&self, cptr: seL4_CPtr) -> Option<Window> {
        if let Ok((sublevel, _)) = self.get_sublevel_cptr(cptr){
            sublevel.slot_window_raw(cptr)
        }else{
            None
        }
    }

    fn parent_root(&self) -> Option<CNode> {
        self.top.parent_root()
    }

    /// The window managed by this allocator.
    fn window(&self) -> Option<Window> {
        self.top.window()
    }
    
    /// The CNodeInfo for this allocator.
    fn info(&self) -> Option<CNodeInfo> {
        self.top.info()
    }
    fn num_slots(&self) -> usize {
        self.top.num_slots() * (1 << self.bottom_size_bits)
    }
    fn slots_remaining(&self) -> usize {
        self.remaining.get()
    }

    fn cptr_to_slot(&self, cptr: seL4_CPtr) -> Result<SlotRef, ()> {
        if let Ok((sublevel, _)) = self.get_sublevel_cptr(cptr){
            sublevel.cptr_to_slot(cptr)
        }else{
            Err(())
        }
    }

    fn allocate_slot_with_object_ref<T: sel4::Allocatable + sel4::FromCap, A: AllocatorBundle>(&self, size_bits: usize, zone: UtZone, alloc: &A) -> Result<SlotRef, CSpaceError>{
        cspace_debug_println!("allocate_slot_with_object_ref");
        match self.get_sublevel_alloc(alloc){
            Ok(sublevel) => {
                self.remaining.set(self.remaining.get() - 1);
                let ret = sublevel.allocate_slot_with_object_ref::<T, A>(size_bits, zone, alloc);
                if ret.is_ok() {
                    cspace_debug_println!("{:x} {} {:x}", ret.unwrap().root.to_cap(), ret.unwrap().depth, ret.unwrap().cptr);
                }else{
                    warn!("DynamicBitmapAllocator::allocate_slot_raw: allocation from sub-level {:?} failed with {:?}; total free slots available: {}", sublevel.window().unwrap(), ret, self.bottom.get_free_slots());
                }
                if let Err(err) = self.check_alloc(alloc) {
                    warn!("DynamicBitmapAllocator::allocate_slot: checking status of sub-level {:?} after allocation failed with {:?}; total free slots available: {}", sublevel.window().unwrap(), ret, self.bottom.get_free_slots());
                    return Err(err); 
                }
                ret
            },
            Err(err) => {
                warn!("DynamicBitmapAllocator::allocate_slot_raw: getting sub-level failed with {:?}; total free slots available: {}", err, self.bottom.get_free_slots());
                Err(err)
            },
        }
    }

    fn delete_hook<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), CSpaceError> {
        cspace_debug_println!("DynamicBitmapAllocator: running delete hook");
        let mut err_ret = CSpaceError::InternalError;
        self.bottom.delete_contents(&mut |sublevel_opt, _|{
            if let Err(err) = self.drop_unused_inner(sublevel_opt, alloc){
                warn!("DynamicBitmapAllocator::delete_hook: freeing sub-level failed with {:?}", err_ret);
                err_ret = err;
                Err(())
            }else{
                Ok(())
            }
        }).and_then(|_| { 
            Ok(()) 
        }).or_else(|_| { 
            warn!("DynamicBitmapAllocator::delete_hook: deleting sublevels failed with {:?}", err_ret);
            Err(err_ret) 
        })
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

impl CopyableCSpaceManager for DynamicBitmapAllocator {
}

impl fmt::Debug for DynamicBitmapAllocator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "DynamicBitmapAllocator: {:x} {} {}", self.first_idx, self.remaining.get(), self.bottom.get_active_idx())
    }
}

impl Drop for DynamicBitmapAllocator {
    fn drop(&mut self) {
        let window = self.window().unwrap();
        let total_slots = window.num_slots * (1 << self.bottom_size_bits);
        if self.slots_remaining() != total_slots {
            panic!("attempted to drop DynamicBitmapAllocator for cptr {:x} root {:x} dpth {} with {} slots remaining out of {}", window.cnode.cptr, window.cnode.root.to_cap(), window.cnode.depth, self.slots_remaining(), total_slots);
        }
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    cspace_debug_println!("cspace::dynamic_bitmap::add_custom_slabs");
    sparse_array::add_custom_slabs_suballoc::<BitmapAllocator, A>(alloc)
}
