// Copyright 2019-2021 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Generic support for allocators that manage multiple sub-allocators

//TODO?: add support for some kind of custom hook to determine when refilling is required, for additional flexibility

use core::cell::{Cell, RefCell};
use alloc::{boxed::Box, vec::Vec};
use intrusive_collections::UnsafeRef;
use crate::ShiftedSparseArray;
use custom_slab_allocator::CustomSlabAllocator;
use core::mem::size_of;
use crate::SparseArrayNode;

macro_rules! suballoc_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_suballoc")]
        debug!($($toks)*);
    })
}

/// This is a generic struct for building allocators that manage multiple 
/// sub-allocators, each of which manages a sub-window of an address space.
/// Sub-allocators are automatically allocated and deallocated as required.
/// Addresses are of type usize, and the only requirement imposed on them is 
/// that each sub-window must have a unique address. Separation of phases for
/// allocation/deallocation within sub-windows and allocation/deallocation of
/// new subwindows is supported in order to limit dependency cycles is 
/// supported.
///
/// Some methods take closures. All closure arguments of the same name are the
/// same between different methods.
///
///
///`alloc_fn` is a closure to allocate a new sub-level, which should return 
///the sub-level, its address, and the total number of slots if it was 
///possible to allocate one, or None if no sub-level could be allocated.
///
///`slots_fn` is a closure that returns the total number of slots and the 
///current number of slots free for a sub-level. It is passed the sublevel and
///its address.
///
///`dealloc_fn` is a closure that deinitializes a sub-level. It is passed the
///sub-level and its address. If the drop_sublevels flag to the new() method was true, the closure will be called twice (once before the sub-level is
///dropped with both the sub-level and address, and once after it is dropped 
///with None and the address), and if it is false, the closure will only be 
///called once (with both the sub-level and address) and it will have to
///arrange for the sub-level to be dropped on 
///its own.

pub struct SubAllocatorManager<T> {
    min_free: Cell<usize>,
    first_idx: usize,
    max_drop_rounds: Cell<usize>,
    max_dealloc_sublevels: Cell<usize>,
    contents: ShiftedSparseArray<Option<UnsafeRef<T>>>,
    to_drop: RefCell<Vec<usize>>,
    to_drop_nested: RefCell<Vec<usize>>,
    active_sublevel: Cell<usize>,
    locks: Cell<usize>,
    available_slots: Cell<usize>,
    num_sublevels: Cell<usize>,
    last_changed_idx: Cell<Option<usize>>,
    last_changed_slots: Cell<usize>,
    max_idx: Cell<usize>,
    drop_sublevels: bool,
}

impl<T: PartialEq> SubAllocatorManager<T> {
    /// Create a new `SubAllocatorManager`
    ///
    /// The first sub-level (`first`), its address (`first_idx`), and the 
    /// number of slots it contains (`first_num_slots`) must be provided.
    ///
    /// If the low bits of the address are always going to be zero (e.g. for 
    /// page-aligned addresses) they may be shifted out of the address by
    /// providing a non-zero value for `addr_shift` in order to save space.
    ///
    /// `min_free` is the minimum number of free slots below which to allocate
    /// a new sub-level (in order to always keep a certain number of free 
    /// slots to allocate another sub-level in a situation where a dependency
    /// cycle exists)
    ///
    /// `max_dealloc_sublevels` is the maximum number of sublevels that may be
    /// deallocated while the recursion lock is held (it can be 0 if no 
    /// recursion locking is needed)
    ///
    /// `max_drop_rounds` is the maximum number of attempts to loop over the
    /// queue of deallocated sublevels when trying to empty it (it is ignored
    /// if max_dealloc_sublevels is 0)
    ///
    /// `drop_sublevels` should be false if the deallocation closure is going
    /// to save sub-levels somewhere to be dropped later. Otherwise, 
    /// sub-levels will be dropped after the first call to the deallocation 
    /// closure.
    pub fn new(first: UnsafeRef<T>, first_idx: usize, first_num_slots: usize, addr_shift: u32, min_free: usize, max_dealloc_sublevels: usize, max_drop_rounds: usize, drop_sublevels: bool) -> SubAllocatorManager<T> {
        let contents = ShiftedSparseArray::new(addr_shift);
        let mut to_drop = Vec::new();
        to_drop.reserve(max_dealloc_sublevels);
        let mut to_drop_nested = Vec::new();
        to_drop_nested.reserve(max_dealloc_sublevels);
        let ret = SubAllocatorManager {
            min_free: Cell::new(min_free),
            first_idx,
            max_drop_rounds: Cell::new(max_drop_rounds),
            max_dealloc_sublevels: Cell::new(max_dealloc_sublevels),
            contents,
            to_drop: RefCell::new(to_drop),
            to_drop_nested: RefCell::new(to_drop_nested),
            active_sublevel: Cell::new(first_idx),
            locks: Cell::new(0),
            available_slots: Cell::new(first_num_slots),
            num_sublevels: Cell::new(1),
            last_changed_idx: Cell::new(Some(first_idx)),
            last_changed_slots: Cell::new(first_num_slots),
            max_idx: Cell::new(0),
            drop_sublevels,
        };
        ret.put(first_idx, first);
        ret
    }
    /// Get the value of `min_free`
    pub fn get_min_free(&self) -> usize{
        self.min_free.get()
    }
    /// Set the value of `min_free`
    pub fn set_min_free(&self, min_free: usize){
        self.min_free.set(min_free);
    }
    /// Get the value of `max_drop_rounds`
    pub fn get_max_drop_rounds(&self) -> usize{
        self.max_drop_rounds.get()
    }
    /// Set the value of `max_drop_rounds`
    pub fn set_max_drop_rounds(&self, max_drop_rounds: usize){
        self.max_drop_rounds.set(max_drop_rounds);
    }
    /// Get the value of `max_dealloc_sublevels`
    pub fn get_max_dealloc_sublevels(&self) -> usize{
        self.max_dealloc_sublevels.get()
    }
    /// Set the value of `max_dealloc_sublevels`
    pub fn set_max_dealloc_sublevels(&self, max_dealloc_sublevels: usize){
        self.max_dealloc_sublevels.set(max_dealloc_sublevels);
    }
    /// Get the current total number of slots available across all sub-levels
    pub fn get_free_slots(&self) -> usize {
        self.available_slots.get()
    }
    /// Get the address of the sub-level from which allocations will occur
    pub fn get_active_idx(&self) -> usize {
        self.active_sublevel.get()
    }
    /// Get the current number of sub-levels
    pub fn len(&self) -> usize {
        self.num_sublevels.get()
    }
    /// Internal method to get the number of slots remaining in a sub-level
    fn get_slots_remaining<F>(&self, index: usize, slots_fn: &mut F) -> Option<usize> where F: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        let sublevel_opt = self.get_any(index);
        if sublevel_opt.is_none(){
            None
        }else{
            let (sublevel, _, _) = sublevel_opt.unwrap();
            let (_, slots_remaining) = slots_fn(sublevel, index);
            Some(slots_remaining)
        }
    }
    ///Internal method to update the saved index of the last sub-level to be 
    ///changed as well as the total number of slots available
    fn update_last_changed<F>(&self, index: usize, slots_fn: &mut F) where F: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        suballoc_debug_println!("update_last_changed: {:p} {:x}", self, index);
        if let Some(last_changed_idx) = self.last_changed_idx.get() {
            suballoc_debug_println!("last_changed_idx: {:p} {:x}", self, last_changed_idx);
            let slots = self.get_slots_remaining(last_changed_idx, slots_fn).unwrap();
            suballoc_debug_println!("available_slots: {} slots: {} last_changed_slots: {}", self.available_slots.get(), slots, self.last_changed_slots.get());
            if slots > self.last_changed_slots.get() {
                self.available_slots.set(self.available_slots.get() + 
                    (slots - self.last_changed_slots.get()));
            }else if slots < self.last_changed_slots.get() {
                self.available_slots.set(self.available_slots.get() - 
                    (self.last_changed_slots.get() - slots));
            }
            self.last_changed_slots.set(slots);
        }
        if self.last_changed_idx.get() != Some(index) { 
            if let Some(last_slots) = self.get_slots_remaining(index, slots_fn) {
                self.last_changed_slots.set(last_slots);
                suballoc_debug_println!("update_last_changed: {:p}: setting last_changed_idx to {:x}", self, index);
                self.last_changed_idx.set(Some(index));
            }else{
                suballoc_debug_println!("update_last_changed: {:p}: setting last_changed_idx to None", self);
                self.last_changed_idx.set(None);
            }
        }
        suballoc_debug_println!("update_last_changed: {:p} {:x}: done", self, index);
    }
    ///Internal base method for getting sub-levels at a particular address
    fn get_common(&self, index: usize, get_used: bool) -> Option<(UnsafeRef<T>, usize, bool)> {
        suballoc_debug_println!("SubAllocatorManager::get: {:x}", index);
        if let Some(allocator) = self.contents.get(index).clone() {
            suballoc_debug_println!("sublevel present in free list");
            Some((allocator, index, true))
        }else{
            if get_used {
                if let Some(allocator) = self.contents.get_hidden(index).clone() {
                    suballoc_debug_println!("sublevel present in used list");
                    Some((allocator, index, false))
                }else{
                    suballoc_debug_println!("sublevel not present in used list");
                    None
                }
            }else{
                suballoc_debug_println!("sublevel not present in free list");
                None
            }
        }
    }
    ///Internal base method for getting sub-levels at or below a particular
    ///address
    fn get_upper_bound_common(&self, index: usize, get_used: bool) -> Option<(UnsafeRef<T>, usize)> {
        suballoc_debug_println!("SubAllocatorManager::get_upper_bound: {:x}", index);
        let (found_index, allocator_opt) = if get_used {
            self.contents.get_upper_bound_any(index).clone()
        } else {
            self.contents.get_upper_bound(index).clone()
        };
        if let Some(allocator) = allocator_opt {
            Some((allocator, found_index))
        }else{
            None
        }
    }

    /// Get a sublevel with free slots at a particular address
    ///
    /// This returns the sub-level, its index, and whether it has any free 
    /// slots (always true) if a free sublevel is present, or None if the 
    /// address is empty or the sub-level is full.
    ///
    /// This method should not be used when allocating or deallocating, since
    /// it will not allocate/deallocate sub-levels nor will it update the free
    /// slots count.
    pub fn get_free(&self, index: usize) -> Option<(UnsafeRef<T>, usize, bool)> {
        self.get_common(index, false)
    }

    /// Get a sublevel at a particular address regardless of whether it is 
    /// full
    ///
    /// This returns the sub-level, its index, and whether it has any free 
    /// slots if one is present, or None if the address is empty.
    ///
    /// This method should not be used when allocating or deallocating, since
    /// it will not allocate/deallocate sub-levels nor will it update the free
    /// slots count.
    pub fn get_any(&self, index: usize) -> Option<(UnsafeRef<T>, usize, bool)> {
        self.get_common(index, true)
    }

    /// Get a sublevel at a particular address in order to deallocate from it,
    /// regardless of whether it is free
    ///
    /// After deallocating from the sublevel one of the check_dealloc* methods
    /// should be called in order to deallocate the sublevel itself if 
    /// necessary.
    ///
    /// This returns the sub-level, its index, and whether it has any free 
    /// slots if one is present, or None if the address is empty.
    ///
    /// Information on slots_fn is provided in the comment at the top of 
    /// this file.
    pub fn get_dealloc<F>(&self, index: usize, slots_fn: &mut F) -> Option<(UnsafeRef<T>, usize, bool)> where F: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        suballoc_debug_println!("get_dealloc: {:p}", self);
        self.update_last_changed(index, slots_fn);
        self.debug_check_slots(slots_fn);
        self.get_any(index)
    }

    /// Get the closest free sub-level at or below a particular address.
    ///
    /// This returns the sub-level and its address if one is present, or None 
    /// if there are no free sub-levels at or below the address.
    ///
    /// This method should not be used when allocating or deallocating, since
    /// it will not allocate/deallocate sub-levels nor will it update the free
    /// slots count.
    pub fn get_upper_bound_free(&self, index: usize) -> Option<(UnsafeRef<T>, usize)> {
        self.get_upper_bound_common(index, false)
    }

    /// Get the closest sub-level at or below a particular address regardless
    /// of whether it is free.
    ///
    /// This returns the sub-level and its address if one is present, or None 
    /// if there are no sub-levels at or below the address.
    ///
    /// This method should not be used when allocating or deallocating, since
    /// it will not allocate/deallocate sub-levels nor will it update the free
    /// slots count.
    pub fn get_upper_bound_any(&self, index: usize) -> Option<(UnsafeRef<T>, usize)> {
        self.get_upper_bound_common(index, true)
    }

    /// Get the closest sub-level at or below a particular address in order to
    /// deallocate from it (regardless of whether it is free)
    ///
    /// This returns the sub-level and its address if one is present, or None 
    /// if there are no sub-levels at or below the address.
    pub fn get_upper_bound_dealloc<F>(&self, index: usize, slots_fn: &mut F) -> Option<(UnsafeRef<T>, usize)> where F: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        suballoc_debug_println!("get_upper_bound_dealloc: {:p}", self);
        let res = self.get_upper_bound_any(index);
        if res.is_some(){
            let (sublevel, found_index) = res.unwrap();
            self.update_last_changed(found_index, slots_fn);
            self.debug_check_slots(slots_fn);
            Some((sublevel, found_index))
        }else{
            None
        }
    }

    ///Internal method to add a new sub-level
    fn put(&self, index: usize, sublevel: UnsafeRef<T>) {
        suballoc_debug_println!("SubAllocatorManager::put: {:x}", index);
        if index > self.max_idx.get(){
            self.max_idx.set(index);
        }
        suballoc_debug_println!("SubAllocatorManager::put: {:p} {:x}", self, index);
        self.contents.put(index, Some(sublevel))
    }

    ///Internal method to get the first free sub-level
    fn get_first_free(&self) -> (usize, Option<UnsafeRef<T>>) {
        suballoc_debug_println!("SubAllocatorManager::get_first_free");

        self.contents.get_first()
    }

    ///Internal method to mark a sub-level free
    fn mark_free(&self, index: usize) -> bool {
        suballoc_debug_println!("SubAllocatorManager::mark_free: {:x}", index);

        let ret = self.contents.show(index).is_some();
        suballoc_debug_println!("sub-level present: {}", ret);
        ret
    }
    ///Internal method to mark a sub-level full
    fn mark_full(&self, index: usize) -> bool {
        suballoc_debug_println!("SubAllocatorManager::mark_full: {:x}", index);
        let ret = self.contents.hide(index).is_some();
        suballoc_debug_println!("sub-level present: {}", ret);
        ret
    }
    ///Internal method to remove a full sub-level at a particular address
    fn take_full(&self, index: usize) -> Option<UnsafeRef<T>> {
        suballoc_debug_println!("SubAllocatorManager::take_full: {:x}", index);
        self.contents.take_hidden(index)
    }

    ///Internal method to remove the first full sublevel
    fn take_first(&self) -> (usize, Option<UnsafeRef<T>>){
        suballoc_debug_println!("SubAllocatorManager::take_first");

        self.contents.take_first_any()
    }

    ///Internal method to mark a sublevel as the current active one, as well
    ///as marking the previous active one as full if it has no slots left
    fn set_active<F>(&self, index: usize, slots_fn: &mut F) where F: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        let old_index = self.active_sublevel.get();
        if let Some((sublevel, _, free)) = self.get_any(old_index) {
            let (_total_slots, slots_remaining) = slots_fn(sublevel.clone(), old_index);
            if free && slots_remaining == 0 {
                self.mark_full(old_index); 
            }
        }
        self.active_sublevel.set(index);
        self.update_last_changed(index, slots_fn);
    }

    ///Get the current number of free sub-levels
    pub fn num_free_sublevels(&self) -> usize {
        self.contents.visible_len()
    }
    ///Get the current number of full sub-levels
    pub fn num_full_sublevels(&self) -> usize {
        self.contents.hidden_len()
    }

    ///Acquires the recursion lock, which prevents this manager from 
    ///attempting to allocate new sublevels or drop deallocated sublevels, in
    ///order to break dependency cycles.
    ///
    ///This is reentrant and may be called recursively as long as there is a 
    ///corresponding call to one of the unlock_* methods for each call to this
    ///
    ///This lock is only to break dependency cycles and does NOT make a 
    ///manager thread-safe. If a manager needs to be shared between multiple
    ///threads it must be wrapped in some kind of thread-safe lock (typically
    ///the containing allocator struct will be wrapped rather than the manager
    ///itself).
    pub fn lock_raw(&self) -> bool {
        let nested;
        if self.locks.get() > 0 {
            nested = true;
        }else{
            nested = false;
        }
        self.locks.set(self.locks.get() + 1);
        suballoc_debug_println!("SubAllocatorManager::lock_raw: {}", self.locks.get());
        nested
    }

    ///Refills this manager by allocating a new sub-level if the number of 
    ///free slots is below the minimum. The recursion lock should always have
    ///been acquired before calling this method (if there are any other 
    ///allocators with recursion locks upon which this manager depends, it is 
    ///safe to acquire them between locking this manager and refilling it.
    ///
    ///
    ///This does nothing if the recursion lock has been acquired more than 
    ///once, so it is safe to call as long as there is a corresponding 
    ///recursion lock acquisition.
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn refill<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        if self.locks.get() <= 1 && self.get_alloc_no_lock(alloc_fn, slots_fn, false).is_err() {
            Err(())
        }else{
            Ok(())
        }
    }

    ///Internal method combining lock_raw and refill (client code should use
    ///lock_alloc and lock_dealloc instead)
    fn lock_and_refill<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        self.lock_raw();
        self.refill(alloc_fn, slots_fn)
    }

    ///Lock and refill this manager before allocating
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn lock_alloc<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        self.lock_and_refill(alloc_fn, slots_fn)
    }

    ///Lock and refill this manager before deallocating
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn lock_dealloc<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        self.lock_and_refill(alloc_fn, slots_fn)
    }

    /// Release the recursion lock without dropping unused sublevels (which
    /// should have been done before calling this method
    pub fn unlock_raw(&self) -> bool {
        suballoc_debug_println!("SubAllocatorManager::unlock_raw: {}", self.locks.get());
        self.locks.set(self.locks.get() - 1);
        self.locks.get() == 0
    }

    /// Internal method to combine drop_unused and unlock_raw
    fn drop_and_unlock<F, G>(&self, dealloc_fn: &mut F, _slots_fn: &mut G) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        let ret;
        if self.drop_unused(dealloc_fn).is_err(){
            ret = Err(());
        }else{
            ret = Ok(());
        }
        self.unlock_raw();
        ret
    }

    /// Drop deallocated sublevels and unlock this manager after allocation
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn unlock_alloc<F, G>(&self, dealloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        self.drop_and_unlock(dealloc_fn, slots_fn)
    }

    /// Drop deallocated sublevels and unlock this manager after deallocation
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn unlock_dealloc<F, G>(&self, dealloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        self.drop_and_unlock(dealloc_fn, slots_fn)
    }

    /// Get a free sublevel for allocation while locking and unlocking the
    /// manager.
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn get_alloc<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G) -> Result<UnsafeRef<T>, ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        let nested = self.lock_raw();
        let ret = self.get_alloc_no_lock(alloc_fn, slots_fn, nested);
        self.unlock_raw();
        ret
    } 

    /// Get a free sublevel for allocation without locking. If the nested flag
    /// is set to false this will attempt to allocate a new sublevel if 
    /// necessary, and if it is true it will not; this is regardless of the
    /// lock state.
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn get_alloc_no_lock<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G, nested: bool) -> Result<UnsafeRef<T>, ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        suballoc_debug_println!("SubAllocatorManager::get_alloc_no_lock: {:p} {} {:x} {}", self, nested, self.active_sublevel.get(), self.available_slots.get());
        self.get_any(self.active_sublevel.get()).ok_or(()).and_then(|res| {
            self.update_last_changed(self.active_sublevel.get(), slots_fn);
            self.debug_check_slots(slots_fn);
            let allocator = res.0;
            let (_total_slots, slots_remaining) = slots_fn(allocator.clone(), self.active_sublevel.get());
            suballoc_debug_println!("total: {} remaining: {} available: {} minimum: {}", total_slots, slots_remaining, self.available_slots.get(), self.min_free.get());
            if slots_remaining == 0 || (self.available_slots.get() < self.min_free.get() && !nested) {
                suballoc_debug_println!("current sublevel out of slots or total slots below minimum");

                //either the current sublevel is full or there are fewer slots 
                //than the minimum and this is a non-nested allocation (if this 
                //is a nested allocation and there are fewer slots than the
                //minimum, the top-level allocation will already be adding a new
                //sublevel
                if slots_remaining == 0 {
                    suballoc_debug_println!("no slots remaining; marking active sublevel full");
                    self.mark_full(self.active_sublevel.get());
                }
                let (index, contents) = self.get_first_free();
                contents.ok_or(())
                    .and_then(|sublevel| {
                        if self.available_slots.get() > self.min_free.get() || nested { 
                            suballoc_debug_println!("SubAllocatorManager: {:p}: using free sublevel at index {:x} (previous active: {:x})", self, index, self.active_sublevel.get());
                            self.set_active(index, slots_fn);
                            self.debug_check_slots(slots_fn);
                            Ok(sublevel.clone())
                        }else{
                            //this forces a new sublevel to be allocated and
                            //doesn't actually get returned
                            suballoc_debug_println!("SubAllocatorManager: available slots ({}) below minimum of {}; allocating new sublevel", self.available_slots.get(), self.min_free.get());
                            Err(())
                        }
                    }).or_else(|_| {
                        if self.to_drop_nested.borrow().len() > 0 {
                            let index = self.to_drop_nested.borrow_mut().pop().unwrap();                       
                            suballoc_debug_println!("SubAllocatorManager: {:p}: using previously freed sublevel from nested deallocation at index {:x}", self, index);
                            self.mark_free(index);
                            self.num_sublevels.set(self.num_sublevels.get() + 1);
                            self.available_slots.set(self.available_slots.get() + self.get_slots_remaining(index, slots_fn).unwrap());
                            self.update_last_changed(index, slots_fn);
                            self.debug_check_slots(slots_fn);
                            return Ok(self.get_free(index).unwrap().0);
                        }
                        if nested {
                            //we shouldn't normally ever get here; the minimum
                            //should be set high enough so that there are always
                            //free slots for nested allocations

                            //TODO: return different error values for this
                            //insufficient free slots condition as well as all
                            //slots exhausted and allocation closure failures
                            warn!("SubAllocatorManager: ran out of slots during nested allocation");
                            return Err(());
                        }
                        alloc_fn().and_then(|res| {
                            let (sublevel, index, num_slots) = res;
                            let rc_sublevel = UnsafeRef::from_box(Box::new(sublevel));
                            let ret = rc_sublevel.clone();
                          
                            //TODO: return a distinct error code here
                            if self.get_any(index).is_some(){
                                warn!("SubAllocatorManager: cannot allocate new sublevel: allocation closure returned a sublevel with a duplicate index");
                                return Err(());
                            }

                            self.put(index, rc_sublevel);
                            suballoc_debug_println!("SubAllocatorManager: {:p} allocated new sublevel with index {:x} at address {:p} (previous active: {:x})", self, index, ret.as_ref(), self.active_sublevel.get());
                            let sublevel_opt = self.get_any(self.active_sublevel.get());
                            if sublevel_opt.is_some(){
                                let (sublevel, _, _) = sublevel_opt.unwrap();
                                let (_, slots_remaining) = slots_fn(sublevel.clone(), self.active_sublevel.get());
                                if slots_remaining == 0 {
                                    suballoc_debug_println!("inner allocation filled previous sublevel at {:x}; marking it full", self.active_sublevel.get());
                                    self.mark_full(self.active_sublevel.get());
                                }
                            }
                            self.set_active(index, slots_fn);
                            self.available_slots.set(self.available_slots.get() + num_slots);
                            self.num_sublevels.set(self.num_sublevels.get() + 1);
                            self.debug_check_slots(slots_fn);
                            Ok(ret)
                        }).or_else(|err| { 
                            warn!("SubAllocatorManager: allocation closure failed");
                            Err(err) 
                        })
                    })
            } else if slots_remaining == 0{
                warn!("no slots remaining in active sublevel at {:x}", self.active_sublevel.get());
                Err(())
            }else{ 
                suballoc_debug_println!("SubAllocatorManager: using current active sublevel at index {:x}", self.active_sublevel.get());
                Ok(allocator)
            }
        }).or_else(|err|{
            warn!("SubAllocatorManager: active sublevel invalid or getting sublevel failed");
            Err(err)
        })
    }

    ///Checks whether the sub-level returned from get_alloc needs to be marked
    ///full. Should be called after allocation from the sub-level is finished
    pub fn check_alloc<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        let nested = self.lock_raw();
        let ret = self.check_alloc_no_lock(alloc_fn, slots_fn, nested);
        self.unlock_raw();
        ret
    } 

    ///Same as check_alloc but doesn't try to acquire the recursion lock
    pub fn check_alloc_no_lock<F, G>(&self, alloc_fn: &mut F, slots_fn: &mut G, nested: bool) -> Result<(), ()> where F: FnMut() -> Result<(T, usize, usize), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        self.get_alloc_no_lock(alloc_fn, slots_fn, nested).and_then(|_| {
            Ok(())
        })
    }

    ///Check whether the specified sub-level can be deallocated, while locking
    ///and unlocking the manager. 
    ///
    ///Call this after deallocating from the sub-level. The reference to the 
    ///sub-level used for deallocating from it should have been obtained with 
    ///get_dealloc in order to keep the free slots count updated.
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    ///
    pub fn check_dealloc<F, G, H>(&self, index: usize, dealloc_fn: &mut F, slots_fn: &mut G, alloc_fn: &mut H) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize), H: FnMut() -> Result<(T, usize, usize), ()> {
        self.check_dealloc_internal(index, dealloc_fn, slots_fn, alloc_fn, true)
    }
    pub fn check_dealloc_no_refill<F, G>(&self, index: usize, dealloc_fn: &mut F, slots_fn: &mut G) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) {
        self.check_dealloc_internal(index, 
                                    dealloc_fn, 
                                    slots_fn, 
                                    &mut || {
                                        panic!("SubAllocatorManager::check_dealloc_no_refill() attempted to refill (this should never happen!)");
                                    },
                                    false)
    }

    fn check_dealloc_internal<F, G, H>(&self, index: usize, dealloc_fn: &mut F, slots_fn: &mut G, alloc_fn: &mut H, refill: bool) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize), H: FnMut() -> Result<(T, usize, usize), ()> {
        let nested = self.lock_raw();
        if !nested && refill {
            let _ = self.get_alloc_no_lock(alloc_fn, slots_fn, false);
        }
        let mut ret = self.check_dealloc_no_lock(index, dealloc_fn, slots_fn, nested);
        if !nested && ret.is_ok() && self.drop_unused(dealloc_fn).is_err(){
            ret = Err(())
        }
        self.unlock_raw();
        ret
    }


    ///Check whether the specified sub-level can be deallocated, without 
    ///locking or unlocking. If the nested flag is set to false this will
    ///attempt to drop it if necessary, and if it is true it will not; this
    ///is regardless of the lock state.
    ///
    ///Call this after deallocating from the sub-level. The reference to the 
    ///sub-level used for deallocating from it should have been obtained with 
    ///get_dealloc in order to keep the free slots count updated.
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn check_dealloc_no_lock<F, G>(&self, index: usize, dealloc_fn: &mut F, slots_fn: &mut G, nested: bool) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>, G: FnMut(UnsafeRef<T>, usize) -> (usize, usize) { 
        suballoc_debug_println!("SubAllocatorManager::check_dealloc_no_lock: {:p} {:x}", self, index);
        self.update_last_changed(index, slots_fn);
        self.debug_check_slots(slots_fn);
        self.mark_free(index);
        self.get_any(index).clone().ok_or(()).and_then(|res| {
            let sublevel = res.0;
            let (total_slots, slots_remaining) = slots_fn(sublevel.clone(), index);
            #[cfg(feature = "debug_suballoc")]
            if slots_remaining > total_slots || slots_remaining > self.available_slots.get() {
                suballoc_debug_println!("SubAllocatorManager::check_dealloc_no_lock: total: {}, remaining: {}, available: {}", total_slots, slots_remaining, self.available_slots.get());
            }

            if index == self.first_idx || total_slots - slots_remaining != 0 || self.available_slots.get() - slots_remaining < self.min_free.get() {
                suballoc_debug_println!("SubAllocatorManager: not freeing sublevel at index {:x} with {} slot(s) remaining out of {}", index, slots_remaining, total_slots);
                self.get_any(self.active_sublevel.get()).clone().ok_or(()).and_then(|res| {
                    let active_sublevel = res.0;
                    if slots_remaining == 0 {
                        self.mark_full(index);
                        suballoc_debug_println!("SubAllocatorManager: marked sublevel at {:x} full", index);
                    }
                    let (_, active_slots_remaining) = slots_fn(active_sublevel, self.active_sublevel.get());
                    // if the sublevel that just had slots freed now has more
                    // than the previous active one, make it active
                    if slots_remaining > active_slots_remaining {
                        suballoc_debug_println!("SubAllocatorManager: {:p}: making sublevel at {:x} active since it has more free slots than the previous active one at {:x} with {} slots free", self, index, self.active_sublevel.get(), active_slots_remaining);
                        self.set_active(index, slots_fn);
                    }
                    self.debug_check_slots(slots_fn);
                    Ok(())
                })
            }else{
                self.mark_full(index);
                self.last_changed_idx.set(None);
                suballoc_debug_println!("SubAllocatorManager: {:p}: setting last_changed_idx to None", self);
                let (free_index, first) = self.get_first_free();
                if first.is_some() && self.num_free_sublevels() != 1 {
                    suballoc_debug_println!("SubAllocatorManager: {:p}: freeing sublevel at index {:x} and address {:p}", self, index, sublevel.as_ref());
                    if nested {
                        if self.max_dealloc_sublevels.get() == 0 {
                            suballoc_debug_println!("cannot free sublevel because no deallocation slots are present and this is a nested call");
                            return Err(());
                        }
                        self.to_drop_nested.borrow_mut().push(index);
                    }else{
                        let _ = self.take_full(index);
                        if dealloc_fn(Some(sublevel.clone()), index).is_err() {
                            warn!("SubAllocatorManager::check_dealloc: deallocating sublevel failed");
                            return Err(());
                        }
                        if self.drop_sublevels {
                            unsafe { drop(UnsafeRef::into_box(sublevel)); }
                            if dealloc_fn(None, index).is_err() {
                                warn!("SubAllocatorManager::check_dealloc: deallocating sublevel failed");
                                return Err(());
                            }
                        }
                    }
                    self.available_slots.set(self.available_slots.get() - total_slots);
                    if index == self.active_sublevel.get() {
                        suballoc_debug_println!("SubAllocatorManager: {:p}: making sublevel at index {:x} current (previous active: {:x})", self, free_index, self.active_sublevel.get());
                        self.set_active(free_index, slots_fn);
                    }
                    self.num_sublevels.set(self.num_sublevels.get() - 1);
                    self.debug_check_slots(slots_fn);
                    Ok(())
                }else{
                    suballoc_debug_println!("SubAllocatorManager: {:p}: not freeing sublevel at index {:x} and address {:p} and marking it active since it was the last one free (previous active: {:x}", self, index, sublevel.as_ref(), self.active_sublevel.get());
                    self.set_active(index, slots_fn);
                    self.mark_free(index);
                    self.debug_check_slots(slots_fn);
                    Ok(()) 
                }
            }
        })
    }

    ///Drop any unused sub-levels that were previously deallocated. Does
    ///nothing if the lock count is greater than 1.
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn drop_unused<F>(&self, dealloc_fn: &mut F) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>{
        if self.locks.get() > 1 {
            return Ok(());
        }
        let mut ok = true;
        for _ in 0..self.max_drop_rounds.get() {
            let mut sublevels_remaining = false;
            loop {
                let index = self.to_drop_nested.borrow_mut().pop();
                if index.is_none() {
                    break;
                }
                sublevels_remaining = true;
                self.to_drop.borrow_mut().push(index.unwrap());
            }
            if !sublevels_remaining {
                break;
            }
            loop {
                let res = self.to_drop.borrow_mut().pop();
                if res.is_none() {
                    break;
                }
                let index = res.unwrap();
                suballoc_debug_println!("deallocating sublevel at {:x}", index);
                let sublevel = self.take_full(index).unwrap();
                if dealloc_fn(Some(sublevel.clone()), index).is_err() {
                    warn!("SubAllocatorManager::drop_sublevels: deallocating sublevel at {:x} failed", index);
                    ok = false;
                }
                if self.drop_sublevels {
                    unsafe { drop(UnsafeRef::into_box(sublevel)); }
                    if dealloc_fn(None, index).is_err() {
                        warn!("SubAllocatorManager::drop_sublevels: deallocating sublevel at {:x} failed", index);
                        ok = false;
                    }
                }
            }
        }
        if ok {
            Ok(())
        }else{
            Err(())
        }
    }

    ///Deletes the contents of this manager.
    ///
    ///Information on the closures is provided in the comment at the top of 
    ///this file.
    pub fn delete_contents<F>(&self, dealloc_fn: &mut F) -> Result<(), ()> where F: FnMut(Option<UnsafeRef<T>>, usize) -> Result<(), ()>{
        suballoc_debug_println!("SubAllocatorManager: deleting contents");
        let mut sublevel = self.take_first();
        while sublevel.1.is_some(){
            let sublevel_unwrapped = sublevel.1.unwrap();
            if dealloc_fn(Some(sublevel_unwrapped.clone()), sublevel.0).is_err() {
                warn!("SubAllocatorManager::delete_contents: deallocating sublevel failed");

                return Err(());
            }
            if self.drop_sublevels {
                unsafe { drop(UnsafeRef::into_box(sublevel_unwrapped)); }
                if dealloc_fn(None, sublevel.0).is_err() {
                    warn!("SubAllocatorManager::delete_contents: deallocating sublevel failed");
                    return Err(());
                }
            }

            sublevel = self.take_first();
        }
        while self.to_drop.borrow().len() > 0 || self.to_drop_nested.borrow().len() > 0 {
            if self.drop_unused(dealloc_fn).is_err() {
                return Err(());
            }
        }
        Ok(())
    }
    ///Internal method to check the contents of this manager when debugging i
    ///enabled.
    #[allow(unused_variables)]
    fn debug_check_slots<F>(&self, slots_fn: &mut F) where F: FnMut(UnsafeRef<T>, usize) -> (usize, usize){
        #[cfg(feature = "debug_suballoc")]
        {
            if log::max_level() != LevelFilter::Debug && log::max_level() != LevelFilter::Trace {
                return;
            }
            let mut idx = self.max_idx.get();
            let mut used_slots = 0;
            let mut free_slots = 0;
            debug!("debug_check_slots: {:p} {:x}", self, idx);
            loop { 
                if let Some((sublevel, real_idx)) = self.get_upper_bound_any(idx){
                    let (sublevel_total_slots, sublevel_free_slots) = slots_fn(sublevel, real_idx);
                    if !self.to_drop.borrow().contains(&real_idx) && !self.to_drop_nested.borrow().contains(&real_idx) {
                        free_slots += sublevel_free_slots;
                        used_slots += sublevel_total_slots - sublevel_free_slots;
                    }
                    debug!("{:x} {} {}", real_idx, sublevel_total_slots, sublevel_free_slots);
                    if real_idx < 1 << self.contents.get_shift_width() {
                        break;
                    }
                    idx = real_idx - (1 << self.contents.get_shift_width());
                }else{
                    break;
                }
            }
            if free_slots != self.available_slots.get() {
                panic!("actual free slots don't match count: {} {} {}", self.available_slots.get(), free_slots, used_slots); 
                //debug!("actual free slots don't match count: {} {} {}", self.available_slots.get(), free_slots, used_slots); 
            }
        }
    }
}

pub fn add_custom_slabs_suballoc<T, A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    //TODO?: allow using different slab sizes
    alloc.add_custom_slab(size_of::<SparseArrayNode<Option<UnsafeRef<T>>>>(), 166, 32, 32, 2)
}
