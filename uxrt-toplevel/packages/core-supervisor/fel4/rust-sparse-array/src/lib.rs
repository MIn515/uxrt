// Copyright 2021 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![cfg_attr(all(not(test), feature = "no_std"), no_std)]

#[cfg(any(test, not(feature = "no_std")))]

///An associative array intended for use in allocators

extern crate core;

#[macro_use]
extern crate log;

macro_rules! array_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_array")]
        debug!($($toks)*);
    })
}

extern crate custom_slab_allocator;
extern crate intrusive_collections;
extern crate alloc;

mod sub_allocator_manager;

pub use sub_allocator_manager::{SubAllocatorManager, add_custom_slabs_suballoc};

use custom_slab_allocator::CustomSlabAllocator;

use core::{
    cell::{Cell, RefCell},
    mem::size_of,
};

use crate::alloc::boxed::Box;
pub use intrusive_collections::UnsafeRef;
use intrusive_collections::{
    intrusive_adapter, rbtree, Bound, KeyAdapter, RBTree,
};

use intrusive_collections::rbtree::CursorMut;
const SUB_ARRAY_BITS: usize = 6;

#[derive(Copy, Clone, Debug, PartialEq)]
enum LookupType {
    Hidden,
    Visible,
    Any,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum GetOperationType {
    Get,
    ChangeVisibility,
    Take,
}

fn get_sub_array_idx(index: usize) -> usize {
    index & ((1 << SUB_ARRAY_BITS) - 1)
}

fn get_indices(index: usize) -> (usize, usize, usize) {
    let sub_array_idx = get_sub_array_idx(index);
    let mut half_idx = 0;
    let mut inner_array_idx = sub_array_idx;
    if sub_array_idx >= (1 << SUB_ARRAY_BITS) / 2 {
        half_idx = 1;
        inner_array_idx = sub_array_idx - ((1 << SUB_ARRAY_BITS) / 2);
    }
    return (half_idx, inner_array_idx, sub_array_idx)
}

///The array node struct. Not visible externally at all.

struct SparseArrayNode<T: Clone + Default> {
    hidden_bitmap: Cell<u64>,
    visible_bitmap: Cell<u64>,
    index: usize,
    //this is split because initializing arrays with Default::default() only
    //works for arrays up to 32 items
    values: RefCell<[[T; (1 << SUB_ARRAY_BITS)/2]; 2]>,
    hidden_link: rbtree::Link,
    visible_link: rbtree::Link,
}

//all SparseArrayNode methods that take an index mask off the upper bits so
//there is no need for SparseArray methods to do it
impl<T: Clone + Default> SparseArrayNode<T> {
    ///Create a new node
    fn new(index: usize) -> SparseArrayNode<T>{
        SparseArrayNode {
            hidden_bitmap: Cell::new(0),
            visible_bitmap: Cell::new(0),
            index,
            //this is split because initializing arrays with the Default::default() only
            //works for arrays up to 32 items
            values: RefCell::new(Default::default()),
            hidden_link: Default::default(),
            visible_link: Default::default(),
        }
    }
    ///Get the bitmap for a specified type of entry
    fn get_bitmap(&self, bitmap_type: LookupType) -> u64 {
        let ret;
        array_debug_println!("SparseArrayNode::get_bitmap");
        match bitmap_type {
            LookupType::Hidden => { ret = self.hidden_bitmap.get() },
            LookupType::Visible => { ret = self.visible_bitmap.get() },
            LookupType::Any => { ret = self.visible_bitmap.get() | self.hidden_bitmap.get() },
        }
        array_debug_println!("SparseArrayNode::get_bitmap return");
        ret
    }
    ///Set the bitmap for a specified type of entry
    fn set_bitmap(&self, bitmap_type: LookupType, bitmap: u64) {
        match bitmap_type {
            LookupType::Hidden => { self.hidden_bitmap.set(bitmap); },
            LookupType::Visible => { self.visible_bitmap.set(bitmap); },
            LookupType::Any => { panic!("SparseArrayNode::set_bitmap called with bitmap type set to Any (this should never happen!)"); },
        }
    }
    ///Marks an index as used for a given type. If the index is already used
    ///for the opposite type it will also be cleared for that type.
    fn set_bit(&self, index: usize, bitmap_type: LookupType) -> (bool, bool) {
        let clear_lookup_type;
        match bitmap_type {
            LookupType::Hidden => { clear_lookup_type = LookupType::Visible; },
            LookupType::Visible => { clear_lookup_type = LookupType::Hidden; },
            LookupType::Any => { panic!("SparseArrayNode::set_bit called with bitmap type set to Any (this should never happen!)"); },
        } 
        let orig_bitmap = self.get_bitmap(bitmap_type);
        let new_bitmap = orig_bitmap | (1 << get_sub_array_idx(index));
        if new_bitmap != orig_bitmap {
            let (cleared, _) = self.clear_bit(index, clear_lookup_type);
            self.set_bitmap(bitmap_type, new_bitmap);
            (!cleared, new_bitmap != 0)
        }else{
            (false, new_bitmap != 0)
        }
    }

    ///Clears an index for a given type
    fn clear_bit(&self, index: usize, bitmap_type: LookupType) -> (bool, bool) {
        let orig_bitmap = self.get_bitmap(bitmap_type);
        let new_bitmap = orig_bitmap & !(1 << get_sub_array_idx(index));
        if new_bitmap != orig_bitmap {
            self.set_bitmap(bitmap_type, new_bitmap);
            (true, new_bitmap != 0)
        }else{
            (false, new_bitmap != 0)
        }
    }

    ///Returns true if an index is set for a given type
    fn get_bit(&self, index: usize, bitmap_type: LookupType) -> bool {
        self.get_bitmap(bitmap_type) & (1 << get_sub_array_idx(index)) != 0
    }

    ///Returns the value for an index if it is present in the bitmap for the
    ///given type, otherwise returns None
    fn get(&self, index: usize, bitmap_type: LookupType) -> Option<T> {
        array_debug_println!("SparseArrayNode::get: {}", index);
        if self.get_bit(index, bitmap_type) {
            let (half_idx, inner_array_idx, _) = get_indices(index);
            let values = self.values.borrow();
            Some(values[half_idx][inner_array_idx].clone())
        }else{
            None
        }
    }
    ///Returns the nearest value of the given type at or below the given 
    ///index; returns None if there is no matching value at or below the index
    fn get_upper_bound(&self, index: usize, bitmap_type: LookupType) -> Option<(T, usize)> { 
        let mut bitmap = self.get_bitmap(bitmap_type);
        let mut upper_bound_idx = get_sub_array_idx(index);
        if index >> SUB_ARRAY_BITS > self.index{
            upper_bound_idx = (1 << SUB_ARRAY_BITS) - 1;
        }
        array_debug_println!("SparseArrayNode::get_upper_bound: {} {} {} {:x}", index, self.index, upper_bound_idx, bitmap);
        if upper_bound_idx < (1 << SUB_ARRAY_BITS) - 1 { 
            bitmap &= (1 << upper_bound_idx + 1) - 1;
        }

        if bitmap == 0 {
            array_debug_println!("no values found");
            None
        }else{
            let sub_array_idx = (1<<SUB_ARRAY_BITS) - bitmap.leading_zeros() as usize - 1;
            array_debug_println!("value found at {}", sub_array_idx);
            let (half_idx, inner_array_idx, _) = get_indices(sub_array_idx as usize);

            let values = self.values.borrow();
            Some((values[half_idx][inner_array_idx].clone(), sub_array_idx))
        }
    }

    ///Gets the first value of the given type
    fn get_first(&self, bitmap_type: LookupType) -> Option<(T, usize)> {
        array_debug_println!("SparseArrayNode::get_first: {:p} {} {:x} {:x}", self, self.index, self.visible_bitmap.get(), self.hidden_bitmap.get());
        let bitmap = self.get_bitmap(bitmap_type);
        if bitmap == 0 {
            None
        }else{
            let values = self.values.borrow_mut();
            let sub_array_idx = bitmap.trailing_zeros() as usize;
            let (half_idx, inner_array_idx, _) = get_indices(sub_array_idx as usize);
            Some((values[half_idx][inner_array_idx].clone(), sub_array_idx))
        }
    }

    ///Stores the value at the given index and type
    fn put(&self, index: usize, value: T, bitmap_type: LookupType) -> bool { 
        let (half_idx, inner_array_idx, sub_array_idx) = get_indices(index);
        let mut values = self.values.borrow_mut();
        values[half_idx][inner_array_idx] = value;
        let ret = self.set_bit(sub_array_idx, bitmap_type);
        if ret.0 { 
            true
        }else{
            false
        }
    }
    ///Clears the bit for the given index in both types and removes the value 
    ///from the internal array
    fn delete(&self, index: usize) -> bool {
        let (half_idx, inner_array_idx, sub_array_idx) = get_indices(index);
        let mut values = self.values.borrow_mut();
        if self.clear_bit(sub_array_idx, LookupType::Visible).0 || self.clear_bit(sub_array_idx, LookupType::Hidden).0 {
            values[half_idx][inner_array_idx] = Default::default();
            true
        }else{
            false
        }
    }
}

impl<T: Clone + Default> Drop for SparseArrayNode<T> {
    fn drop(&mut self) {
        array_debug_println!("dropping node {:p}", self);
    }
}

intrusive_adapter!(VisibleAdapter<T> = UnsafeRef<SparseArrayNode<T>>: SparseArrayNode<T> { visible_link: rbtree::Link } where T: Clone + Default);
intrusive_adapter!(HiddenAdapter<T> = UnsafeRef<SparseArrayNode<T>>: SparseArrayNode<T> { hidden_link: rbtree::Link } where T: Clone + Default);

impl<'a, T: Clone + Default> KeyAdapter<'a> for VisibleAdapter<T> {
    type Key = usize;
    fn get_key(&self, node: &'a SparseArrayNode<T>) -> usize {
        node.index
    }
}

impl<'a, T: Clone + Default> KeyAdapter<'a> for HiddenAdapter<T> {
    type Key = usize;
    fn get_key(&self, node: &'a SparseArrayNode<T>) -> usize {
        node.index
    }
}

///A wrapper around the cursors for both trees that saves the nodes between 
///calls to make lookups quicker (and reduce the amound of boilerplate in
///SparseArray methods)

struct CursorContainer<'a, T: Clone + Default> {
    array: &'a SparseArray<T>,
    visible_node: Option<*const SparseArrayNode<T>>,
    hidden_node: Option<*const SparseArrayNode<T>>,
}

impl<'a, T: Clone + Default> CursorContainer<'a, T> {
    ///Returns true if the cursor is null for the given type
    fn is_null(&self, lookup_type: LookupType) -> bool {
        match lookup_type {
            LookupType::Visible => self.visible_node.is_none(),
            LookupType::Hidden => self.hidden_node.is_none(),
            LookupType::Any => self.visible_node.is_none() || self.hidden_node.is_none(),
        }
    }
    ///Saves the visible cursor (shouldn't be called by methods external to 
    ///this struct)
    fn set_state_visible(&mut self, cursor: &CursorMut<VisibleAdapter<T>>, upper_index: Option<usize>){
        if cursor.is_null() {
            self.visible_node = None;
            self.array.previous_visible_node.set(None);
            self.array.previous_visible_index.set(None);
            self.array.previous_visible_upper_index.set(None);
        }else{
            let visible_node = cursor.get().unwrap();
            self.visible_node = Some(visible_node);
            let index = Some(visible_node.index);
            if !(index == self.array.previous_visible_index.get() && upper_index < self.array.previous_visible_upper_index.get()){
                self.array.previous_visible_upper_index.set(upper_index);
            }
            self.array.previous_visible_node.set(self.visible_node);
            self.array.previous_visible_index.set(index);
        }
    }
    ///Saves the hidden cursor (shouldn't be called by methods external to 
    ///this struct)
    fn set_state_hidden(&mut self, cursor: &CursorMut<HiddenAdapter<T>>, upper_index: Option<usize>){
        if cursor.is_null() {
            self.hidden_node = None;
            self.array.previous_hidden_node.set(None);
            self.array.previous_hidden_index.set(None);
            self.array.previous_hidden_upper_index.set(None);
        }else{
            let hidden_node = cursor.get().unwrap();
            self.hidden_node = Some(hidden_node);
            let index = Some(hidden_node.index);
            if !(index == self.array.previous_hidden_index.get() && upper_index < self.array.previous_hidden_upper_index.get()){
                self.array.previous_hidden_upper_index.set(upper_index);
            }
            self.array.previous_hidden_node.set(self.hidden_node);
            self.array.previous_hidden_index.set(index);
        }
    }
    ///Looks up the node of the given type at the lowest address
    fn front(&mut self, lookup_type: LookupType) {
        match lookup_type {
            LookupType::Visible => { 
                let mut visible = self.array.visible.borrow_mut();
                let cursor = visible.front_mut();
                self.set_state_visible(&cursor, None);
            },
            LookupType::Hidden => {
                let mut hidden = self.array.hidden.borrow_mut();
                let cursor = hidden.front_mut();
                self.set_state_hidden(&cursor, None);
            },
            LookupType::Any => {
                self.front(LookupType::Visible);
                self.front(LookupType::Hidden);
            },
        }
    }
    ///Looks up the node of the given type and address
    fn find(&mut self, index: usize, lookup_type: LookupType) {
        match lookup_type {
            LookupType::Visible => {
                let mut visible = self.array.visible.borrow_mut();
                let cursor;
                if self.array.previous_visible_index.get() == Some(index) {
                    cursor = unsafe { visible.cursor_mut_from_ptr(self.array.previous_visible_node.get().unwrap()) };
                }else{
                    cursor = visible.find_mut(&index);

                }
                self.set_state_visible(&cursor, None);
            },
            LookupType::Hidden => {
                let mut hidden = self.array.hidden.borrow_mut();
                let cursor;
                if self.array.previous_hidden_index.get() == Some(index) {
                    cursor = unsafe { hidden.cursor_mut_from_ptr(self.array.previous_hidden_node.get().unwrap()) };
                }else{
                    cursor = hidden.find_mut(&index);

                }
                self.set_state_hidden(&cursor, None);
            },
            LookupType::Any => {
                self.find(index, LookupType::Visible);
                self.find(index, LookupType::Hidden);
            },
        }
    }
    ///Looks up the closest node of the given type at or below the address
    fn find_upper_bound(&mut self, index: usize, lookup_type: LookupType) {
        match lookup_type {
            LookupType::Visible => {
                let mut visible = self.array.visible.borrow_mut();
                let cursor;
                if self.array.previous_visible_upper_index.get().is_some() && 
                        index <= self.array.previous_hidden_upper_index.get().unwrap() && 
                        index >= self.array.previous_hidden_index.get().unwrap() {
                    cursor = unsafe { visible.cursor_mut_from_ptr(self.array.previous_visible_node.get().unwrap()) };
                }else{
                    cursor = visible.upper_bound_mut(Bound::Included(&index));
                }
                self.set_state_visible(&cursor, None);
            },
            LookupType::Hidden => {
                let mut hidden = self.array.hidden.borrow_mut();
                let cursor;
                if self.array.previous_hidden_upper_index.get().is_some() && 
                        index <= self.array.previous_hidden_upper_index.get().unwrap() && 
                        index >= self.array.previous_hidden_index.get().unwrap() {
                    cursor = unsafe { hidden.cursor_mut_from_ptr(self.array.previous_hidden_node.get().unwrap()) };
                }else{
                    cursor = hidden.upper_bound_mut(Bound::Included(&index));
                }
                self.set_state_hidden(&cursor, None);
            },
            LookupType::Any => {
                self.find_upper_bound(index, LookupType::Visible);
                self.find_upper_bound(index, LookupType::Hidden);
            },
        }
    }
    ///Gets the item of the given type at the current position
    fn get(&self, lookup_type: LookupType) -> Option<&SparseArrayNode<T>> {
        match lookup_type {
            LookupType::Visible => {
                if self.visible_node.is_none() {
                    None
                }else{
                    unsafe { Some(&*self.visible_node.unwrap()) }
                }
            },
            LookupType::Hidden => {
                if self.hidden_node.is_none() {
                    None
                }else{
                    unsafe { Some(&*self.hidden_node.unwrap()) }
                }
            },
            LookupType::Any => {
                let visible_node = self.get(LookupType::Visible);
                if visible_node.is_none() {
                    self.get(LookupType::Hidden)
                }else{
                    visible_node
                }
            },
        }
    }

    ///Moves to the node below the current one
    fn move_prev(&mut self, lookup_type: LookupType) {
        match lookup_type {
            LookupType::Visible => {
                let mut visible = self.array.visible.borrow_mut();
                let mut cursor;
                if self.visible_node.is_some() {
                    cursor = unsafe { visible.cursor_mut_from_ptr(self.visible_node.unwrap()) };
                }else{
                    cursor = visible.cursor_mut();
                }
                cursor.move_prev();
                if cursor.is_null() {
                    self.visible_node = None;
                }else{
                    self.visible_node = Some(cursor.get().unwrap());
                }
            },
            LookupType::Hidden => {
                let mut hidden = self.array.hidden.borrow_mut();
                let mut cursor;
                if self.hidden_node.is_some() {
                    cursor = unsafe { hidden.cursor_mut_from_ptr(self.hidden_node.unwrap()) };
                }else{
                    cursor = hidden.cursor_mut();
                }
                cursor.move_prev();
                if cursor.is_null() {
                    self.hidden_node = None;
                }else{
                    self.hidden_node = Some(cursor.get().unwrap());
                }
            },
            LookupType::Any => {
                panic!("CursorContainer.get_prev called with LookupType::Any (this shouldn't happen!");
            },
        }
    }


    ///Removes the current node
    fn remove(&mut self, lookup_type: LookupType) -> Option<UnsafeRef<SparseArrayNode<T>>> {
        match lookup_type {
            LookupType::Visible => {
                self.array.previous_visible_index.set(None);
                self.array.previous_visible_node.set(None);
                self.array.previous_visible_upper_index.set(None);
                if self.visible_node.is_none() {
                    None
                }else{
                    let mut visible = self.array.visible.borrow_mut();
                    let mut cursor = unsafe { visible.cursor_mut_from_ptr(self.visible_node.unwrap()) };
                    let ret = cursor.remove();
                    if cursor.is_null() {
                        self.visible_node = None;
                    }else{
                        self.visible_node = Some(cursor.get().unwrap());
                    }
                    ret
                }
            },
            LookupType::Hidden => {
                self.array.previous_hidden_index.set(None);
                self.array.previous_hidden_node.set(None);
                self.array.previous_hidden_upper_index.set(None);
                if self.hidden_node.is_none() {
                    None
                }else{
                    let mut hidden = self.array.hidden.borrow_mut();
                    let mut cursor = unsafe { hidden.cursor_mut_from_ptr(self.hidden_node.unwrap()) };
                    let ret = cursor.remove();
                    if cursor.is_null() {
                        self.hidden_node = None;
                    }else{
                        self.hidden_node = Some(cursor.get().unwrap());
                    }
                    ret
                }
            },
            LookupType::Any => {
                panic!("CursorContainer.remove called with LookupType::Any (this shouldn't happen!");
            },
        }
    }
    ///Resets the saved visible node if necessary
    fn check_reset_visible(&mut self, node: UnsafeRef<SparseArrayNode<T>>){
        if self.array.previous_visible_upper_index.get().is_some() &&
            node.index >= self.array.previous_visible_index.get().unwrap() && 
            node.index <= self.array.previous_visible_upper_index.get().unwrap() {
                self.array.previous_visible_upper_index.set(None);
        }
    }
    ///Resets the saved hidden node if necessary
    fn check_reset_hidden(&mut self, node: UnsafeRef<SparseArrayNode<T>>){
        if self.array.previous_hidden_upper_index.get().is_some() &&
            node.index >= self.array.previous_hidden_index.get().unwrap() && 
            node.index <= self.array.previous_hidden_upper_index.get().unwrap() {
                self.array.previous_hidden_upper_index.set(None);
        }
    }
    ///Inserts a node before the current one (the address must be lower than
    ///that of the current one but higher than any that precede it
    fn insert_before(&mut self, node: UnsafeRef<SparseArrayNode<T>>, lookup_type: LookupType) {
        match lookup_type {
            LookupType::Visible => {
                let mut visible = self.array.visible.borrow_mut();
                let mut cursor;
                self.check_reset_visible(node.clone());
                if self.visible_node.is_some() {
                    cursor = unsafe { visible.cursor_mut_from_ptr(self.visible_node.unwrap()) };
                }else{
                    cursor = visible.cursor_mut();
                }
                cursor.insert_before(node);
            },
            LookupType::Hidden => {
                let mut hidden = self.array.hidden.borrow_mut();
                let mut cursor;
                self.check_reset_hidden(node.clone());
                if self.hidden_node.is_some() {
                    cursor = unsafe { hidden.cursor_mut_from_ptr(self.hidden_node.unwrap()) };
                }else{
                    cursor = hidden.cursor_mut();
                }
                cursor.insert_before(node);
            },
            LookupType::Any => {
                panic!("CursorContainer.insert_before called with LookupType::Any (this shouldn't happen!");
            },
        }
    }

    ///Inserts a node after the current one (the address must be higher than
    ///that of the current one but lower than any that follow it
    fn insert_after(&mut self, node: UnsafeRef<SparseArrayNode<T>>, lookup_type: LookupType) {
        match lookup_type {
            LookupType::Visible => {
                let mut visible = self.array.visible.borrow_mut();
                let mut cursor;
                self.check_reset_visible(node.clone());
                if self.visible_node.is_some() {
                    cursor = unsafe { visible.cursor_mut_from_ptr(self.visible_node.unwrap()) };
                }else{
                    cursor = visible.cursor_mut();
                }
                cursor.insert_after(node);
            },
            LookupType::Hidden => {
                let mut hidden = self.array.hidden.borrow_mut();
                let mut cursor;
                self.check_reset_hidden(node.clone());
                if self.hidden_node.is_some() {
                    cursor = unsafe { hidden.cursor_mut_from_ptr(self.hidden_node.unwrap()) };
                }else{
                    cursor = hidden.cursor_mut();
                } 
                cursor.insert_after(node);
            },
            LookupType::Any => {
                panic!("CursorContainer.insert_after called with LookupType::Any (this shouldn't happen!");
            },
        }
    }

    ///Inserts a node at the correct position. Both cursors are reset to null.
    fn insert(&mut self, node: UnsafeRef<SparseArrayNode<T>>, lookup_type: LookupType) {
        match lookup_type {
            LookupType::Visible => {
                let mut visible = self.array.visible.borrow_mut();
                let mut cursor = visible.cursor_mut();
                self.array.previous_visible_index.set(None);
                self.array.previous_visible_upper_index.set(None);
                cursor.insert(node);
            },
            LookupType::Hidden => {
                let mut hidden = self.array.hidden.borrow_mut();
                let mut cursor = hidden.cursor_mut();
                self.array.previous_hidden_index.set(None);
                self.array.previous_hidden_upper_index.set(None);

                cursor.insert(node);
            },
            LookupType::Any => {
                panic!("CursorContainer.insert called with LookupType::Any (this shouldn't happen!");
            },
        }
    }
}

///This is a sparse associative array with usize keys (based on a red-black
///tree of small fixed-size arrays) intended for use in allocators. It is
///possible to hide items from the "regular" accessor methods. This allows an
///allocator to track which items are free and used without having to use 
///multiple arrays (which incurs extra allocations).
///
///All mutability is internal using cells, so all methods take &self
///regardless of whether they mutate the array. Heap allocation occurs only
///while no mutable borrows are active, so this is safe to use in heap
///allocators (as long as they separate refilling/dropping from actually 
///fulfilling allocations/deallocations). `OuterMutableSparseArray` is a
///version of this with mutation methods that take &mut self.

pub struct SparseArray<T: Clone + Default> {
    visible_items: Cell<usize>,
    hidden_items: Cell<usize>,
    visible: RefCell<RBTree<VisibleAdapter<T>>>,
    hidden: RefCell<RBTree<HiddenAdapter<T>>>,
    previous_visible_upper_index: Cell<Option<usize>>,
    previous_hidden_upper_index: Cell<Option<usize>>,
    previous_visible_index: Cell<Option<usize>>,
    previous_hidden_index: Cell<Option<usize>>,
    previous_visible_node: Cell<Option<*const SparseArrayNode<T>>>,
    previous_hidden_node: Cell<Option<*const SparseArrayNode<T>>>,
}

impl<'a, T: Clone + Default> SparseArray<T> {
    ///Creates a new empty array
    pub fn new() -> SparseArray<T> {
        SparseArray {
            visible_items: Cell::new(0),
            hidden_items: Cell::new(0),
            visible: Default::default(),
            hidden: Default::default(),
            previous_visible_upper_index: Cell::new(None),
            previous_hidden_upper_index: Cell::new(None),
            previous_visible_index: Cell::new(None),
            previous_hidden_index: Cell::new(None),
            previous_visible_node: Cell::new(None),
            previous_hidden_node: Cell::new(None),
        }
    }
    ///Gets the total number of items (both hidden and visible)
    pub fn len(&self) -> usize {
        self.visible_items.get() + self.hidden_items.get()
    }
    ///Gets the total number of visible items
    pub fn visible_len(&self) -> usize {
        self.visible_items.get()
    }
    ///Gets the total number of hidden items
    pub fn hidden_len(&self) -> usize {
        self.hidden_items.get()
    }

    ///Internal method to get a new cursor container
    fn cursors(&self) -> CursorContainer<T> {
        CursorContainer {
            array: self,
            hidden_node: None,
            visible_node: None,
        }
    }

    ///Internal method to link a new sub-array into one of the trees
    fn link_sub_array(&self, index: usize, cursors: &mut CursorContainer<T>, lookup_type: LookupType){
        array_debug_println!("link_sub_array: {} {:?}", index, lookup_type);
        let tree_idx = index >> SUB_ARRAY_BITS;
        let src_lookup_type;
        match lookup_type {
            LookupType::Visible => {
                src_lookup_type = LookupType::Hidden;
            },
            LookupType::Hidden => {
                src_lookup_type = LookupType::Visible;
            },
            _ => { panic!("link_sub_array called with invalid lookup type (this shouldn't happen!)");}
        }
        if cursors.is_null(src_lookup_type) || cursors.get(src_lookup_type).unwrap().index != tree_idx {
            panic!("link_sub_array called with {:?} as source lookup type but node isn't present in source sub-array (this shouldn't happen!)", src_lookup_type);
        }
        let src_ref = cursors.remove(src_lookup_type).unwrap();
        let dest_ref = src_ref.clone();
        cursors.insert_before(src_ref, src_lookup_type);
        if cursors.is_null(lookup_type) {
            array_debug_println!("destination cursor null");
            cursors.find_upper_bound(tree_idx, lookup_type);
        }
        if cursors.is_null(lookup_type) || cursors.get(lookup_type).unwrap().index != tree_idx {
            array_debug_println!("linked node into destination tree");
            cursors.insert_after(dest_ref, lookup_type);
        } 
    }

    ///Internal method to remove a sub-array from one or both trees
    fn remove_sub_array(&self, index: usize, cursors: &mut CursorContainer<T>, lookup_type: LookupType){
        array_debug_println!("remove_sub_array: {} {:?}", index, lookup_type); 
        let visible = lookup_type == LookupType::Visible || lookup_type == LookupType::Any;
        let hidden = lookup_type == LookupType::Hidden || lookup_type == LookupType::Any;
        if visible && (cursors.is_null(LookupType::Visible) || cursors.get(LookupType::Visible).unwrap().index != index) {
            cursors.find(index, LookupType::Visible);
        }
        if hidden && (cursors.is_null(LookupType::Hidden) || cursors.get(LookupType::Hidden).unwrap().index != index) {
            cursors.find(index, LookupType::Hidden);
        }
        let mut node = None;
        if visible && !cursors.is_null(LookupType::Visible){
            node = cursors.get(LookupType::Visible);
        }
        if hidden && !cursors.is_null(LookupType::Hidden){
            node = cursors.get(LookupType::Hidden);
        }

        if node.is_none() {
            array_debug_println!("node not found in either tree; nothing to remove");
            return;
        }
        
        array_debug_println!("SparseArray::remove_sub_array bitmaps");
        let hidden_bitmap = node.unwrap().hidden_bitmap.get();
        let visible_bitmap = node.unwrap().visible_bitmap.get();
        array_debug_println!("SparseArray::remove_sub_array bitmaps done");

        array_debug_println!("remove_sub_array: {:p} {} {} {} {} {}", node.as_ref().unwrap(), node.unwrap().index, visible, hidden, cursors.is_null(LookupType::Visible), cursors.is_null(LookupType::Hidden));
        array_debug_println!("bitmaps: {:x} {:x}", hidden_bitmap, visible_bitmap);
        let mut node_ref = None;
        if !cursors.is_null(LookupType::Visible) && visible_bitmap == 0 {
            array_debug_println!("node contains no more visible items; removed from visible tree");
            node_ref = cursors.remove(LookupType::Visible);
        }
        if !cursors.is_null(LookupType::Hidden) && hidden_bitmap == 0 {
            array_debug_println!("node contains no more hidden items; removed from hidden tree");
            node_ref = cursors.remove(LookupType::Hidden);
        }
        array_debug_println!("node_ref: {}", node_ref.is_none()); 
        array_debug_println!("index: {}", node_ref.as_ref().unwrap().index); 
        if hidden_bitmap == 0 && visible_bitmap == 0 && node_ref.is_some() {
            array_debug_println!("dropping node since it is empty");
            unsafe { drop(UnsafeRef::into_box(node_ref.unwrap())); }
        }
    }

    ///Internal method to increment item counts
    fn increment_items(&self, lookup_type: LookupType){
        match lookup_type {
            LookupType::Hidden => { self.hidden_items.set(self.hidden_items.get() + 1); },
            LookupType::Visible => { self.visible_items.set(self.visible_items.get() + 1); },
            _ => { panic!("increment_items called with invalid lookup type (this shouldn't happen!)"); },
        }
    }

    ///Internal method to decrement item counts
    fn decrement_items(&self, lookup_type: LookupType){
        match lookup_type {
            LookupType::Hidden => { self.hidden_items.set(self.hidden_items.get() - 1); },
            LookupType::Visible => { self.visible_items.set(self.visible_items.get() - 1); },
            _ => { panic!("decrement_items called with invalid lookup type (this shouldn't happen!)"); },
        }
    }

    ///Internal method to get an item and optionally remove it; called in 
    ///get_take_common and get_take_first_common when a sub-array is found
    fn get_take_inner_common(&self, index: usize, cursors: &mut CursorContainer<T>, operation_type: GetOperationType, lookup_type: LookupType) -> T {
        let ret;

        let mut remove_lookup_type = lookup_type;
        if operation_type == GetOperationType::Take {
            remove_lookup_type = LookupType::Any;
        }
        let sub_array_opt = cursors.get(lookup_type);
        if sub_array_opt.is_none() {
            array_debug_println!("no node found");
            return Default::default();
        }
        let sub_array = sub_array_opt.unwrap();
        let mut bitmap = sub_array.get_bitmap(remove_lookup_type);
        let value = sub_array.get(index, lookup_type);
        array_debug_println!("sub_array: {:p} {}", sub_array, sub_array.index);
        if value.is_some() {
            array_debug_println!("value found");
            ret = value.unwrap();
            if operation_type == GetOperationType::Take {
                let mut decrement_lookup_type = lookup_type;
                if lookup_type == LookupType::Any {
                    if sub_array.get_bit(index, LookupType::Hidden){
                        decrement_lookup_type = LookupType::Hidden;
                    }else{
                        decrement_lookup_type = LookupType::Visible;
                    }
                }
                if sub_array.delete(index) {
                    array_debug_println!("decrementing item count");
                    self.decrement_items(decrement_lookup_type);
                }
                bitmap = sub_array.get_bitmap(lookup_type);
            }else if operation_type == GetOperationType::ChangeVisibility {
                let dest_lookup_type;
                match lookup_type {
                    LookupType::Hidden => { dest_lookup_type = LookupType::Visible },
                    LookupType::Visible => { dest_lookup_type = LookupType::Hidden },
                    _ => { panic!("invalid lookup type when changing visibility (this should never happen!)"); },
                }
                let orig_dest_bitmap = sub_array.get_bitmap(dest_lookup_type);
                let orig_bitmap = sub_array.get_bitmap(lookup_type);
                sub_array.set_bit(index, dest_lookup_type);
                bitmap = sub_array.get_bitmap(lookup_type);
                if bitmap != orig_bitmap {
                    self.decrement_items(lookup_type);
                    self.increment_items(dest_lookup_type);
                }
                if orig_dest_bitmap == 0 {
                    array_debug_println!("linking sub-array into destination tree since it wasn't present there already");
                    self.link_sub_array(index, cursors, dest_lookup_type);
                }
            }
        }else{
            array_debug_println!("no value found");
            ret = Default::default();
        }
        if bitmap == 0 {
            array_debug_println!("removing node, since it has no values left, lookup type: {:?}", lookup_type);
            self.remove_sub_array(index >> SUB_ARRAY_BITS, cursors, remove_lookup_type);
        }
        ret
    }

    ///Internal method that provides the underlying implementation of get/take
    ///methods
    fn get_take_common(&self, index: usize, operation_type: GetOperationType, lookup_type: LookupType) -> T {
        array_debug_println!("get_take_common: {:p} {} {:?} {:?}", self, index, operation_type, lookup_type);
        let tree_idx = index >> SUB_ARRAY_BITS;
        let mut cursors = self.cursors();
        if lookup_type == LookupType::Visible || lookup_type == LookupType::Any {
            cursors.find(tree_idx, LookupType::Visible);
        }
        if lookup_type == LookupType::Hidden || lookup_type == LookupType::Any && cursors.is_null(LookupType::Hidden) {
            cursors.find(tree_idx, LookupType::Hidden);
        }
        self.get_take_inner_common(index, &mut cursors, operation_type, lookup_type)
    }

    ///Returns the visible item at the specified index
    ///
    ///If no visible item is present, the default value for the type will be 
    ///returned.
    pub fn get(&self, index: usize) -> T {
        self.get_take_common(index, GetOperationType::Get, LookupType::Visible)
    }
    ///Removes the visible item at the specified index from the array and
    ///returns it
    ///
    ///If no visible item is present, the default value for the type will be
    ///returned (if there is a hidden item at the index it will not be
    ///removed).
    pub fn take(&self, index: usize) -> T {
        array_debug_println!("take: {:p} {:x}", self, index);
        self.get_take_common(index, GetOperationType::Take, LookupType::Visible)
    }
    ///Returns the hidden item at the specified index
    ///
    ///If no hidden item is present, the default value for the type will be 
    ///returned.
    pub fn get_hidden(&self, index: usize) -> T {
        self.get_take_common(index, GetOperationType::Get, LookupType::Hidden)
    }
    ///Removes the hidden item at the specified index from the array and
    ///returns it
    ///
    ///If no hidden item is present, the default value for the type will be
    ///returned (if there is a hidden item at the index it will not be
    ///removed).
    pub fn take_hidden(&self, index: usize) -> T {
        array_debug_println!("take_hidden: {:p} {:x}", self, index);
        self.get_take_common(index, GetOperationType::Take, LookupType::Hidden)
    }
    ///Returns the item at the specified index regardless of its
    ///visible/hidden status.
    ///
    ///If no item is present, the default value for the type will be returned.
    pub fn get_any(&self, index: usize) -> T {
        self.get_take_common(index, GetOperationType::Get, LookupType::Any)
    }
    ///Removes the item at the specified index from the array and returns it 
    ///regardless of its visible/hidden status.
    ///
    ///If no item is present, the default value for the type will be returned.
    pub fn take_any(&self, index: usize) -> T {
        array_debug_println!("take_any: {:p} {:x}", self, index);
        self.get_take_common(index, GetOperationType::Take, LookupType::Any)
    }
    ///Makes the hidden item at the specified index visible and returns it
    ///
    ///If no hidden item is present, the default value for the type will be
    ///returned.
    pub fn show(&self, index: usize) -> T {
        array_debug_println!("show: {:p} {:x}", self, index);
        self.get_take_common(index, GetOperationType::ChangeVisibility, LookupType::Hidden)
    }
    ///Makes the visible item at the specified index visible and returns it
    ///
    ///If no visible item is present, the default value for the type will be
    ///returned.
    pub fn hide(&self, index: usize) -> T {
        array_debug_println!("hide: {:p} {:x}", self, index);
        let ret = self.get_take_common(index, GetOperationType::ChangeVisibility, LookupType::Visible);
        array_debug_println!("hide: done");
        ret
    }

    ///Internal method providing the underlying implementation of 
    ///get_first/take_first methods
    fn get_take_first_common(&self, operation_type: GetOperationType, mut lookup_type: LookupType) -> (usize, T) {
        array_debug_println!("get_take_first_common: {:p} {:?} {:?}", self, operation_type, lookup_type);

        let mut cursors = self.cursors();
        if lookup_type == LookupType::Hidden || lookup_type == LookupType::Any {
            cursors.front(LookupType::Hidden);
        }
        if lookup_type == LookupType::Visible || lookup_type == LookupType::Any {
            cursors.front(LookupType::Visible);
        }
        if lookup_type == LookupType::Any {
            if cursors.is_null(LookupType::Hidden) {
                array_debug_println!("hidden is null");
                lookup_type = LookupType::Visible;
            }else if cursors.is_null(LookupType::Visible) {
                array_debug_println!("visible is null");
                lookup_type = LookupType::Hidden;
            }
        }
        if cursors.is_null(lookup_type) {
            array_debug_println!("tree empty");
            (0, Default::default())
        }else{
            array_debug_println!("tree non-empty");
            if lookup_type == LookupType::Any {
                let hidden_sub_array = cursors.get(LookupType::Hidden).unwrap();
                let visible_sub_array = cursors.get(LookupType::Visible).unwrap();

                if hidden_sub_array.index < visible_sub_array.index {
                    array_debug_println!("using hidden node");
                    lookup_type = LookupType::Hidden;
                }else{
                    array_debug_println!("using visible node");
                    lookup_type = LookupType::Visible;
                }
            }
            array_debug_println!("lookup type: {:?}", lookup_type);
            let sub_array = cursors.get(lookup_type).unwrap();
            array_debug_println!("sub_array.index: {}", sub_array.index);
            let (_, sub_array_idx) = sub_array.get_first(lookup_type).expect("first sub-array contains no values of the requested type");
            let index = (sub_array.index << SUB_ARRAY_BITS) | sub_array_idx as usize;
            (index, self.get_take_inner_common(index, &mut cursors, operation_type, lookup_type))
        }
    }

    ///Returns the first visible item and its index.
    ///
    ///If there are no visible items, the default value for the type will be
    ///returned.
    pub fn get_first(&self) -> (usize, T) {
        self.get_take_first_common(GetOperationType::Get, LookupType::Visible)
    }
    ///Removes the first visible item from the array and returns it along with
    ///its index.
    ///
    ///If there are no visible items, the default value for the type will be
    ///returned.
    pub fn take_first(&self) -> (usize, T) {
        array_debug_println!("take_first: {:p}", self);
        self.get_take_first_common(GetOperationType::Take, LookupType::Visible)
    }
    ///Returns the first item and its index regardless of its visible/hidden
    ///status.
    ///
    ///If the array is empty, the default value for the type will be returned.
    pub fn get_first_any(&self) -> (usize, T) {
        self.get_take_first_common(GetOperationType::Get, LookupType::Any)
    }
    ///Removes the first item from the array and returns it along with its
    ///index regardless of its visible/hidden status.
    ///
    ///If the array is empty, the default value for the type will be returned.
    pub fn take_first_any(&self) -> (usize, T) {
        array_debug_println!("take_first_any: {:p}", self);
        self.get_take_first_common(GetOperationType::Take, LookupType::Any)
    }
    ///Returns the first hidden item and its index.
    ///
    ///If there are no hidden items, the default value for the type will be
    ///returned.
    pub fn get_first_hidden(&self) -> (usize, T) {
        self.get_take_first_common(GetOperationType::Get, LookupType::Hidden)
    }
    ///Removes the first hidden item from the array and returns it along with 
    ///its index.
    ///
    ///If there are no hidden items, the default value for the type will be
    ///returned.
    pub fn take_first_hidden(&self) -> (usize, T) {
        array_debug_println!("take_first_hidden: {:p}", self);
        self.get_take_first_common(GetOperationType::Take, LookupType::Hidden)
    }
    ///Makes the first hidden item in the array visible and returns it along 
    ///with its index
    ///
    ///If there are no hidden items, the default value for the type will be
    ///returned.
    pub fn show_first(&self) -> (usize, T) {
        array_debug_println!("show_first: {:p}", self);
        self.get_take_first_common(GetOperationType::ChangeVisibility, LookupType::Hidden)
    }
    ///Makes the first visible item in the array hidden and returns it along 
    ///with its index
    ///
    ///If there are no hidden items, the default value for the type will be
    ///returned.
    pub fn hide_first(&self) -> (usize, T) {
        array_debug_println!("hide_first: {:p}", self);
        self.get_take_first_common(GetOperationType::ChangeVisibility, LookupType::Visible)
    }
    ///Internal method providing the underlying implementation of 
    ///get_upper_bound methods.
    fn get_upper_bound_common(&self, index: usize, lookup_type: LookupType) -> (usize, T) {
        array_debug_println!("get_upper_bound_common: {:p} {:?} {}", self, lookup_type, index);
        let ret;
        if lookup_type == LookupType::Any {
            let visible_result = self.get_upper_bound_inner_common(index, LookupType::Visible);
            let hidden_result = self.get_upper_bound_inner_common(index, LookupType::Hidden);
            if visible_result.is_some() && hidden_result.is_some() {

                if visible_result.as_ref().unwrap().0 > hidden_result.as_ref().unwrap().0 {
                    ret = visible_result;
                }else{
                    ret = hidden_result;
                }
            }else if visible_result.is_some(){
                ret = visible_result;
            }else if hidden_result.is_some(){
                ret = hidden_result;
            }else{
                ret = None;
            }
        }else{
            ret = self.get_upper_bound_inner_common(index, lookup_type);
        }
        if ret.is_some() {
            return ret.unwrap();
        }else{
            return (0, Default::default());
        }
    }

    ///Internal method providing the inner implementation of 
    ///get_upper_bound methods (only operating on a single tree).
    fn get_upper_bound_inner_common(&self, index: usize, lookup_type: LookupType) -> Option<(usize, T)> {
        let tree_idx = index >> SUB_ARRAY_BITS;

        let mut cursors = self.cursors();
        cursors.find_upper_bound(tree_idx, lookup_type);
        if cursors.is_null(lookup_type) {
            array_debug_println!("tree empty");
            None
        }else{
            array_debug_println!("tree non-empty");
            array_debug_println!("lookup type: {:?}", lookup_type);
            let mut sub_array = cursors.get(lookup_type).unwrap();
            array_debug_println!("sub_array.index: {}", sub_array.index);
            let mut res = sub_array.get_upper_bound(index, lookup_type);
            if res.is_none() {
                cursors.move_prev(lookup_type);
                if cursors.is_null(lookup_type) {
                    return None;
                }
                sub_array = cursors.get(lookup_type).unwrap();
                res = sub_array.get_upper_bound(index, lookup_type);
            }
            if res.is_some() {
                let (value, sub_array_idx) = res.unwrap();
                let index = (sub_array.index << SUB_ARRAY_BITS) | sub_array_idx as usize;
                array_debug_println!("{} {} {}", sub_array.index, sub_array_idx, index);
                Some((index, value))
            }else{
                None
            }
        }
    }
    ///Returns the nearest visible item at or below the specified index
    ///
    ///If no visible item is present at or below the index, the default value 
    ///for the type will be returned.
    pub fn get_upper_bound(&self, index: usize) -> (usize, T) {
        self.get_upper_bound_common(index, LookupType::Visible)
    }
    ///Returns the nearest hidden item at or below the specified index
    ///
    ///If no hidden item is present at or below the index, the default value 
    ///for the type will be returned.
    pub fn get_upper_bound_hidden(&self, index: usize) -> (usize, T) {
        self.get_upper_bound_common(index, LookupType::Hidden)
    }
    ///Returns the nearest item at or below the specified index regardless of
    ///its visible/hidden status
    ///
    ///If no item is present at or below the index, the default value for the
    ///type will be returned.
    pub fn get_upper_bound_any(&self, index: usize) -> (usize, T) {
        self.get_upper_bound_common(index, LookupType::Any)
    }

    ///Adds an item to the array. 
    ///
    ///Items will always be visible when added (even if there was a hidden
    ///item at the index before)
    pub fn put(&self, index: usize, value: T){ 
        let tree_idx = index >> SUB_ARRAY_BITS;
        array_debug_println!("put: {:p} {:x} {} {}", self, index, tree_idx, self.len());
        array_debug_println!("put: {:p} {:x}", self, index);
        let mut cursors = self.cursors();
        cursors.find_upper_bound(tree_idx, LookupType::Visible);
        let visible_found = !cursors.is_null(LookupType::Visible) && cursors.get(LookupType::Visible).unwrap().index == tree_idx;

        if !visible_found {
            array_debug_println!("node not found in visible tree; looking for it in hidden tree");
            cursors.find_upper_bound(tree_idx, LookupType::Hidden);
        }
        let hidden_found = !cursors.is_null(LookupType::Hidden) && cursors.get(LookupType::Hidden).unwrap().index == tree_idx;

        let filled;
        let was_hidden;

        if !visible_found && !hidden_found {
            array_debug_println!("adding new node");
            let sub_array = SparseArrayNode::<T>::new(tree_idx);
            was_hidden = false;
            filled = sub_array.put(index, value, LookupType::Visible);
            let boxed_array = Box::new(sub_array);
            array_debug_println!("allocated new node: {:p} {:p}", boxed_array, self);
            cursors.insert(UnsafeRef::from_box(boxed_array), LookupType::Visible);
        }else{
            array_debug_println!("using existing node");
            let mut lookup_type = LookupType::Visible;
            if hidden_found {
                array_debug_println!("node is from hidden tree");
                lookup_type = LookupType::Hidden;
            }
            let sub_array = cursors.get(lookup_type).unwrap();
            let old_hidden_bitmap = sub_array.get_bitmap(LookupType::Hidden);
            filled = sub_array.put(index, value, LookupType::Visible);
            let new_hidden_bitmap = sub_array.get_bitmap(LookupType::Hidden);
            array_debug_println!("bitmap: {:x} {:x}", old_hidden_bitmap, new_hidden_bitmap);
            if hidden_found {
                self.link_sub_array(index, &mut cursors, LookupType::Visible);
            }
            was_hidden = old_hidden_bitmap != new_hidden_bitmap; 
            if new_hidden_bitmap == 0 && was_hidden {
                array_debug_println!("node no longer contains any hidden items; removing it from hidden tree");
                self.remove_sub_array(tree_idx, &mut cursors, LookupType::Hidden);
            }
        }

        if filled {
            array_debug_println!("index was previously empty; incrementing item count");
            self.increment_items(LookupType::Visible);
        }else if was_hidden {
            self.decrement_items(LookupType::Hidden);
            self.increment_items(LookupType::Visible);
        }
        array_debug_println!("put: done");
    }
}

impl<T: Clone + Default> Drop for SparseArray<T> {
    fn drop(&mut self) {
        array_debug_println!("SparseArray::drop: {:p}", self);
        let mut cursors = self.cursors();
        loop {
            cursors.front(LookupType::Any);
            let node_opt = cursors.get(LookupType::Any);
            if node_opt.is_none(){
                array_debug_println!("end of array");
                break;
            }
            let node = node_opt.unwrap();
            node.visible_bitmap.set(0);
            node.hidden_bitmap.set(0);
            let index = node.index;
            array_debug_println!("SparseArray::drop: index: {}", index);
            self.remove_sub_array(index, &mut cursors, LookupType::Any);
        }
    }
}


///Wrapper for SparseArray that shifts out the low-order bits from indices 
///for uses where they are all zero (attempting to add an item with non-zero
///low-order bits that would be dropped will cause a panic).
///
///All of the methods other than get_shift_width are the same as their
///SparseArray equivalents
pub struct ShiftedSparseArray<T: Clone + Default> {
    shift_width: u32,
    contents: SparseArray<T>,
}

impl<T: Clone + Default> ShiftedSparseArray<T> {
    ///Return a new ShiftedSparseArray
    ///
    ///The address will be shifted right by `shift_width`.
    pub fn new(shift_width: u32) -> ShiftedSparseArray<T> {
        ShiftedSparseArray {
            shift_width,
            contents: SparseArray::new(),
        }
    }
    ///Gets the shift width
    pub fn get_shift_width(&self) -> u32 {
        self.shift_width
    }
    pub fn len(&self) -> usize {
        self.contents.len()
    }
    pub fn visible_len(&self) -> usize {
        self.contents.visible_len()
    }
    pub fn hidden_len(&self) -> usize {
        self.contents.hidden_len()
    }
    ///Internal method for shifting index arguments
    fn shr(&self, index: usize) -> usize {
        if index.trailing_zeros() < self.shift_width {
            panic!("attempt to use index {:x} with non-zero low-order bits that would be removed by shifting by {}", index, self.shift_width);
        }
        index >> self.shift_width
    }
    pub fn get(&self, index: usize) -> T {
        self.contents.get(self.shr(index))
    }
    pub fn take(&self, index: usize) -> T {
        self.contents.take(self.shr(index))
    }

    pub fn get_hidden(&self, index: usize) -> T {
        self.contents.get_hidden(self.shr(index))
    }
    pub fn take_hidden(&self, index: usize) -> T {
        self.contents.take_hidden(self.shr(index))
    }
    pub fn get_any(&self, index: usize) -> T {
        self.contents.get_any(self.shr(index))
    }
    pub fn take_any(&self, index: usize) -> T {
        self.contents.take_any(self.shr(index))
    }
    pub fn show(&self, index: usize) -> T {
        self.contents.show(self.shr(index))
    }
    pub fn hide(&self, index: usize) -> T {
        self.contents.hide(self.shr(index))
    }
    ///Internal method for shifting returned indices
    fn res_shr(&self, res: (usize, T)) -> (usize, T) {
        (res.0 << self.shift_width, res.1)
    }
    pub fn get_first(&self) -> (usize, T) {
        self.res_shr(self.contents.get_first())
    }
    pub fn take_first(&self) -> (usize, T) {
        let res = self.contents.take_first();
        self.res_shr(res)
    }
    pub fn get_first_any(&self) -> (usize, T) {
        self.res_shr(self.contents.get_first_any())
    }
    pub fn take_first_any(&self) -> (usize, T) {
        let res = self.contents.take_first_any();
        self.res_shr(res)
    }
    pub fn get_first_hidden(&self) -> (usize, T) {
        self.res_shr(self.contents.get_first_hidden())
    }
    pub fn take_first_hidden(&self) -> (usize, T) {
        let res = self.contents.take_first_hidden();
        self.res_shr(res)
    }
    pub fn show_first(&self) -> (usize, T) {
        let res = self.contents.show_first();
        self.res_shr(res)
    }
    pub fn hide_first(&self) -> (usize, T) {
        let res = self.contents.hide_first();
        self.res_shr(res)
    }
    pub fn get_upper_bound(&self, index: usize) -> (usize, T) {
        let res = self.contents.get_upper_bound(self.shr(index));
        self.res_shr(res)
    }
    pub fn get_upper_bound_hidden(&self, index: usize) -> (usize, T) {
        let res = self.contents.get_upper_bound_hidden(self.shr(index));
        self.res_shr(res)
    }
    pub fn get_upper_bound_any(&self, index: usize) -> (usize, T) {
        let res = self.contents.get_upper_bound_any(self.shr(index));
        self.res_shr(res)
    }
    pub fn put(&self, index: usize, value: T){
        self.contents.put(self.shr(index), value)
    }
}


///Wrapper for SparseArray that has all methods that mutate the array taking
///&mut self instead of &self. All methods are otherwise identical to those of
///SparseArray.
pub struct OuterMutableSparseArray<T: Clone + Default> {
    contents: SparseArray<T>,
}

impl<T: Clone + Default> OuterMutableSparseArray<T> {
    pub fn new() -> OuterMutableSparseArray<T> {
        OuterMutableSparseArray {
            contents: SparseArray::new(),
        }
    }
    pub fn len(&self) -> usize {
        self.contents.len()
    }
    pub fn visible_len(&self) -> usize {
        self.contents.visible_len()
    }
    pub fn hidden_len(&self) -> usize {
        self.contents.hidden_len()
    }
    pub fn get(&self, index: usize) -> T {
        self.contents.get(index)
    }
    pub fn take(&mut self, index: usize) -> T {
        self.contents.take(index)
    }

    pub fn get_hidden(&self, index: usize) -> T {
        self.contents.get_hidden(index)
    }
    pub fn take_hidden(&mut self, index: usize) -> T {
        self.contents.take_hidden(index)
    }
    pub fn get_any(&mut self, index: usize) -> T {
        self.contents.get_any(index)
    }
    pub fn take_any(&mut self, index: usize) -> T {
        self.contents.take_any(index)
    }
    pub fn show(&mut self, index: usize) -> T {
        self.contents.show(index)
    }
    pub fn hide(&mut self, index: usize) -> T {
        self.contents.hide(index)
    }
    pub fn get_first(&self) -> (usize, T) {
        self.contents.get_first()
    }
    pub fn take_first(&mut self) -> (usize, T) {
        self.contents.take_first()
    }
    pub fn get_first_any(&self) -> (usize, T) {
        self.contents.get_first_any()
    }
    pub fn take_first_any(&mut self) -> (usize, T) {
        self.contents.take_first_any()
    }
    pub fn get_first_hidden(&self) -> (usize, T) {
        self.contents.get_first_hidden()
    }
    pub fn take_first_hidden(&mut self) -> (usize, T) {
        self.contents.take_first_hidden()
    }
    pub fn show_first(&mut self) -> (usize, T) {
        self.contents.show_first()
    }
    pub fn hide_first(&mut self) -> (usize, T) {
        self.contents.hide_first()
    }
    pub fn get_upper_bound(&self, index: usize) -> (usize, T) {
        self.contents.get_upper_bound(index)
    }
    pub fn get_upper_bound_hidden(&self, index: usize) -> (usize, T) {
        self.contents.get_upper_bound_hidden(index)
    }
    pub fn get_upper_bound_any(&self, index: usize) -> (usize, T) {
        self.contents.get_upper_bound_any(index)
    }
    pub fn put(&mut self, index: usize, value: T) {
        self.contents.put(index, value);
    }
}

///Wrapper for ShiftedSparseArray that has all methods that mutate the array 
///taking &mut self instead of &self. All methods are otherwise identical to
///those of ShiftedSparseArray.
pub struct OuterMutableShiftedSparseArray<T: Clone + Default> {
    contents: ShiftedSparseArray<T>,
}

impl<T: Clone + Default> OuterMutableShiftedSparseArray<T> {
    pub fn new(shift_width: u32) -> OuterMutableShiftedSparseArray<T> {
        OuterMutableShiftedSparseArray {
            contents: ShiftedSparseArray::new(shift_width),
        }
    }
    pub fn len(&self) -> usize {
        self.contents.len()
    }
    pub fn visible_len(&self) -> usize {
        self.contents.visible_len()
    }
    pub fn hidden_len(&self) -> usize {
        self.contents.hidden_len()
    }
    pub fn get(&self, index: usize) -> T {
        self.contents.get(index)
    }
    pub fn take(&mut self, index: usize) -> T {
        self.contents.take(index)
    }

    pub fn get_hidden(&self, index: usize) -> T {
        self.contents.get_hidden(index)
    }
    pub fn take_hidden(&mut self, index: usize) -> T {
        self.contents.take_hidden(index)
    }
    pub fn get_any(&mut self, index: usize) -> T {
        self.contents.get_any(index)
    }
    pub fn take_any(&mut self, index: usize) -> T {
        self.contents.take_any(index)
    }
    pub fn show(&mut self, index: usize) -> T {
        self.contents.show(index)
    }
    pub fn hide(&mut self, index: usize) -> T {
        self.contents.hide(index)
    }
    pub fn get_first(&self) -> (usize, T) {
        self.contents.get_first()
    }
    pub fn take_first(&mut self) -> (usize, T) {
        self.contents.take_first()
    }
    pub fn get_first_any(&self) -> (usize, T) {
        self.contents.get_first_any()
    }
    pub fn take_first_any(&mut self) -> (usize, T) {
        self.contents.take_first_any()
    }
    pub fn get_first_hidden(&self) -> (usize, T) {
        self.contents.get_first_hidden()
    }
    pub fn take_first_hidden(&mut self) -> (usize, T) {
        self.contents.take_first_hidden()
    }
    pub fn show_first(&mut self) -> (usize, T) {
        self.contents.show_first()
    }
    pub fn hide_first(&mut self) -> (usize, T) {
        self.contents.hide_first()
    }
    pub fn get_upper_bound(&self, index: usize) -> (usize, T) {
        self.contents.get_upper_bound(index)
    }
    pub fn get_upper_bound_hidden(&self, index: usize) -> (usize, T) {
        self.contents.get_upper_bound_hidden(index)
    }
    pub fn get_upper_bound_any(&self, index: usize) -> (usize, T) {
        self.contents.get_upper_bound_any(index)
    }
    pub fn put(&mut self, index: usize, value: T) {
        self.contents.put(index, value);
    }
}

pub fn add_custom_slabs_nonalloc<T: Clone + Default, A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    alloc.add_custom_slab(size_of::<SparseArrayNode<T>>(), 83, 0, 0, 0)
}

pub fn add_custom_slabs_alloc<T: Clone + Default, A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    alloc.add_custom_slab(size_of::<SparseArrayNode<T>>(), 83, 32, 32, 2)
}

#[cfg(test)]
mod test {
    use crate::SparseArray;

    fn check_get(array: &mut SparseArray<usize>, start: usize, end: usize, expected_value_offset: usize){
        for i in start..end {
            let mut expected_value = 0;
            if expected_value_offset != 0 {
                expected_value = i + expected_value_offset;
            }
            let mut value = array.get(i);
            if value != expected_value {
                panic!("get returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }
            value = array.get_any(i);
            if value != expected_value {
                panic!("get_any returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }
            value = array.get_hidden(i);
            if value != 0 {
                panic!("get_hidden returned non-zero value {} at index {}", value, i);
            }
            value = array.show(i);
            if value != 0 {
                panic!("show returned non-zero value {} at index {}", value, i);
            }
            value = array.take_hidden(i);
            if value != 0 {
                panic!("take_hidden returned non-zero value {} at index {}", value, i);
            }
        }
    }
    fn check_get_hidden(array: &mut SparseArray<usize>, start: usize, end: usize, expected_value_offset: usize){
        for i in start..end {
            let mut expected_value = 0;
            if expected_value_offset != 0 {
                expected_value = i + expected_value_offset;
            }
            let mut value = array.get_hidden(i);
            if value != expected_value {
                panic!("get_hidden returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }
            value = array.get_any(i);
            if value != expected_value {
                panic!("get_any returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }
            value = array.get(i);
            if value != 0 {
                panic!("get returned non-zero value {} at index {}", value, i);
            }
            value = array.hide(i);
            if value != 0 {
                panic!("hide returned non-zero value {} at index {}", value, i);
            }
            value = array.take(i);
            if value != 0 {
                panic!("take returned non-zero value {} at index {}", value, i);
            }
        }
    }

    fn check_get_first(array: &mut SparseArray<usize>, expected_index: usize, expected_value_offset: usize, any: bool){
        let expected_value;
        if expected_value_offset == 0 {
            expected_value = 0;
        }else{
            expected_value = expected_index + expected_value_offset;
        }
        let (index, value) = array.get_first();
        if index != expected_index {
            panic!("get_first returned incorrect index {}, expected: {}", index, expected_index);
        }
        if value != expected_value {
            panic!("get_first returned incorrect value {}, expected: {}", value,expected_value);
        }

        if !any {
            return;
        }

        let (index_any, value_any) = array.get_first_any();
        if index_any != expected_index {
            panic!("get_first_any returned incorrect index {}, expected: {}", index, expected_index);
        }
        if value_any != expected_value {
            panic!("get_first_any returned incorrect value {}, expected: {}", value, expected_value);
        }


    }

    fn check_get_upper_bound_offset(array: &mut SparseArray<usize>, start: usize, end: usize, expected_value_offset: usize, any: bool){
        for i in start..end {
            let mut expected_value = 0;
            if expected_value_offset != 0 {
                expected_value = i + expected_value_offset;
            }
            let (_, value) = array.get_upper_bound(i);
            if value != expected_value {
                panic!("get_upper_bound returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }
            if !any {
                continue;
            }
            let (_, value_any) = array.get_upper_bound_any(i);
            if value_any != expected_value {
                panic!("get_upper_bound_any returned incorrect value {} at index {}, expected: {}", value_any, i, expected_value);
            }
        }
    }

    fn check_get_upper_bound(array: &mut SparseArray<usize>, start: usize, end: usize, expected_value: usize, any: bool){
        for i in start..end {
            let (_, value) = array.get_upper_bound(i);
            if value != expected_value {
                panic!("get_upper_bound returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }
            if !any {
                continue;
            }
            let (_, value_any) = array.get_upper_bound_any(i);
            if value_any != expected_value {
                panic!("get_upper_bound_any returned incorrect value {} at index {}, expected: {}", value_any, i, expected_value);
            }
        }
    }

    fn check_get_upper_bound_offset_hidden(array: &mut SparseArray<usize>, start: usize, end: usize, expected_value_offset: usize, any: bool){
        for i in start..end {
            let mut expected_value = 0;
            if expected_value_offset != 0 {
                expected_value = i + expected_value_offset;
            }
            let (_, value) = array.get_upper_bound_hidden(i);
            if value != expected_value {
                panic!("get_upper_bound_hidden returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }

            if !any {
                continue;
            }

            let (_, value_any) = array.get_upper_bound_any(i);
            if value_any != expected_value {
                panic!("get_upper_bound_any returned incorrect value {} at index {}, expected: {}", value_any, i, expected_value);
            }
        }
    }

    fn check_get_upper_bound_hidden(array: &mut SparseArray<usize>, start: usize, end: usize, expected_value: usize, any: bool){
        for i in start..end {
            let (_, value) = array.get_upper_bound_hidden(i);
            if value != expected_value {
                panic!("get_upper_bound_hidden returned incorrect value {} at index {}, expected: {}", value, i, expected_value);
            }
            if !any {
                continue;
            }
            let (_, value_any) = array.get_upper_bound_any(i);
            if value_any != expected_value {
                panic!("get_upper_bound_any returned incorrect value {} at index {}, expected: {}", value_any, i, expected_value);
            }
        }
    }

    fn check_take_first_fail(array: &mut SparseArray<usize>){
        let (mut index, mut value) = array.take_first();
        if index != 0 {
            panic!("take_first returned non-zero index {}", index);
        }
        if value != 0 {
            panic!("take_first returned non-zero value {}", value);
        }
        (index, value) = array.hide_first();
        if index != 0 {
            panic!("hide_first returned non-zero index {}", index);
        }
        if value != 0 {
            panic!("hide_first returned non-zero value {}", value);
        }
    }
    fn check_take_first_hidden_fail(array: &mut SparseArray<usize>){
        let (mut index, mut value) = array.take_first_hidden();
        if index != 0 {
            panic!("take_first_hidden returned non-zero index {}", index);
        }
        if value != 0 {
            panic!("take_first_hidden returned non-zero value {}", value);
        }
        (index, value) = array.show_first();
        if index != 0 {
            panic!("show_first returned non-zero index {}", index);
        }
        if value != 0 {
            panic!("show_first returned non-zero value {}", value);
        }
    }
    fn check_take_first_any_fail(array: &mut SparseArray<usize>){
        let (index, value) = array.take_first_any();
        if index != 0 {
            panic!("take_first_any returned non-zero index {}", index);
        }
        if value != 0 {
            panic!("take_first_any returned non-zero value {}", value);
        }
    }

    fn check_get_first_hidden(array: &mut SparseArray<usize>, expected_index: usize, expected_value_offset: usize, any: bool){
        let expected_value;
        if expected_value_offset == 0 {
            expected_value = 0;
        }else{
            expected_value = expected_index + expected_value_offset;
        }

        let (index, value) = array.get_first_hidden();
        if index != expected_index {
            panic!("get_first_hidden returned incorrect index {}, expected: {}", index, expected_index);
        }
        if value != expected_value {
            panic!("get_first_hidden returned incorrect value {}, expected: {}", value, expected_value);
        }

        if !any {
            return;
        }

        let (index_any, value_any) = array.get_first_any();
        if index_any != expected_index {
            panic!("get_first_any returned incorrect index {}, expected: {}", index, expected_index);
        }
        if value_any != expected_value {
            panic!("get_first_any returned incorrect value {}, expected: {}", value, expected_value);
        }
    }

    fn check_len(array: &mut SparseArray<usize>, len: usize){
        if array.len() != len {
            panic!("incorrect number of items in array ({}, expected {})", array.len(), len);
        }
    }

    fn check_hidden_len(array: &mut SparseArray<usize>, len: usize){
        if array.hidden_len() != len {
            panic!("incorrect number of hidden items in array ({}, expected {})", array.len(), len);
        }
    }

    fn check_visible_len(array: &mut SparseArray<usize>, len: usize){
        if array.visible_len() != len {
            panic!("incorrect number of visible items in array ({}, expected {})", array.len(), len);
        }
    }

    #[test]
    fn fixed_sequence_0() {
        const MAX_ITEMS: usize = 1028;
        let mut array: SparseArray<usize> = SparseArray::new();

        check_get_first(&mut array, 0, 0, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_fail(&mut array);
        check_take_first_hidden_fail(&mut array);
        check_take_first_any_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS*2, 0);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS*2, 0, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, 0);
        check_visible_len(&mut array, 0);
        check_hidden_len(&mut array, 0);

        for i in 0..MAX_ITEMS {
            array.put(i, i+1);
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, 0, MAX_ITEMS, 1);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS, 1, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);
        
        for i in 0..MAX_ITEMS/2 {
            let value = array.take(i);
            if value != i + 1 {
                panic!("take returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, MAX_ITEMS/2, 1, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS/2, 0);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 1);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS/2, 0, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 1, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS/2);
        check_visible_len(&mut array, MAX_ITEMS/2);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/2 {
            let (index, value) = array.take_first();
            let expected_index = i + MAX_ITEMS/2;
            if index != expected_index {
                panic!("take_first returned incorrect index {} instead of {}", index, expected_index);
            }
            if value != expected_index + 1 {
                panic!("take_first returned incorrect value {} at index {}", value, expected_index);
            }
            //println!("take_first: {:x} {:x}", index, value);
        }
        check_get_first(&mut array, 0, 0, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS*2, 0, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, true);
        check_get(&mut array, 0, MAX_ITEMS, 0);
        check_len(&mut array, 0);
        check_visible_len(&mut array, 0);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS {
            array.put(i, i+1);
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS, 1);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS, 1, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS);
        check_hidden_len(&mut array, 0);


        for i in MAX_ITEMS/2..MAX_ITEMS {
            array.put(i, i+2);
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS/2, 1);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/2, 1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS + 1, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS);
        check_hidden_len(&mut array, 0);

        for i in 0..MAX_ITEMS/2 {
            let value = array.hide(i);
            if value != i + 1 {
                panic!("hide returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, MAX_ITEMS/2, 2, false);
        check_get_first_hidden(&mut array, 0, 1, true);
        check_get_hidden(&mut array, 0, MAX_ITEMS/2, 1);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS/2, 0, false);
        check_get_upper_bound_offset_hidden(&mut array, 0, MAX_ITEMS/2, 1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS + 1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS*2, MAX_ITEMS/2, false);

        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS/2);
        check_hidden_len(&mut array, MAX_ITEMS/2);

        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/4 {
            let value = array.show(i);
            if value != i + 1 {
                panic!("show returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, MAX_ITEMS/4, 1, false);
        check_get(&mut array, 0, MAX_ITEMS/4, 1);
        check_get_hidden(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 1);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS/4, 0, false);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/4, 1, true);
        check_get_upper_bound_offset_hidden(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS + 1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS*2, MAX_ITEMS/2, false);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS/4*3);
        check_hidden_len(&mut array, MAX_ITEMS/4);

        for i in 0..MAX_ITEMS/4 {
            let (index, value) = array.hide_first();
            if index != i {
                panic!("hide_first returned incorrect index {} instead of {}", index, i);
            }
            if value != i + 1 {
                panic!("hide_first returned incorrect value {} at index {}", value, i);
            }
            //println!("hide_first: {} {} {} {}", index, value, array.visible_len(), array.hidden_len());
        }
        check_get_first(&mut array, MAX_ITEMS/2, 2, false);
        check_get_first_hidden(&mut array, 0, 1, true);
        check_get_hidden(&mut array, 0, MAX_ITEMS/2, 1);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS/2, 0, false);
        check_get_upper_bound_offset_hidden(&mut array, 0, MAX_ITEMS/2, 1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS + 1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS*2, MAX_ITEMS/2, false);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS/2);
        check_hidden_len(&mut array, MAX_ITEMS/2);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/4 {
            let (index, value) = array.show_first();
            if index != i {
                panic!("show_first returned incorrect index {} instead of {}", index, i);
            }
            if value != i + 1 {
                panic!("show_first returned incorrect value {} at index {}", value, i);
            }
            //println!("show_first: {} {} {} {}", index, value, array.visible_len(), array.hidden_len());
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, MAX_ITEMS/4, 1, false);
        check_get(&mut array, 0, MAX_ITEMS/4, 1);
        check_get_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS/4, 1);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/4, 1, false);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS/4, 0, false);
        check_get_upper_bound(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, MAX_ITEMS/4, false);
        check_get_upper_bound_offset_hidden(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS*2, MAX_ITEMS/2, false);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS/4*3);
        check_hidden_len(&mut array, MAX_ITEMS/4);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/4 {
            let (index, value) = array.take_first_hidden();
            let expected_index = i + MAX_ITEMS/4;
            if index != expected_index {
                panic!("take_first_hidden returned incorrect index {} instead of {}", index, expected_index);
            }
            if value != expected_index + 1 {
                panic!("take_first_hidden returned incorrect value {} at index {}", value, expected_index);
            }
            //println!("take_first_hidden: {} {} {} {} {}", i, index, value, array.visible_len(), array.hidden_len());
        }

        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS/4, 1);
        check_get(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 0);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/4, 1, true);
        check_get_upper_bound(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, MAX_ITEMS/4, false);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS/4*3);
        check_visible_len(&mut array, MAX_ITEMS/4*3);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/4 {
            let (index, value) = array.take_first();
            if index != i {
                panic!("take_first returned incorrect index {} instead of {}", index, i);
            }
            if value != i + 1 {
                panic!("take_first returned incorrect value {} at index {}", value, i);
            }
            //println!("take_first: {} {}", index, value);
        }
        check_get_first(&mut array, MAX_ITEMS/2, 2, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS/2, 0);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS/2, 0, false);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS/2);
        check_visible_len(&mut array, MAX_ITEMS/2);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in MAX_ITEMS/2..MAX_ITEMS/4*3 {
            let (index, value) = array.hide_first();
            if index != i {
                panic!("hide_first returned incorrect index {} instead of {}", index, i);
            }
            if value != i + 2 {
                panic!("hide_first returned incorrect value {} at index {}", value, i);
            }
        }

        check_get_first(&mut array, MAX_ITEMS/4*3, 2, false);
        check_get_first_hidden(&mut array, MAX_ITEMS/2, 2, true);
        check_get_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, 2);
        check_get(&mut array, 0, MAX_ITEMS/2, 0);
        check_get_hidden(&mut array, 0, MAX_ITEMS/2, 0);
        check_get(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS/2, 0, true);
        check_get_upper_bound(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, 0, false);
        check_get_upper_bound_offset_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, 2, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS/4*3+1, false);
        check_len(&mut array, MAX_ITEMS/2);
        check_visible_len(&mut array, MAX_ITEMS/4);
        check_hidden_len(&mut array, MAX_ITEMS/4);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in MAX_ITEMS/2..MAX_ITEMS/4*3 {
            let value = array.take_hidden(i);
            if value != i + 2 {
                panic!("take_hidden returned incorrect value {} at index {}", value, i);
            }
        }

        check_get_first(&mut array, MAX_ITEMS/4*3, 2, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS/4*3, 0);
        check_get(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS/4*3, 0, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS/4*3, 0, true);

        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS/4);
        check_visible_len(&mut array, MAX_ITEMS/4);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/2 {
            array.put(i, i+1);
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS/2, 1);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, 0);
        check_get(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/2, 1, true);
        check_get_upper_bound(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, MAX_ITEMS/2, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS/4*3);
        check_visible_len(&mut array, MAX_ITEMS/4*3);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in MAX_ITEMS/4..MAX_ITEMS/2 {
            let value = array.hide(i);
            if value != i + 1 {
                panic!("hide returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, MAX_ITEMS/4, 1, false);
        check_get(&mut array, 0, MAX_ITEMS/4, 1);
        check_get_hidden(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 1);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, 0);
        check_get(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/4, 1, true);
        check_get_upper_bound(&mut array, MAX_ITEMS/4, MAX_ITEMS/4*3, MAX_ITEMS/4, false);
        check_get_upper_bound_offset_hidden(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS*2, MAX_ITEMS/2, false);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_len(&mut array, MAX_ITEMS/4*3);
        check_visible_len(&mut array, MAX_ITEMS/2);
        check_hidden_len(&mut array, MAX_ITEMS/4);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in MAX_ITEMS/4..MAX_ITEMS/2 {
            array.put(i, i + 2);
            //println!("visible_len: {} hidden_len: {}", array.visible_len(), array.hidden_len());
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_take_first_hidden_fail(&mut array);
        check_get(&mut array, 0, MAX_ITEMS/4, 1);
        check_get(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 2);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, 0);
        check_get(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/4, 1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, MAX_ITEMS/2+1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS/4*3);
        check_visible_len(&mut array, MAX_ITEMS/4*3);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in MAX_ITEMS/4..MAX_ITEMS/2 {
            let value = array.hide(i);
            if value != i + 2 {
                panic!("hide returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, 0, 1, true);
        check_get_first_hidden(&mut array, MAX_ITEMS/4, 2, false);
        check_get(&mut array, 0, MAX_ITEMS/4, 1);
        check_get_hidden(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 2);
        check_get(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, 0);
        check_get(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/4, 1, true);
        check_get_upper_bound_offset_hidden(&mut array, MAX_ITEMS/4, MAX_ITEMS/2, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS/4, MAX_ITEMS/4*3, MAX_ITEMS/4, false);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS/4*3, MAX_ITEMS/2+1, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS*2, MAX_ITEMS/2+1, false);

        check_len(&mut array, MAX_ITEMS/4*3);
        check_visible_len(&mut array, MAX_ITEMS/2);
        check_hidden_len(&mut array, MAX_ITEMS/4);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/4 {
            let value = array.take_any(i);
            if value != i + 1 {
                panic!("take_any returned incorrect value {} at index {}", value, i);
            }
        }
        for i in MAX_ITEMS/4..MAX_ITEMS/2 {
            let value = array.take_any(i);
            if value != i + 2 {
                panic!("take_any returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, MAX_ITEMS/4*3, 2, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_get(&mut array, 0, MAX_ITEMS/4*3, 0);
        check_get(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS/4*3, 0, true);
        check_get_upper_bound_offset(&mut array, MAX_ITEMS/4*3, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS/4);
        check_visible_len(&mut array, MAX_ITEMS/4);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS/4*3 {
            array.put(i, i + 2);
        }
        check_get_first(&mut array, 0, 2, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_get(&mut array, 0, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS);
        check_hidden_len(&mut array, 0);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in MAX_ITEMS/2..MAX_ITEMS {
            let value = array.hide(i);
            if value != i + 2 {
                panic!("hide returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, 0, 2, true);
        check_get_first_hidden(&mut array, MAX_ITEMS/2, 2, false);
        check_get(&mut array, 0, MAX_ITEMS/2, 2);
        check_get_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2);
        check_get_upper_bound_offset(&mut array, 0, MAX_ITEMS/2, 2, true);
        check_get_upper_bound(&mut array, MAX_ITEMS/2, MAX_ITEMS*2, MAX_ITEMS/2+1, false);
        check_get_upper_bound_offset_hidden(&mut array, MAX_ITEMS/2, MAX_ITEMS, 2, true);
        check_get_upper_bound_hidden(&mut array, MAX_ITEMS, MAX_ITEMS*2, MAX_ITEMS+1, true);
        check_len(&mut array, MAX_ITEMS);
        check_visible_len(&mut array, MAX_ITEMS/2);
        check_hidden_len(&mut array, MAX_ITEMS/2);
        check_get(&mut array, MAX_ITEMS, MAX_ITEMS*2, 0);

        for i in 0..MAX_ITEMS {
            let (index, value) = array.take_first_any();
            if index != i {
                panic!("take_first_any returned incorrect index {} instead of {}", index, i);
            }
            if value != i + 2 {
                panic!("take_first_any returned incorrect value {} at index {}", value, i);
            }
        }
        check_get_first(&mut array, 0, 0, true);
        check_get_first_hidden(&mut array, 0, 0, false);
        check_get(&mut array, 0, MAX_ITEMS*2, 0);
        check_get_upper_bound(&mut array, 0, MAX_ITEMS*2, 0, true);
        check_get_upper_bound_hidden(&mut array, 0, MAX_ITEMS*2, 0, false);
        check_len(&mut array, 0);
        check_visible_len(&mut array, 0);
        check_hidden_len(&mut array, 0);
    }
    #[test]
    fn drop_full_array() {
        const MAX_ITEMS: usize = 1028;
        let array: SparseArray<usize> = SparseArray::new();
        for i in 0..MAX_ITEMS {
            array.put(i, i+1);
        }
    }
}
