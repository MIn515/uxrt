// Copyright (c) 2021 Andrew Warkentin
//
// Based on code from Robigalia:
// Copyright (c) 2015 The Robigalia Project Developers
//
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.
//! See the `Treemap` type.

#[cfg(not(any(test, not(feature = "no_std"))))]
use alloc::vec::Vec;
#[cfg(not(any(test, not(feature = "no_std"))))]
use alloc::boxed::Box;
#[cfg(not(any(test, not(feature = "no_std"))))]
use core::cell::{Cell, RefCell};
#[cfg(not(any(test, not(feature = "no_std"))))]
use core::mem;

#[cfg(any(test, not(feature = "no_std")))]
use std::vec::Vec;
#[cfg(any(test, not(feature = "no_std")))]
use std::boxed::Box;
#[cfg(any(test, not(feature = "no_std")))]
use std::cell::{Cell, RefCell};
#[cfg(any(test, not(feature = "no_std")))]
use std::mem;

#[cfg(feature = "debug_treemap")]
#[macro_use]
use log;

macro_rules! treemap_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_treemap")]
        debug!($($toks)*);
    })
}

use intrusive_collections::{
    intrusive_adapter, rbtree, Bound, KeyAdapter, RBTree, UnsafeRef,
};

use custom_slab_allocator::CustomSlabAllocator;

use crate::{Bitmap, OneBit};

/// An individual node in a `Treemap`

struct TreemapNode {
    index: usize,
    num_set: Cell<usize>,
    bitmap: RefCell<Option<Bitmap<Vec<usize>, OneBit>>>,
    link: rbtree::Link,
}

impl TreemapNode {
    /// Create a new node
    fn new(index: usize, bitmap_size: usize, init_set: bool) -> Option<TreemapNode> {
        let mut num_set = 0;
        if init_set {
            num_set = bitmap_size;
        }
        let ret = TreemapNode {
            index,
            num_set: Cell::new(num_set),
            bitmap: RefCell::new(None),
            link: Default::default(),
        };
        if !init_set {
            ret.create_bitmap(bitmap_size, false);
        }
        Some(ret)
    }
    /// Create a bitmap for this node
    fn create_bitmap(&self, bitmap_size: usize, init_set: bool) -> bool {
        treemap_debug_println!("TreemapNode::create_bitmap: {:p}, index: {}, bitmap_size: {}, init_set: {}", self, self.index, bitmap_size, init_set);
        let mut init_value: usize = 0;
        if init_set {
            init_value = !init_value;
        }
        let bitmap = Bitmap::from_storage(
            bitmap_size,
            (),
            vec![init_value; bitmap_size / mem::size_of::<usize>() * 8],
        );
        if bitmap.is_some() {
            treemap_debug_println!("bitmap creation succeeded");
            self.bitmap.replace(Some(bitmap.unwrap()));
            true
        }else{
            treemap_debug_println!("bitmap creation failed");
            false
        }
    }
    ///Internal method to get an item from the bitmap (panics if no bitmap is 
    ///present)
    fn get_raw(&self, i: usize) -> Option<u64> {
        self.bitmap.borrow().as_ref().unwrap().get(i)
    }
    ///Internal method to set an item in the bitmap (panics if no bitmap is 
    ///present)
    fn set_raw(&self, i: usize, value: u64) -> bool {
        self.bitmap.borrow_mut().as_mut().unwrap().set(i, value)
    }
    ///Internal method to get the total length of the bitmap (panics if no
    ///bitmap is present)
    fn len_raw(&self) -> usize {
        self.bitmap.borrow().as_ref().unwrap().len()
    }
    ///Returns true if a bitmap is present
    fn has_bitmap(&self) -> bool {
        self.bitmap.borrow().is_some()
    }
    ///Sets an item
    ///
    ///If the internal bitmap is filled with all ones, it will be deallocated
    ///(to be reallocated when an item is set to zero)
    fn set(&self, i: usize, value: u64, bitmap_size: usize) -> bool {
        treemap_debug_println!("TreemapNode::set {:x} {:x}", i, value);
        if i > bitmap_size {
            return false;
        }

        if self.has_bitmap() {
            treemap_debug_println!("bitmap present");
            let existing_value = self.get_raw(i);
            if existing_value.is_none() {
                return false;
            }
            if value != existing_value.unwrap(){
                if value > 0 {
                    treemap_debug_println!("TreemapNode::set: incrementing num_set");
                    self.num_set.set(self.num_set.get() + 1);
                }else{
                    treemap_debug_println!("TreemapNode::set: decrementing num_set");
                    self.num_set.set(self.num_set.get() - 1);
                }
                if self.num_set.get() < self.len_raw() {
                    treemap_debug_println!("TreemapNode::set: setting value");
                    self.set_raw(i, value)
                }else{
                    treemap_debug_println!("TreemapNode::set: dropping bitmap");
                    self.bitmap.replace(None);
                    true
                }
            }else{
                true
            }
        } else if value == 0 {
            treemap_debug_println!("bitmap not present");
            if !self.create_bitmap(bitmap_size, true){
                false
            }else{
                treemap_debug_println!("bitmap created");
                self.num_set.set(self.len_raw() - 1);
                self.set_raw(i, value)
            }
        } else {
            true
        }
    }
    ///Gets an item
    fn get(&self, i: usize) -> Option<u64> {
        if self.has_bitmap() { 
            self.get_raw(i)
        }else{
            if i < self.num_set.get() {
                Some(1)
            }else{
                None
            }
        }
    }
    ///Gets the index of the first item set to 1 (returning None if no such
    ///item exists)
    fn first_set(&self) -> Option<usize> {
        let bitmap = self.bitmap.borrow();
        if bitmap.is_some() {
            treemap_debug_println!("TreemapNode::first_set: {:p}, num_set: {}, index: {}, bitmap present", self, self.num_set.get(), self.index);
            bitmap.as_ref().unwrap().first_set()
        }else{
            treemap_debug_println!("TreemapNode::first_set: {:p}, index: {}, bitmap absent", self, self.index);
            Some(0)
        }
    }
}

intrusive_adapter!(TreemapAdapter = UnsafeRef<TreemapNode>: TreemapNode { link: rbtree::Link });

impl<'a> KeyAdapter<'a> for TreemapAdapter {
    type Key = usize;
    fn get_key(&self, node: &'a TreemapNode) -> usize {
        node.index
    }
}

/// A sparse bitmap implemented as an RBTree of Bitmaps. This allows the bitmap 
/// CSpace allocator to use fixed size allocations from the heap rather than 
/// having a bitmap size that varies with the CNode size (necessary with a slab 
/// heap allocator), and it also should make allocation a bit faster on average
/// because it only has to search a tree and one of the relatively small 
/// sub-bitmaps, rather than a large bitmap.
///
/// Nodes without any items set to 1 are dropped from the tree, to be replaced
/// when an item is set to 1.
///
/// Currently only supports initializing to all ones (since that is what the 
/// bitmap CSpace allocator requires).

pub struct Treemap {
    contents: RBTree<TreemapAdapter>,
    entries: usize,
    max_node: usize,
    bitmap_size_bits: u32,
}

impl core::fmt::Debug for Treemap {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        writeln!(f, "Treemap: entries {}, bitmap_size_bits {}, max_node: {}, first_set: {:?}", self.entries, self.bitmap_size_bits, self.max_node, self.first_set()).unwrap();
        let mut cursor = self.contents.front();
        let mut node_opt = cursor.get();
        while node_opt.is_some() {
            let node = node_opt.unwrap();
            if node.bitmap.borrow().is_some() {
                if node.first_set().is_some() {
                    writeln!(f, "node {}: bitmap present, first set: {}", node.index, node.first_set().unwrap()).unwrap();
                }else{
                    writeln!(f, "node {}: bitmap present, first set: None", node.index).unwrap();
                }
            }else{
                writeln!(f, "node {}: bitmap absent", node.index).unwrap();
            }
            cursor.move_next();
            node_opt = cursor.get();
        }
        Ok(())
    }
}

impl Treemap {
    /// Creates a new `Treemap`
    pub fn new(entries: usize, bitmap_size_bits: u8) -> Option<Treemap> {
        Some(Treemap {
            contents: Default::default(),
            entries,
            max_node: 0,
            bitmap_size_bits: bitmap_size_bits as u32,
        })
    }

    /// Get the `i`th bitslice, returning None on out-of-bounds or if `E::from_bits` returns None.
    pub fn get(&self, i: usize) -> Option<u64> {
        treemap_debug_println!("Treemap::get {:x}", i);
        if i >= self.entries {
            return None;
        }

        let tree_idx = i.wrapping_shr(self.bitmap_size_bits);
        let bitmap_idx = i & ((1 << self.bitmap_size_bits) - 1);
        let cursor = self.contents.find(&tree_idx);

        if let Some(node) = cursor.get() {
            treemap_debug_println!("Treemap::get: node present");
            node.get(bitmap_idx)
        }else if tree_idx < self.max_node {
            treemap_debug_println!("Treemap::get: node absent, below max_node");
            Some(0)
        }else{
            treemap_debug_println!("Treemap::get: node absent, above max_node");
            Some(1)
        }
    }

    /// Set the `i`th bitslice to `value`, returning false on out-of-bounds or if `value` contains
    /// bits outside of the least significant `E::width(w)` bits.
    pub fn set(&mut self, i: usize, value: u64) -> bool {
        treemap_debug_println!("Treemap::set {:x} {:x}", i, value);
        if i >= self.entries {
            return false;
        }
        let tree_idx = i.wrapping_shr(self.bitmap_size_bits);
        let bitmap_idx = i & ((1 << self.bitmap_size_bits) - 1);
        let mut cursor = self.contents.upper_bound_mut(Bound::Included(&tree_idx));
        let mut ret = true;
        if cursor.is_null() || cursor.get().unwrap().index < tree_idx {
            treemap_debug_println!("Treemap.set: node not found, index: {}", tree_idx);
            #[cfg(feature = "debug_treemap")]
            if !cursor.is_null(){ 
                treemap_debug_println!("upper bound index: {}", cursor.get().unwrap().index); 
            }
            let mut start_idx = tree_idx;
            let mut num_new_nodes = 0;
            let mut init_set = false;
            if tree_idx >= self.max_node {
                if value == 0 {
                    treemap_debug_println!("Treemap.set: set to 0 above max_node");
                    num_new_nodes = tree_idx + 1 - self.max_node;
                    start_idx = self.max_node;
                    self.max_node += num_new_nodes;
                    init_set = true;
                }
            }else{
                if value > 0 {
                    treemap_debug_println!("Treemap.set: set to 1 below max_node");
                    num_new_nodes = 1;
                }
            }
            for i in 0..num_new_nodes {
                treemap_debug_println!("adding new node: {} {} {}", start_idx + i, 1 << self.bitmap_size_bits, init_set);
                let node = TreemapNode::new(start_idx + i, 1 << self.bitmap_size_bits, init_set).expect("out of memory when attempting to allocate Treemap node");
                if i == num_new_nodes - 1 {
                    treemap_debug_println!("setting value at {} in node {} to {}", bitmap_idx, start_idx + i, value);
                    ret = node.set(bitmap_idx, value, 1 << self.bitmap_size_bits);
                }
                self.contents.insert(UnsafeRef::from_box(Box::new(node)));
            }
            ret
        }else{
            let node = cursor.get().unwrap();
            treemap_debug_println!("Treemap.set: node found, index: {}, num_set: {}", node.index, node.num_set.get());
            let ret = node.set(bitmap_idx, value, 1 << self.bitmap_size_bits);
            if node.num_set.get() == 0 {
                treemap_debug_println!("removing node");
                if node.index == self.max_node + 1 {
                    self.max_node -= 1;
                }
                unsafe { 
                    drop(UnsafeRef::into_box(cursor.remove().unwrap()));
                }
            }
            ret
        }
    }

    /// Length in number of bitslices contained.
    pub fn len(&self) -> usize {
        self.entries
    }

    /// Return the index of the first bit set
    pub fn first_set(&self) -> Option<usize> {
        treemap_debug_println!("Treemap::first_set");
        let cursor = self.contents.front();
        if cursor.is_null() {
            treemap_debug_println!("tree empty: {} {}", self.max_node, self.entries >> self.bitmap_size_bits);
            let ret = self.max_node << self.bitmap_size_bits;
            if ret < self.entries {
                Some(ret)
            }else{
                None
            }
        }else{
            let node = cursor.get().unwrap();
            if let Some(sub_idx) = node.first_set() {
                let idx = (node.index << self.bitmap_size_bits) | sub_idx as usize;
                if idx < self.len() {
                    treemap_debug_println!("node: {} idx: {}, sub_idx: {}", node.index, idx, sub_idx);
                    Some(idx)
                }else{
                    treemap_debug_println!("node: {} idx: {} (OOB)", node.index, idx);
                    None
                }
            }else{
                treemap_debug_println!("node {} empty", node.index);
                None
            }
        }
    }
}

impl Drop for Treemap {
    fn drop(&mut self) {
        let mut cursor = self.contents.front_mut();
        while let Some(node) = cursor.remove(){
            unsafe { drop(UnsafeRef::into_box(node)) };
            cursor.move_next();
        }
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    alloc.add_custom_slab(mem::size_of::<TreemapNode>(), 256, 32, 32, 2)
}

#[cfg(test)]
mod test {
    extern crate quickcheck;
    extern crate rand;

    use self::quickcheck::{quickcheck, TestResult};
    use crate::{Bitmap, OneBit, Treemap, bits};
    use std::mem;
    use self::rand::{thread_rng, Rng};

    fn clear_then_set_prop(entries: usize, bitmap_size_bits: u8) -> bool {
        let entries = entries * 1000; 
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits <= 6 { return true }
        println!("entries: {}, bitmap_size_bits: {}", entries, bitmap_size_bits);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();

        for i in 0..entries {
            if bm.get(i) != Some(1) { return false; }
        }

        for i in 0..entries {
            assert!(bm.set(i, 0));
        }

        for i in 0..entries {
            if bm.get(i) != Some(0) { return false; }
        }

        for i in 0..entries {
            assert!(bm.set(i, 1));
        }

        for i in 0..entries {
            if bm.get(i) != Some(1) { return false; }
        }
        true
    }

    #[test]
    fn clear_then_set_is_identity() {
        quickcheck(clear_then_set_prop as fn(usize, u8) -> bool);
    }

    fn first_set_works_prop(entries: usize, bitmap_size_bits: u8) -> quickcheck::TestResult {
        let entries = entries * 1000; 
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 { return quickcheck::TestResult::discard() }
         println!("first_set_works: entries: {}, bitmap_size_bits: {}", entries, bitmap_size_bits);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();

        for i in 0..entries {
            treemap_debug_println!("{}", i);
            if !bm.set(i, 0) { 
                println!("set at {} failed", i);
                return quickcheck::TestResult::from_bool(false); 
            }
            let mut expected_first_set = Some(i + 1);

            if i == entries - 1 {
                expected_first_set = None;
            }
            let first_set = bm.first_set();
            if first_set != expected_first_set { 
                println!("first_set failed: {:?} {:?}", first_set, expected_first_set);

                return quickcheck::TestResult::from_bool(false); 
            }
            if expected_first_set.is_some(){
                let val = bm.get(expected_first_set.unwrap());
                if val != Some(1) {
                    println!("get for index {:?} failed", val);
                    return quickcheck::TestResult::from_bool(false); 
                }
            }
        }
        for i in (0..entries).rev() {
            treemap_debug_println!("{}", i);
            if !bm.set(i, 1) { 
                println!("set at {} failed", i);
                return quickcheck::TestResult::from_bool(false); 
            }
            let expected_first_set = Some(i);

            let first_set = bm.first_set();
            if first_set != expected_first_set { 
                println!("first_set failed: {:?} {:?}", first_set, expected_first_set);

                return quickcheck::TestResult::from_bool(false); 
            }
            let val = bm.get(expected_first_set.unwrap());
            if val != Some(1) {
                println!("get for index {:?} failed", val);
                return quickcheck::TestResult::from_bool(false); 
            }
        }
        println!("success");
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn first_set_works() {
        quickcheck(first_set_works_prop as fn(usize, u8) -> quickcheck::TestResult);
    }

    fn allocate(bm: &mut Treemap, entries: usize) -> bool {
        for i in 0..entries {
            treemap_debug_println!("{}", i);
            let first_set = bm.first_set().expect("allocation failed");
            if bm.get(first_set) != Some(1) {
                println!("first_set returned a 0 slot at index {}", first_set);
                return false;
            }
            if !bm.set(first_set, 0) { 
                println!("set at {} failed", i);
                return false; 
            }
        }
        true
    }

    fn deallocate_ascending(bm: &mut Treemap, start: usize, end: usize) -> bool {
        for i in start..end {
            treemap_debug_println!("{}", i);
            if bm.get(i) == Some(1) {
                println!("get returned a 1 slot at index {} before deallocation", i);
                return false;
            }
            if !bm.set(i, 1) { 
                println!("set at {} failed", i);
                return false; 
            }
            if bm.get(i) != Some(1) {
                println!("get returned a 0 slot at index {} after deallocation", i);
                return false;
            }
        }
        true
    }

    fn deallocate_descending(bm: &mut Treemap, start: usize, end: usize) -> bool {
        for i in (start..end).rev() {
            treemap_debug_println!("{}", i);
            if bm.get(i) == Some(1) {
                println!("get returned a 1 slot at index {} before deallocation", i);
                return false;
            }
            if !bm.set(i, 1) { 
                println!("set at {} failed", i);
                return false; 
            }
            if bm.get(i) != Some(1) {
                println!("get returned a 0 slot at index {} after deallocation", i);
                return false;
            }
        }
        true
    }

    fn check_range(bm: &mut Treemap, start: usize, end: usize, expected_value: u64) -> bool {
        for i in start..end {
            treemap_debug_println!("{}", i);
            let value = bm.get(i);
            if value != Some(expected_value) {
                println!("get returned a slot with value {:?} instead of {:?} at index {}", value, Some(expected_value), i);
                return false;
            }
        }
        true
    }

    fn check_first_set(bm: &mut Treemap, expected_value: Option<usize>) -> bool {
        let first_set = bm.first_set();
        if first_set != expected_value {
            println!("first_set returned {:?} rather than the expected value of {:?}", first_set, expected_value);
            false
        }else{
            true
        }
    }

    fn allocate_deallocate_full_ascending_prop(entries: usize, bitmap_size_bits: u8) -> TestResult {
        let entries = entries * 1000; 
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 { return TestResult::discard() }
         println!("allocate_deallocate_full_ascending: entries: {}, bitmap_size_bits: {}", entries, bitmap_size_bits);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, entries) { return TestResult::from_bool(false) }

        if !check_first_set(&mut bm, None) { return TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, entries, 0) { return TestResult::from_bool(false); }

        if !deallocate_ascending(&mut bm, 0, entries) { return TestResult::from_bool(false); }
        if !check_first_set(&mut bm, Some(0)) { return TestResult::from_bool(false); }
        TestResult::from_bool(true)

    }

    #[test]
    fn allocate_deallocate_full_ascending() {
        quickcheck(allocate_deallocate_full_ascending_prop as fn(usize, u8) -> quickcheck::TestResult);
    }

    fn allocate_deallocate_full_descending_prop(entries: usize, bitmap_size_bits: u8) -> quickcheck::TestResult {
        let entries = entries * 1000; 
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 { return quickcheck::TestResult::discard() }
         println!("allocate_deallocate_full_ascending: entries: {}, bitmap_size_bits: {}", entries, bitmap_size_bits);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, entries) { return  TestResult::from_bool(false) }

        if !check_first_set(&mut bm, None) { return TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, entries, 0) { return TestResult::from_bool(false); }

        if !deallocate_descending(&mut bm, 0, entries) { return TestResult::from_bool(false); }
        if !check_first_set(&mut bm, Some(0)) { return TestResult::from_bool(false); }
        TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_full_descending() {
        quickcheck(allocate_deallocate_full_descending_prop as fn(usize, u8) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate the same number of slots in ascending order
    fn allocate_deallocate_partial_1_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries { return TestResult::discard() }
         println!("allocate_deallocate_partial_1: entries: {}, bitmap_size_bits: {}, max: {}", entries, bitmap_size_bits, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return TestResult::from_bool(false) }

        if !deallocate_ascending(&mut bm, 0, max) { return TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, entries, 1) { return TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(0)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_1() {
        quickcheck(allocate_deallocate_partial_1_prop as fn(usize, u8, usize, usize) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate the same number of slots in descending order
    fn allocate_deallocate_partial_2_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries { return quickcheck::TestResult::discard() }
         println!("allocate_deallocate_partial_2: entries: {}, bitmap_size_bits: {}, max: {}", entries, bitmap_size_bits, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return quickcheck::TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return quickcheck::TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !deallocate_descending(&mut bm, 0, max) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(0)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_2() {
        quickcheck(allocate_deallocate_partial_2_prop as fn(usize, u8, usize, usize) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate fewer slots than allocated in asscending order, starting from the beginning
    fn allocate_deallocate_partial_3_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize, dealloc_max1: usize, dealloc_max2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        let dealloc_max = dealloc_max1 * 1000 + dealloc_max2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries || dealloc_max >= max { return quickcheck::TestResult::discard() }
         println!("allocate_deallocate_partial_3: entries: {}, bitmap_size_bits: {}, dealloc_max: {} max: {}", entries, bitmap_size_bits, dealloc_max, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return quickcheck::TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return quickcheck::TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !deallocate_ascending(&mut bm, 0, dealloc_max) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, dealloc_max, 1) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, dealloc_max, max, 0) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(0)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_3() {
        quickcheck(allocate_deallocate_partial_3_prop as fn(usize, u8, usize, usize, usize, usize) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate fewer slots than allocated in descending order, starting from the beginning
    fn allocate_deallocate_partial_4_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize, dealloc_max1: usize, dealloc_max2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        let dealloc_max = dealloc_max1 * 1000 + dealloc_max2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries || dealloc_max >= max { return quickcheck::TestResult::discard() }
        println!("allocate_deallocate_partial_4: entries: {}, bitmap_size_bits: {}, dealloc_max: {} max: {}", entries, bitmap_size_bits, dealloc_max, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return quickcheck::TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return quickcheck::TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !deallocate_descending(&mut bm, 0, dealloc_max) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, dealloc_max, 1) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, dealloc_max, max, 0) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(0)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_4() {
        quickcheck(allocate_deallocate_partial_4_prop as fn(usize, u8, usize, usize, usize, usize) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate fewer slots than allocated in ascending order, starting from a random point inside the bitmap
    fn allocate_deallocate_partial_5_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize, min1: usize, min2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        let min = min1 * 1000 + min2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries || min >= max { return quickcheck::TestResult::discard() }
         println!("allocate_deallocate_partial_5: entries: {}, bitmap_size_bits: {}, min: {}, max: {}", entries, bitmap_size_bits, min, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return quickcheck::TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return quickcheck::TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !deallocate_ascending(&mut bm, min, max) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, min, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, min, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(min)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_5() {
        quickcheck(allocate_deallocate_partial_5_prop as fn(usize, u8, usize, usize, usize, usize) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate fewer slots than allocated in ascending order, starting from a random point inside the bitmap
    fn allocate_deallocate_partial_6_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize, min1: usize, min2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        let min = min1 * 1000 + min2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries || min >= max { return quickcheck::TestResult::discard() }
         println!("allocate_deallocate_partial_6: entries: {}, bitmap_size_bits: {}, min: {}, max: {}", entries, bitmap_size_bits, min, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return quickcheck::TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return quickcheck::TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !deallocate_descending(&mut bm, min, max) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, min, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, min, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(min)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_6() {
        quickcheck(allocate_deallocate_partial_6_prop as fn(usize, u8, usize, usize, usize, usize) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate fewer slots than allocated in ascending order, starting from a random point inside the bitmap and leaving some allocated slots at the end
    fn allocate_deallocate_partial_7_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize, min1: usize, min2: usize, dealloc_max1: usize, dealloc_max2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        let min = min1 * 1000 + min2;
        let dealloc_max = dealloc_max1 * 1000 + dealloc_max2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries || min >= max || dealloc_max <= min || dealloc_max >= max { return quickcheck::TestResult::discard() }
         println!("allocate_deallocate_partial_7: entries: {}, bitmap_size_bits: {}, min: {}, dealloc_max: {}, max: {}", entries, bitmap_size_bits, min, dealloc_max, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return quickcheck::TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return quickcheck::TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !deallocate_ascending(&mut bm, min, dealloc_max) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, min, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, min, dealloc_max, 1) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, dealloc_max, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(min)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_7() {
        quickcheck(allocate_deallocate_partial_7_prop as fn(usize, u8, usize, usize, usize, usize, usize, usize) -> quickcheck::TestResult);
    }

    ///allocate fewer than the maximum and then deallocate fewer slots than allocated in descending order, starting from a random point inside the bitmap and leaving some allocated slots at the end
    fn allocate_deallocate_partial_8_prop(entries: usize, bitmap_size_bits: u8, max1: usize, max2: usize, min1: usize, min2: usize, dealloc_max1: usize, dealloc_max2: usize) -> quickcheck::TestResult {
        let entries = entries * 1000;
        let max = max1 * 1000 + max2;
        let min = min1 * 1000 + min2;
        let dealloc_max = dealloc_max1 * 1000 + dealloc_max2;
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 || max == 0 || max >= entries || min >= max || dealloc_max <= min || dealloc_max >= max { return quickcheck::TestResult::discard() }
         println!("allocate_deallocate_partial_8: entries: {}, bitmap_size_bits: {}, min: {}, dealloc_max: {}, max: {}", entries, bitmap_size_bits, min, dealloc_max, max);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        if !allocate(&mut bm, max) { return quickcheck::TestResult::from_bool(false) }
        if !check_first_set(&mut bm, Some(max)) { return quickcheck::TestResult::from_bool(false); }

        if !check_range(&mut bm, 0, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !deallocate_descending(&mut bm, min, dealloc_max) { return quickcheck::TestResult::from_bool(false) }

        if !check_range(&mut bm, 0, min, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, min, dealloc_max, 1) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, dealloc_max, max, 0) { return quickcheck::TestResult::from_bool(false) }
        if !check_range(&mut bm, max, entries, 1) { return quickcheck::TestResult::from_bool(false) }

        if !check_first_set(&mut bm, Some(min)) { return quickcheck::TestResult::from_bool(false); }
        quickcheck::TestResult::from_bool(true)
    }

    #[test]
    fn allocate_deallocate_partial_8() {
        quickcheck(allocate_deallocate_partial_8_prop as fn(usize, u8, usize, usize, usize, usize, usize, usize) -> quickcheck::TestResult);
    }

    fn allocate_deallocate_random_prop(entries: usize, bitmap_size_bits: u8) -> TestResult {
        let entries = entries * 100; 
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 { return TestResult::discard() }
         println!("allocate_deallocate_random: entries: {}, bitmap_size_bits: {}", entries, bitmap_size_bits);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        let mut bm_ref: Bitmap<Vec<usize>, OneBit> = Bitmap::from_storage(
            entries,
            (),
            vec![!0; entries / mem::size_of::<usize>() * 8],
        ).unwrap();
        let mut rng = thread_rng();
        let mut free = entries;
        let rounds = entries * 10;
        for i in 0..rounds {
            if free == entries || free > 0 && rng.gen_bool(0.5) {
                let slots = rng.gen_range(0, free);
                for i in 0..slots{
                    let first_set = bm.first_set().unwrap();
                    let first_set_ref = bm_ref.first_set().unwrap();
                    if first_set != first_set_ref {
                        println!("first_set() return value of {} differs from the reference bitmap value of {}", first_set, first_set_ref);
                        return quickcheck::TestResult::from_bool(false);
                    }
                    if !bm.set(first_set, 0) {
                        println!("set() failed for Treemap at {}", first_set); 
                        return quickcheck::TestResult::from_bool(false);
                    }
                    if !bm_ref.set(first_set, 0) {
                        println!("set() failed for reference bitmap at {}", first_set); 
                        return quickcheck::TestResult::from_bool(false);
                    }
                    let val = bm.get(first_set);
                    let val_ref = bm_ref.get(first_set);
                    if val != val_ref {
                        println!("Treemap value of {:?} differs from reference bitmap value of {:?} at {}", val, val_ref, first_set); 
                        return quickcheck::TestResult::from_bool(false);
                    }
                    free -= 1;
                }
            }else{
                let start = rng.gen_range(0, entries);
                let slots = rng.gen_range(0, entries - start);
                for i in start..slots {
                    let val = bm.get(i);
                    let val_ref = bm_ref.get(i);
                    if val != val_ref {
                        println!("Treemap value of {:?} differs from reference bitmap value of {:?} at {}", val, val_ref, i); 
                        return quickcheck::TestResult::from_bool(false);
                    }
                    if val_ref.unwrap() == 1 {
                        continue;
                    }
                    if !bm.set(i, 1) {
                        println!("set() failed for Treemap at {}", i); 
                        return quickcheck::TestResult::from_bool(false);
                    }
                    if !bm_ref.set(i, 1) {
                        println!("set() failed for reference bitmap at {}", i); 
                        return quickcheck::TestResult::from_bool(false);
                    }
                    let val = bm.get(i);
                    let val_ref = bm_ref.get(i);
                    if val != val_ref {
                        println!("Treemap value of {:?} differs from reference bitmap value of {:?} at {}", val, val_ref, i); 
                        return quickcheck::TestResult::from_bool(false);
                    }
                    free += 1;
                }
            }
            for i in 0..bm.len() {
                let val = bm.get(i);
                let val_ref = bm_ref.get(i);
                if val != val_ref {
                    println!("Treemap value of {:?} differs from reference bitmap value of {:?} at {}", val, val_ref, i); 
                    return quickcheck::TestResult::from_bool(false);
                }
            }
        }

        TestResult::from_bool(true)

    }

    #[test]
    fn allocate_deallocate_random() {
        quickcheck(allocate_deallocate_random_prop as fn(usize, u8) -> quickcheck::TestResult);
    }

    fn get_set_random_prop(entries: usize, bitmap_size_bits: u8) -> TestResult {
        let entries = entries * 100; 
        if bitmap_size_bits >= bits() as u8 || (1 << bitmap_size_bits) > entries || bitmap_size_bits < 6 { return TestResult::discard() }
         println!("get_set_random: entries: {}, bitmap_size_bits: {}", entries, bitmap_size_bits);

        let mut bm: Treemap = Treemap::new(entries, bitmap_size_bits).unwrap();
        let mut bm_ref: Bitmap<Vec<usize>, OneBit> = Bitmap::from_storage(
            entries,
            (),
            vec![!0; entries / mem::size_of::<usize>() * 8],
        ).unwrap();
        let mut rng = thread_rng();
        let rounds = entries * 10;
        for i in 0..rounds {
            let mut new_value = 0;
            if rng.gen_bool(0.5) {
                new_value = 1;
            }
            let idx = rng.gen_range(0, entries);

            if !bm.set(idx, new_value) {
                println!("set() failed for Treemap at {}", idx); 
                return quickcheck::TestResult::from_bool(false);
            }
            if !bm_ref.set(idx, new_value) {
                println!("set() failed for reference bitmap at {}", idx); 
                return quickcheck::TestResult::from_bool(false);
            }
            let val = bm.get(idx);
            let val_ref = bm_ref.get(idx);
            if val != val_ref {
                println!("Treemap value of {:?} differs from reference bitmap value of {:?} at {}", val, val_ref, idx); 
                return quickcheck::TestResult::from_bool(false);
            }
            for i in 0..bm.len() {
                let val = bm.get(i);
                let val_ref = bm_ref.get(i);
                if val != val_ref {
                    println!("Treemap value of {:?} differs from reference bitmap value of {:?} at {}", val, val_ref, i); 
                    return quickcheck::TestResult::from_bool(false);
                }
            }
        }

        TestResult::from_bool(true)

    }

    #[test]
    fn get_set_random() {
        quickcheck(get_set_random_prop as fn(usize, u8) -> quickcheck::TestResult);
    }
}
