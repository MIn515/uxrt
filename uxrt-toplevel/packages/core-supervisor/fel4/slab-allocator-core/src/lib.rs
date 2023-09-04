// Copyright 2021 Andrew Warkentin
// Copyright 2017 Robert Węcławski
//
// Licensed under the the MIT license <LICENSE or 
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! A generic slab heap allocator with support for custom object sizes. 
//! Requires a platform-specfic wrapper.

#![feature(allocator_api)]
#![no_std]

extern crate alloc;
extern crate sparse_array;
extern crate intrusive_collections;
extern crate custom_slab_allocator;

#[macro_use]
mod slab;

use core::cell::{Cell, RefCell};
use core::ptr::NonNull;
use core::fmt;

use slab::{
    DeallocMode,
    SlabManager
};
use alloc::{
    alloc::{AllocError, Layout},
    boxed::Box,
};

pub use slab::add_custom_slabs;

use intrusive_collections::{
    intrusive_adapter, rbtree, KeyAdapter, RBTree, UnsafeRef
};

#[macro_use]
extern crate log;

#[cfg(test)]
mod test;

pub const NUM_GENERIC_SLABS: usize = 12;

///RBTree node holding a custom slab
struct CustomSlab {
    contents: SlabManager,
    size: usize,
    main_link: rbtree::Link,
    refill_link: rbtree::Link,
}

intrusive_adapter!(MainAdapter = UnsafeRef<CustomSlab>: CustomSlab { main_link: rbtree::Link });

impl<'a> KeyAdapter<'a> for MainAdapter {
    type Key = usize;
    fn get_key(&self, node: &'a CustomSlab) -> usize {
        node.size
    }
}

intrusive_adapter!(RefillAdapter = UnsafeRef<CustomSlab>: CustomSlab { refill_link: rbtree::Link });

impl<'a> KeyAdapter<'a> for RefillAdapter {
    type Key = usize;
    fn get_key(&self, node: &'a CustomSlab) -> usize {
        node.size
    }
}

///Trait for wrapper objects that map and unmap pages
pub trait PageProvider {
    ///Allocates a contiguous virtual memory region of the given size in 
    ///bytes; it will always be a multiple of the page size passed to 
    ///Heap::new().
    ///
    ///Returns the starting virtual address of the allocated region on 
    ///success.
    fn allocate_pages(&self, size: usize) -> Result<usize, ()>;
    ///Deallocates the given virtual memory region.
    ///
    ///As with allocate_pages, the size is in bytes and will always be a 
    ///multiple of the page size.
    ///
    fn deallocate_pages(&self, addr: usize, size: usize) -> Result<(), ()>;
}

///Parameters needed to create a bootstrap slab.
///
///The arguments are respectively:
///
///`start_addr` - start address of the slab.
///`slab_size` - size of the slab in blocks.
///`block_size` - block size of the slab.
pub struct BootstrapSlabInfo(pub usize, pub usize, pub usize);
///Parameters needed to initialize dynamic allocation for each standard block 
///size.
///
///The arguments are respectively:
///
///`slab_size` - slab size for dynamic slabs, which doesn't have to be the 
///same as for the corresponding bootstrap slab.
///`min_free` - minimum free blocks for this size (when the total free blocks 
///between all slabs of this size are below this, a new slab will be 
///allocated)
///`max_dealloc_slabs` - maximum number of slabs that may be deallocated 
///in a single lock-deallocate-unlock cycle
///`max_drop_rounds` - the maximum number of iterations to attempt when 
///dropping unused slabs.
pub struct DynamicSlabInfo(pub usize, pub usize, pub usize, pub usize);

/// A dynamic size heap backed by multiple slabs with blocks of different
/// sizes. A set of standard power-of-two block sizes from 16 to 32768 are 
/// provided, and it is also possible to add custom block sizes (recommended
/// for objects that are a fixed non-power-of-two size).
///
/// Acts as a fixed size heap until dynamic allocation is initialized.
///
/// A platform-specific wrapper is required for this to be used as a global 
/// allocator. An example of such a wrapper can be found in sel4_alloc::heap.
pub struct Heap {
    generic_slabs: [SlabManager; NUM_GENERIC_SLABS],
    custom_slabs: RefCell<RBTree<MainAdapter>>,
    refill_custom_slabs: RefCell<RBTree<RefillAdapter>>,
    lock_count: Cell<u32>,
    page_bits: u32,
    dynamic_initialized: Cell<bool>,
    custom_slab_params: Cell<Option<(usize, usize, usize, usize)>>,
}

impl Heap {
    /// Creates a new heap in bootstrap state (i.e. dynamic growing and 
    /// shrinking disabled) with slabs having the given `start_addr`, 
    /// `slab_size`, and `block_size`. It is possible to specify a zero 
    /// `slab_size` for a slab that will not be used while in bootstrap 
    /// state. For each slab of non-zero size, the start address must be 
    /// valid and the memory in each `(start_addr, start_addr + slab_size)`
    /// range must not be used for anything else. 
    ///
    /// This function is unsafe because it can cause undefined behavior if 
    /// any of the given address ranges are invalid.
    ///
    /// It is recommended that the bootstrap slabs are created using the
    /// bootstrap_heap!() macro.
    ///
    /// All methods that allocate take an object implementing `PageProvider`
    /// to map/unmap pages.
    pub unsafe fn new(slab_info: [BootstrapSlabInfo; NUM_GENERIC_SLABS], page_bits: u32) -> Heap {
        Heap {
            generic_slabs: [
                SlabManager::new(slab_info[0].0, slab_info[0].1, slab_info[0].2, page_bits),
                SlabManager::new(slab_info[1].0, slab_info[1].1, slab_info[1].2, page_bits),
                SlabManager::new(slab_info[2].0, slab_info[2].1, slab_info[2].2, page_bits),
                SlabManager::new(slab_info[3].0, slab_info[3].1, slab_info[3].2, page_bits),
                SlabManager::new(slab_info[4].0, slab_info[4].1, slab_info[4].2, page_bits),
                SlabManager::new(slab_info[5].0, slab_info[5].1, slab_info[5].2, page_bits),
                SlabManager::new(slab_info[6].0, slab_info[6].1, slab_info[6].2, page_bits),
                SlabManager::new(slab_info[7].0, slab_info[7].1, slab_info[7].2, page_bits),
                SlabManager::new(slab_info[8].0, slab_info[8].1, slab_info[8].2, page_bits),
                SlabManager::new(slab_info[9].0, slab_info[9].1, slab_info[9].2, page_bits),
                SlabManager::new(slab_info[10].0, slab_info[10].1, slab_info[10].2, page_bits),
                SlabManager::new(slab_info[11].0, slab_info[11].1, slab_info[11].2, page_bits),
            ],
            custom_slabs: Default::default(),
            refill_custom_slabs: Default::default(),
            lock_count: Cell::new(0),
            page_bits,
            dynamic_initialized: Cell::new(false),
            custom_slab_params: Cell::new(None), 
        }
    }

    ///Initializes dynamic growing and shrinking of the heap.
    ///
    ///Takes an array of DynamicSlabInfo objects and a page provider.
    pub fn init_dynamic<P: PageProvider>(&self, slab_info: [DynamicSlabInfo; NUM_GENERIC_SLABS], page_provider: Option<&P>) {
        for i in 0..NUM_GENERIC_SLABS {
            unsafe { self.generic_slabs[i].init_dynamic(slab_info[i].0, slab_info[i].1, slab_info[i].2, slab_info[i].3, page_provider); }
            self.generic_slabs[i].lock();
        }
        for i in 0..NUM_GENERIC_SLABS {
            self.generic_slabs[i].refill(page_provider);
        }
        for i in 0..NUM_GENERIC_SLABS {
            self.generic_slabs[i].drop_slabs(page_provider);
        }
        for i in 0..NUM_GENERIC_SLABS {
            self.generic_slabs[i].unlock();
        }
        self.dynamic_initialized.set(true);
    }
    ///Internal function to update the parameters of a pre-existing slab
    fn update_slab(slab: &SlabManager, slab_size: usize, min_free: usize, max_dealloc_slabs: usize, max_drop_rounds: usize) {
        if slab_size > slab.get_dynamic_slab_size(){
            slab.set_dynamic_slab_size(slab_size);
        }
        if min_free > slab.get_min_free(){
            slab.set_min_free(min_free);
        }
        if max_dealloc_slabs > slab.get_max_dealloc_slabs(){
            slab.set_max_dealloc_slabs(max_dealloc_slabs);
        }
        if max_drop_rounds > slab.get_max_drop_rounds(){
            slab.set_max_drop_rounds(max_drop_rounds);
        }
    }
    ///Adds a new custom slab.
    ///
    ///If an existing slab of the requested block size exists, a new slab will
    ///not be allocated. Instead, the existing slab will be updated, with each
    ///size parameter that is bigger than the existing one being changed to 
    ///the new size (any parameter that is smaller than the existing one will
    ///have no effect)
    ///
    ///`block_size` and `slab_size` are the block size and slab size for the
    ///custom slab. Remaining size arguments have the same meaning as those of
    ///DynamicSlabInfo. If this slab is for an object not used internally by
    ///an allocator, all sizes besides `block_size` and `slab_size` may be 
    ///zero.
    pub fn add_custom_slab<P: PageProvider>(&self, block_size: usize, slab_size: usize, min_free: usize, max_dealloc_slabs: usize, max_drop_rounds: usize, page_provider: Option<&P>) -> Result<(), ()>{
        if !self.dynamic_initialized.get() {
            return Err(());
        }
        alloc_debug_println!("Heap::add_custom_slab: {} {} {} {} {}", block_size, slab_size, min_free, max_dealloc_slabs, max_drop_rounds);

        self.lock(0, page_provider);
        for i in 0..NUM_GENERIC_SLABS {
            let slab = &self.generic_slabs[i];
            if block_size == slab.get_block_size() {
                alloc_debug_println!("updating standard slab");
                Self::update_slab(&slab, slab_size, min_free, max_dealloc_slabs, max_drop_rounds);
                self.unlock(0, page_provider);
                return Ok(());
            }
        }
        let custom_slabs = self.custom_slabs.borrow();
        let cursor = custom_slabs.find(&block_size);
        let node_ref;
        let mut add_new = false;
        if cursor.is_null(){
            alloc_debug_println!("adding new slab");

            let slab_manager = unsafe { SlabManager::new_dynamic(block_size, slab_size, self.page_bits, page_provider) };
            let node = CustomSlab {
                contents: slab_manager,
                size: block_size,
                main_link: Default::default(),
                refill_link: Default::default(),
            };
            node_ref = UnsafeRef::from_box(Box::new(node));
            add_new = true;
            unsafe { node_ref.contents.init_dynamic(slab_size, min_free, max_dealloc_slabs, max_drop_rounds, page_provider) };

        }else{
            alloc_debug_println!("updating custom slab");
            let node = cursor.get().unwrap();
            node_ref = unsafe{ UnsafeRef::from_raw(node) };
            Self::update_slab(&node.contents, slab_size, min_free, max_dealloc_slabs, max_drop_rounds);
        }
        drop(custom_slabs);
        self.unlock(0, page_provider);

        if add_new {
            let mut custom_slabs = self.custom_slabs.borrow_mut();
            custom_slabs.insert(node_ref.clone());
        }
        if min_free > 0 || max_dealloc_slabs > 0 {
            let mut refill_custom_slabs = self.refill_custom_slabs.borrow_mut();
            let refill_cursor = refill_custom_slabs.find_mut(&block_size);
            if refill_cursor.is_null(){
                refill_custom_slabs.insert(node_ref.clone());
            }
        }

        alloc_debug_println!("SlabManager::add_custom_slab: done");

        Ok(())
    }
    ///Makes the next allocation automatically add a new custom slab size
    ///with the given parameters rather than using generic slabs if no custom
    ///slab size already exists.
    ///
    ///This is intended for allocating custom slabs for objects in containers
    ///where the size of the underlying allocation cannot be easily obtained,
    ///e.g. Arc
    ///
    ///This must be called before each allocation that should add a custom 
    ///slab
    pub fn add_next_custom_slab(&self, slab_size: usize, min_free: usize, max_dealloc_slabs: usize, max_drop_rounds: usize) -> Result<(), ()>{
        self.custom_slab_params.set(Some((slab_size, min_free, max_dealloc_slabs, max_drop_rounds)));
        Ok(())
    }
    ///Internal implementation for lock_*
    fn lock<P: PageProvider>(&self, block_size: usize, page_provider: Option<&P>){
        alloc_debug_println!("Heap::lock");
        alloc_debug_println!("{}", self.lock_count.get());

        self.lock_count.set(self.lock_count.get() + 1);

        if self.lock_count.get() > 1 {
            return;
        }
        for i in 0..NUM_GENERIC_SLABS {
            alloc_debug_println!("Heap::lock: locking slab: {}", self.generic_slabs[i].get_block_size());
            self.generic_slabs[i].lock();
        }

        let refill_custom_slabs = self.refill_custom_slabs.borrow();
        let mut cursor = refill_custom_slabs.front();
        while !cursor.is_null(){
            cursor.get().unwrap().contents.lock();
            alloc_debug_println!("Heap::lock: locking slab: {}", cursor.get().unwrap().contents.get_block_size());
            cursor.move_next();
        }
        let mut requested_size_found = false;
        for i in 0..NUM_GENERIC_SLABS {
            alloc_debug_println!("Heap::lock: {} {} {} {}", i, block_size, self.generic_slabs[i].get_block_size(), self.generic_slabs[i].get_min_free());
            if self.generic_slabs[i].get_block_size() == block_size || self.generic_slabs[i].get_min_free() != 0 {
                alloc_debug_println!("Heap::lock: refilling slab: {} {} {} {}", i, block_size, self.generic_slabs[i].get_block_size(), self.generic_slabs[i].get_min_free());
                self.generic_slabs[i].refill(page_provider);
                alloc_debug_println!("Heap::lock: done");
            }
            if self.generic_slabs[i].get_block_size() == block_size {
                requested_size_found = true;
            }
        }
        let mut cursor = refill_custom_slabs.front();
        while !cursor.is_null(){
            let slab = &cursor.get().unwrap().contents;
            if slab.get_block_size() == block_size || slab.get_min_free() != 0 {
                alloc_debug_println!("Heap::lock: refilling slab: {} {} {}", block_size, slab.get_block_size(), slab.get_min_free());
                slab.refill(page_provider);
                alloc_debug_println!("Heap::lock: done");
            }
            if slab.get_block_size() == block_size {
                requested_size_found = true;
            }
            cursor.move_next();
        }
        if !requested_size_found {
            let custom_slabs = self.custom_slabs.borrow();
            let cursor = custom_slabs.find(&block_size);
            if !cursor.is_null(){
                let slab = &cursor.get().unwrap().contents;
                alloc_debug_println!("Heap::lock: refilling slab: {} {} {}", block_size, slab.get_block_size(), slab.get_min_free());
                slab.lock();
                slab.refill(page_provider);
                alloc_debug_println!("Heap::lock: done");
            }
        }
    }
    ///Internal implementation for lock_allocate
    fn lock_allocate_internal<P: PageProvider>(&self, block_size: usize, page_provider: Option<&P>){
        self.lock(block_size, page_provider);
    }
    ///Acquires the recursion lock before allocating. If this is the top-level
    ///call, all slabs with non-zero minimum free counts will be checked and
    ///refilled if necessary.
    ///
    ///This is reentrant and may be called recursively as long as there is a 
    ///corresponding call to one of the unlock_* methods for each call to this
    ///
    ///This lock is only to break dependency cycles and does NOT make this 
    ///allocator thread-safe as is. The wrapper must provide its own lock in 
    ///order to be used in a multi-threaded environment.
    pub fn lock_allocate<P: PageProvider>(&self, page_provider: Option<&P>){
        self.lock(0, page_provider);
    }
    ///Acquires the recursion lock before allocating. Currently does the same
    ///thing as lock_allocate.
    pub fn lock_deallocate<P: PageProvider>(&self, page_provider: Option<&P>){
        self.lock(0, page_provider);
    }
    ///Internal implementation for unlock_*
    fn unlock<P: PageProvider>(&self, block_size: usize, page_provider: Option<&P>){
        alloc_debug_println!("Heap::unlock");
        alloc_debug_println!("{}", self.lock_count.get());

        if self.lock_count.get() == 1 {
            let mut requested_size_found = false;
            for i in 0..NUM_GENERIC_SLABS {
                alloc_debug_println!("Heap::unlock: deallocating leftover slabs at index {}", i);
                self.generic_slabs[i].drop_slabs(page_provider);
                if self.generic_slabs[i].get_block_size() == block_size {
                    requested_size_found = true;
                }

                alloc_debug_println!("done");
            }

            let refill_custom_slabs = self.refill_custom_slabs.borrow();

            let mut cursor = refill_custom_slabs.front();
            while !cursor.is_null(){
                let slab = &cursor.get().unwrap().contents;
                alloc_debug_println!("Heap::unlock: deallocating leftover slabs for size {}", cursor.get().unwrap().size);
                slab.drop_slabs(page_provider);
                if slab.get_block_size() == block_size {
                    requested_size_found = true;
                }
                cursor.move_next();
                alloc_debug_println!("done");
            }

            if !requested_size_found {
                let custom_slabs = self.custom_slabs.borrow();
                let cursor = custom_slabs.find(&block_size);

                if !cursor.is_null(){
                    let slab = &cursor.get().unwrap().contents;
                    alloc_debug_println!("Heap::unlock: deallocating leftover slabs for size {}", cursor.get().unwrap().size);
                    slab.drop_slabs(page_provider);
                    alloc_debug_println!("done");
                }
            }

            for i in 0..NUM_GENERIC_SLABS {
                alloc_debug_println!("Heap::unlock: unlocking index {}", i);
                self.generic_slabs[i].unlock();
                alloc_debug_println!("done");
            }

            if !requested_size_found {
                let custom_slabs = self.custom_slabs.borrow();
                let cursor = custom_slabs.find(&block_size);

                if !cursor.is_null(){
                    let slab = &cursor.get().unwrap().contents;
                    slab.unlock();
                }
            }
            {
                let mut cursor = refill_custom_slabs.front();
                while !cursor.is_null(){
                    let slab = &cursor.get().unwrap().contents;
                    alloc_debug_println!("Heap::unlock: unlocking slab of size {}", cursor.get().unwrap().size);
                    slab.unlock();
                    cursor.move_next();
                    alloc_debug_println!("done");
                }
            }
        }
        self.lock_count.set(self.lock_count.get() - 1);
    }
    ///Internal implementation of unlock_allocate
    fn unlock_allocate_internal<P: PageProvider>(&self, block_size: usize, page_provider: Option<&P>){
        self.unlock(block_size, page_provider);
    }
    ///Releases the recursion lock after allocating. If this is the top-level 
    ///call, any unneeded slabs will be unmapped.
    pub fn unlock_allocate<P: PageProvider>(&self, page_provider: Option<&P>){
        self.unlock_allocate_internal(0, page_provider);
    }
    ///Internal implementation of unlock_deallocate
    fn unlock_deallocate_internal<P: PageProvider>(&self, block_size: usize, page_provider: Option<&P>){
        self.unlock(block_size, page_provider);
    }
    ///Releases the recursion lock after deallocating. If this is the
    ///top-level call, any unneeded slabs will be unmapped.
    pub fn unlock_deallocate<P: PageProvider>(&self, page_provider: Option<&P>){
        self.unlock_deallocate_internal(0, page_provider);
    }
    /// Allocates a chunk of the given size with the given alignment. Returns 
    /// a pointer to the beginning of that chunk if it was successful. Else it
    /// returns `Err`.
    ///
    /// This function finds the slab of the lowest size which can still 
    /// acommodate the given chunk.
    pub fn allocate<P: PageProvider>(&self, layout: Layout, page_provider: Option<&P>) -> Result<*mut u8, AllocError> {
        let ret;
        alloc_debug_println!("Heap::allocate: {} {}", layout.size(), layout.align());

        let mut custom_slabs = self.custom_slabs.borrow();
        let block_size = layout.size();
        let mut cursor = custom_slabs.find(&block_size);
 
        if let Some((slab_size, min_free, max_dealloc_slabs, max_drop_rounds)) = self.custom_slab_params.get() {
            self.custom_slab_params.set(None);
            if cursor.is_null() {
                alloc_debug_println!("no custom slabs found for size {}; adding one", block_size);
                drop(cursor);
                drop(custom_slabs);

                if self.add_custom_slab(block_size, slab_size, min_free, max_dealloc_slabs, max_drop_rounds, page_provider).is_err() {
                    return Err(AllocError);
                }
                custom_slabs = self.custom_slabs.borrow();
                cursor = custom_slabs.find(&block_size);
            }
        }

        if cursor.is_null(){
            if let Some(idx) = self.get_generic_slab_idx(&layout) {
                alloc_debug_println!("no custom slabs found; using generic slab of size {}", self.generic_slabs[idx].get_block_size());
                self.lock_allocate_internal(self.generic_slabs[idx].get_block_size(), page_provider);
                ret = self.generic_slabs[idx].allocate(layout, page_provider)
            }else{
                panic!("attempt to allocate a block bigger than the maximum; size: {}, align: {}", layout.size(), layout.align())
            }
        }else{
            alloc_debug_println!("custom slabs found");
            let node = cursor.get().unwrap();
            self.lock_allocate_internal(layout.size(), page_provider);
            ret = node.contents.allocate(layout, page_provider);
        }
        self.unlock_allocate_internal(layout.size(), page_provider);

        alloc_debug_println!("Heap::allocate: ok");
        alloc_debug_println!("ok: {}", ret.is_ok());
        if ret.is_err(){
            error!("Heap::allocate: allocation for size {} and alignment {} failed", layout.size(), layout.align());
            error!("allocator state: {:?}", self);
        }
        ret
    }

    /// Same as allocate(), but returns NonNull<u8> instead of *mut u8
    pub unsafe fn allocate_nonnull<P: PageProvider>(&self, layout: Layout, page_provider: Option<&P>) -> Result<NonNull<u8>, AllocError> {
        self.allocate(layout, page_provider).and_then(|ptr|{ Ok(NonNull::new(ptr).unwrap()) })
    }

    /// Same as allocate(), but returns a null pointer on failure rather than 
    /// returning a Result
    pub unsafe fn allocate_raw<P: PageProvider>(&self, layout: Layout, page_provider: Option<&P>) -> *mut u8 {
        alloc_debug_println!("Heap::allocate_raw: {} {}", layout.size(), layout.align());
        if let Ok(ptr) = self.allocate(layout, page_provider){
            alloc_debug_println!("Heap::allocate_raw: object start: {:p}", ptr);
            ptr
        }else{
            let ret: *mut u8 = core::ptr::null_mut();
            ret
        }
    }

    /// Frees the given allocation. `ptr` must be a pointer returned
    /// by a call to the `allocate` function with identical size and alignment. Undefined
    /// behavior may occur for invalid arguments, thus this function is unsafe.
    ///
    /// This function finds the slab which contains the address of `ptr` and
    /// adds the blocks beginning with `ptr` address to the list of free 
    /// blocks (if dynamic allocation has been initialized the slab itself may
    /// be unmapped if it is no longer needed). 
    pub unsafe fn deallocate<P: PageProvider>(&self, ptr: *mut u8, layout: Layout, page_provider: Option<&P>) {
        alloc_debug_println!("Heap::deallocate: {:p}", ptr);
        self.lock_deallocate(page_provider);
        let custom_slabs = self.custom_slabs.borrow();
        let cursor = custom_slabs.find(&layout.size());
        let mut custom = false;
        if !cursor.is_null(){
            let node = cursor.get().unwrap();
            if node.contents.deallocate(ptr, page_provider, DeallocMode::FallThrough).is_ok(){
                custom = true;
            }
        }
        if !custom {
            if let Some(idx) = self.get_generic_slab_idx(&layout) {
                if self.generic_slabs[idx].deallocate(ptr, page_provider, DeallocMode::Normal).is_err() {
                        
                    error!("Heap::deallocate: failed, allocator state: {:?}", self);
                    panic!("failed to deallocate object at address {:p} with size {} and alignment {}", ptr, layout.size(), layout.align());
                }
            }else{
                panic!("attempt to deallocate a block that was too big; this shouldn't happen");
            }
        }
        self.unlock_deallocate_internal(layout.size(), page_provider);
        alloc_debug_println!("Heap::deallocate: ok");
    }

    /// Same as deallocate(), but takes a NonNull<u8> instead of a *mut u8
    pub unsafe fn deallocate_nonnull<P: PageProvider>(&self, ptr: NonNull<u8>, layout: Layout, page_provider: Option<&P>) {
        self.deallocate(ptr.as_ptr(), layout, page_provider)
    }

    ///Reallocates the given allocation. If the original underlying block size
    ///was bigger than the original allocation and the new size still fits 
    ///within the block size, this will just return the original pointer as 
    ///is. Otherwise, a new block will be allocated, the allocation will be
    ///moved, and the old block will be freed.
    pub unsafe fn reallocate<P: PageProvider>(&self, ptr: *mut u8, old_layout: Layout, new_size: usize, page_provider: Option<&P>) -> Result<*mut u8, AllocError> {
        let new_layout = Layout::from_size_align(new_size, old_layout.align());
        if new_layout.is_err(){
            warn!("Heap::reallocate: could not get layout for size {} and alignment {}", new_size, old_layout.align());
            return Err(AllocError);
        }


        let old_idx = self.get_generic_slab_idx(&old_layout);
        let new_idx = self.get_generic_slab_idx(new_layout.as_ref().unwrap());
 
        if old_idx.is_none() || new_idx.is_none() {
            panic!("attempt to reallocate a block bigger than the maximum; old size: {}, old align: {}, new size: {}, new align: {}", old_layout.size(), old_layout.align(), new_layout.as_ref().unwrap().size(), new_layout.as_ref().unwrap().align());
        }
        let is_generic = self.generic_slabs[old_idx.unwrap()].deallocate(ptr, page_provider, DeallocMode::Mock).is_ok();

        if old_idx == new_idx && is_generic {
            return Ok(ptr);
        }
        self.allocate(new_layout.unwrap(), page_provider).map(|new| {
            Self::copy(new, ptr, old_layout.size());
            self.deallocate(ptr, old_layout, page_provider);
            new
        })

    }

    ///Same as reallocate() but returns null on failure rather than returning
    ///a Result.
    pub unsafe fn reallocate_raw<P: PageProvider>(&self, ptr: *mut u8, layout: Layout, new_size: usize, page_provider: Option<&P>) -> *mut u8 {
        if let Ok(ptr) = self.reallocate(ptr, layout, new_size, page_provider){
            ptr
        }else{
            let ret: *mut u8 = core::ptr::null_mut();
            ret
        }
    }

    ///Internal method to copy memory for reallocation
    unsafe fn copy(dest: *mut u8, src: *const u8, n: usize) {
        let mut i = 0;
        while i < n {
            *dest.offset(i as isize) = *src.offset(i as isize);
            i += 1;
        }
    }

    /// Returns bounds on the guaranteed usable size of a successful
    /// allocation created with the specified `layout`.
    pub fn usable_size(&self, layout: &Layout) -> (usize, usize) {
        if let Some(idx) = self.get_generic_slab_idx(layout) {
            (layout.size(), self.generic_slabs[idx].get_block_size())
        }else{
            panic!("attempt to get the usable size for an unsupported layout size; this shouldn't happen");
        }
    }

    ///Finds generic slab to use based on layout size and alignment
    pub fn get_generic_slab_idx(&self, layout: &Layout) -> Option<usize> {
        if layout.align() > 1 << self.page_bits {
            return None;
        }
        for i in 0..NUM_GENERIC_SLABS {
            let block_size = self.generic_slabs[i].get_block_size();
            if layout.size() <= block_size && layout.align() <= block_size {
                return Some(i);
            }
        }
        None
    }
}

impl fmt::Debug for Heap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Slabs:").unwrap();
        for slab in 0..self.generic_slabs.len(){
            write!(f, "{:?}", self.generic_slabs[slab]).unwrap();
        }
        let custom_slabs = self.custom_slabs.borrow();
        let mut cursor = custom_slabs.front();
        while !cursor.is_null(){
            write!(f, "{:?}", cursor.get().unwrap().contents).unwrap();
            cursor.move_next();
        }
        Ok(())
    }
}

//unsafe impl Alloc for Heap {
//    unsafe fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, AllocErr> {
//        self.allocate_nonnull(layout)
//    }

//    unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
//        self.deallocate_nonnull(ptr, layout)
//    }

    //fn oom(&mut self, err: AllocErr) -> ! {
    //    panic!("Out of memory: {:?}", err);
    //}

//    fn usable_size(&self, layout: &Layout) -> (usize, usize) {
//        self.usable_size(layout)
//    }
//}
//
//
//

/// Macro to generate a bootstrap heap. It is used by declaring a module and 
/// calling this macro within it.
/// 
/// `scratch_len` is the size of the static array, and `page_size` is the 
/// standard page size.
///
/// This macro generates a static array for the heap and also defines a 
/// bootstrap_heap_info() function to create a list of slabs from the array. 
/// This function takes a list of slab sizes and returns an array of 
/// BootstrapSlabInfo objects.
#[macro_export]
macro_rules! bootstrap_heap {
    ($scratch_len:expr,$page_size:expr) => {
        use slab_allocator_core::BootstrapSlabInfo;
        #[repr(align(32768))]
        struct ScratchHeap([u8; $scratch_len]);

        static mut SCRATCH_HEAP: ScratchHeap = ScratchHeap([0; $scratch_len]);
        static mut SCRATCH_HEAP_OFFSET: usize = 0;

        fn bootstrap_slab_info(slab_size: usize, block_size: usize) -> BootstrapSlabInfo{
            let slab_bytes = (slab_size * block_size + $page_size - 1) & !($page_size - 1);
            let offset = unsafe { SCRATCH_HEAP_OFFSET };
            unsafe { 
                SCRATCH_HEAP_OFFSET += slab_bytes;
                println!("bootstrap heap used: {}", SCRATCH_HEAP_OFFSET);
                if SCRATCH_HEAP_OFFSET > $scratch_len {
                    panic!("slab of size {} extends past end of bootstrap heap", slab_size);
                }
            };
            let heap_start_addr = unsafe { &SCRATCH_HEAP.0 as *const u8 as usize };
            BootstrapSlabInfo(heap_start_addr + offset, slab_size, block_size)
        }
        pub fn bootstrap_heap_info(info: [usize; NUM_GENERIC_SLABS]) -> [BootstrapSlabInfo; NUM_GENERIC_SLABS] {
            [
                bootstrap_slab_info(info[0], 16),
                bootstrap_slab_info(info[1], 32),
                bootstrap_slab_info(info[2], 64),
                bootstrap_slab_info(info[3], 128),
                bootstrap_slab_info(info[4], 256),
                bootstrap_slab_info(info[5], 512),
                bootstrap_slab_info(info[6], 1024),
                bootstrap_slab_info(info[7], 2048),
                bootstrap_slab_info(info[8], 4096),
                bootstrap_slab_info(info[9], 8192),
                bootstrap_slab_info(info[10], 16384),
                bootstrap_slab_info(info[11], 32768),
            ]
        }
    }
}
