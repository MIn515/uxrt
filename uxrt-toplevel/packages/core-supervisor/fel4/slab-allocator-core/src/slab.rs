// Copyright 2021 Andrew Warkentin       
// Copyright 2017 Robert Węcławski              
//  
// Licensed under the the MIT license <LICENSE or 
// http://opensource.org/licenses/MIT>, at your option. This file may not be 
// copied, modified, or distributed except according to those terms

//! The slab manager and inner linked list allocator

use core::alloc::{AllocError, Layout};
use core::cell::{Cell, RefCell};
use core::fmt;
use core::mem::size_of;
use sparse_array::{UnsafeRef, SubAllocatorManager};
use custom_slab_allocator::CustomSlabAllocator;
use crate::PageProvider;


#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DeallocMode {
    Normal,
    FallThrough,
    Mock,
}


#[macro_export]
macro_rules! alloc_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug")]
        debug!($($toks)*);
    })
}

///Manager for slabs of a given block size
pub struct SlabManager {
    block_size: usize,
    slab_size: Cell<usize>,
    page_bits: u32,
    initial_start_addr: usize,
    initial_slab_size: usize,
    initial_slab: RefCell<Slab>,
    dynamic_slabs: RefCell<Option<SubAllocatorManager<RefCell<Slab>>>>,
    blocks_allocated: Cell<usize>,
}

impl SlabManager {
    ///Creates a new slab manager
    pub unsafe fn new(initial_start_addr: usize, initial_slab_size: usize, block_size: usize, page_bits: u32) -> SlabManager {
        alloc_debug_println!("SlabManager::new: initial_start_addr: {:x}, initial_slab_size: {}, block_size: {}, page_bits: {}", initial_start_addr, initial_slab_size, block_size, page_bits);
        let page_size = 1 << page_bits;
        let initial_slab_bytes = (initial_slab_size * block_size + page_size - 1) & !(page_size - 1);
        alloc_debug_println!("initial_slab_bytes: {}", initial_slab_bytes);
        let slab = Slab::new(initial_start_addr, initial_slab_bytes, block_size);
        SlabManager {
            block_size,
            slab_size: Cell::new(0),
            page_bits,
            initial_start_addr,
            initial_slab_size: initial_slab_bytes,
            initial_slab: RefCell::new(slab),
            dynamic_slabs: RefCell::new(None),
            blocks_allocated: Cell::new(0),
        }
    }
    ///Creates a new slab manager with dynamic allocation initialized
    pub unsafe fn new_dynamic<P: PageProvider>(block_size: usize, slab_size: usize, page_bits: u32, page_provider: Option<&P>) -> SlabManager {
        let page_size = 1 << page_bits;
        let slab_bytes = (slab_size * block_size + page_size - 1) & !(page_size - 1);
        alloc_debug_println!("SlabManager::new_dynamic: slab_bytes: {}", slab_bytes);
        let start_addr = page_provider.unwrap().allocate_pages(slab_bytes).expect("could not allocate pages to initialize custom slab");
        SlabManager::new(start_addr, slab_size, block_size, page_bits)
    }

    ///Initializes dynamic allocation for this SlabManager. This must only be
    ///called when the SlabManager has been moved to its final location, since
    ///it takes a reference to the initial slab stored within the SlabManager 
    ///structure itself and stores it in the internal array
    pub unsafe fn init_dynamic<P: PageProvider>(&self, slab_size: usize, min_free: usize, max_dealloc_slabs: usize, max_drop_rounds: usize, page_provider: Option<&P>) {
        let page_size = 1 << self.page_bits;
        let slab_bytes = (slab_size * self.block_size + page_size - 1) & !(page_size - 1);
        alloc_debug_println!("SlabManager::new_dynamic: slab_bytes: {}", slab_bytes);
        if self.dynamic_slabs.borrow().is_some() {
            panic!("atttempt to call init_dynamic on an allocator that was already initialized");
        }
        self.slab_size.set(slab_bytes);
        let mut initial_start_addr = self.initial_start_addr;
        if self.initial_slab_size == 0 { 
            initial_start_addr = page_provider.unwrap().allocate_pages(slab_bytes).expect("failed to allocate initial slab when initializing dynamic allocator");
            self.initial_slab.replace(Slab::new(initial_start_addr, slab_bytes, self.block_size));
        }

        let initial_blocks = self.initial_slab_size / self.block_size;

        let dynamic_slabs = SubAllocatorManager::new(
            UnsafeRef::from_raw(&self.initial_slab), 
            initial_start_addr, 
            initial_blocks,
            self.page_bits, 
            min_free, 
            max_dealloc_slabs, 
            max_drop_rounds,
            true
        );
        self.dynamic_slabs.replace(Some(dynamic_slabs));
        let dynamic_slabs_opt = self.dynamic_slabs.borrow();
        #[allow(unused_variables)]
        let dynamic_slabs = dynamic_slabs_opt.as_ref().unwrap();

        alloc_debug_println!("SlabManager::init_dynamic: {} {} {}", 
                             self.block_size, 
                             initial_blocks, 
                             dynamic_slabs.get_any(initial_start_addr).unwrap().0.borrow().free_blocks());

    }

    ///Sets the minimum number of free blocks
    pub fn set_min_free(&self, min_free: usize){
        self.dynamic_slabs.borrow().as_ref().unwrap().set_min_free(min_free);
    }
    ///Gets the maximum number of iterations to attempt when dropping 
    ///deallocated slabs
    pub fn get_max_drop_rounds(&self) -> usize{
        self.dynamic_slabs.borrow().as_ref().unwrap().get_max_drop_rounds()
    }
    ///Gets the maximum number of iterations to attempt when dropping 
    ///deallocated slabs
    pub fn set_max_drop_rounds(&self, max_drop_rounds: usize){
        self.dynamic_slabs.borrow().as_ref().unwrap().set_max_drop_rounds(max_drop_rounds);
    }
    ///Gets the maximum number of slabs that can be deallocated in a single
    ///call to allocate() or deallocate()
    pub fn get_max_dealloc_slabs(&self) -> usize{
        self.dynamic_slabs.borrow().as_ref().unwrap().get_max_dealloc_sublevels()
    }
    ///Sets the maximum number of slabs that can be deallocated in a single
    ///call to allocate() or deallocate()
    pub fn set_max_dealloc_slabs(&self, max_dealloc_slabs: usize){
        self.dynamic_slabs.borrow().as_ref().unwrap().set_max_dealloc_sublevels(max_dealloc_slabs);
    }
    ///Gets the current size for new dynamic slabs
    pub fn get_dynamic_slab_size(&self) -> usize {
        self.slab_size.get()
    }
    ///Sets the size for new dynamic slabs
    pub fn set_dynamic_slab_size(&self, size: usize) {
        let page_size = 1 << self.page_bits;
        if self.dynamic_slabs.borrow().is_some() && self.dynamic_slabs.borrow().as_ref().unwrap().len() > 1 {
            panic!("cannot change slab size after sublevels have been allocated");
        }
        self.slab_size.set((size + page_size - 1) & !(page_size - 1));
    }
    ///Gets the size and free blocks for a slab
    fn get_slab_size(&self, slab: UnsafeRef<RefCell<Slab>>, addr: usize) -> (usize, usize){
        let slab_size;
        slab_size = slab.borrow().end_addr - addr;
        alloc_debug_println!("get_slab_size: {:x} {:x} {} {}", addr, slab.borrow().end_addr, slab_size / self.block_size, slab.borrow().free_blocks());
        (slab_size / self.block_size, slab.borrow().free_blocks())
    }
    ///Allocates a new dynamic slab
    fn allocate_slab<P: PageProvider>(&self, page_provider: Option<&P>) -> Result<(RefCell<Slab>, usize, usize), ()>{
        alloc_debug_println!("allocate_slab");
        let slab_size = self.slab_size.get();
        alloc_debug_println!("size: {}", slab_size);
        page_provider.unwrap().allocate_pages(slab_size).and_then(|start_addr| {
            let slab = unsafe { Slab::new(start_addr, slab_size, self.block_size) };
            let free_blocks = slab.free_blocks();
            Ok((RefCell::new(slab), start_addr, free_blocks))
        }).or_else(|_| {
            warn!("SlabManager::allocate_slab: could not allocate new slab for for block size {} and slab size {}", self.block_size, self.slab_size.get());
            Err(())
        })
    }
    ///Gets a slab with free slots for allocation
    fn get_alloc<P: PageProvider>(&self, nested: bool, page_provider: Option<&P>) -> Result<UnsafeRef<RefCell<Slab>>, ()> {
        let dynamic_slabs_opt = self.dynamic_slabs.borrow();
        let dynamic_slabs = dynamic_slabs_opt.as_ref().unwrap();
        dynamic_slabs.get_alloc_no_lock(
            &mut || {
                self.allocate_slab(page_provider).or_else(|_| { Err(()) })
            },
            &mut |slab: UnsafeRef<RefCell<Slab>>, addr: usize|{
                self.get_slab_size(slab, addr)
            },
            nested
        )
    }

    ///Checks whether the current slab for allocations needs to be marked full
    fn check_alloc<P: PageProvider>(&self, nested: bool, page_provider: Option<&P>) -> Result<(), ()> {
        let dynamic_slabs_opt = self.dynamic_slabs.borrow();
        let dynamic_slabs = dynamic_slabs_opt.as_ref().unwrap();
        dynamic_slabs.check_alloc_no_lock(
            &mut || {
                self.allocate_slab(page_provider).or_else(|_| { Err(()) })
            },
            &mut |slab: UnsafeRef<RefCell<Slab>>, addr: usize|{
                self.get_slab_size(slab, addr)
            },
            nested
        )
    }
    ///Allocates a block
    pub fn allocate<P: PageProvider>(&self, layout: Layout, page_provider: Option<&P>) -> Result<*mut u8, AllocError> {
        alloc_debug_println!("SlabManager::allocate: {}", self.block_size);
        let ret;
        if self.dynamic_slabs.borrow().is_none() {
            ret = self.initial_slab.borrow_mut().allocate(layout)
        }else{
            ret = self.allocate_dynamic(layout, page_provider)
        }
        if ret.is_ok(){
            self.blocks_allocated.set(self.blocks_allocated.get() + 1);
        }
        ret
    }
    ///Allocates a block from the dynamic slab manager
    fn allocate_dynamic<P: PageProvider>(&self, layout: Layout, page_provider: Option<&P>) -> Result<*mut u8, AllocError> {
        if let Ok(cell) = self.get_alloc(true, page_provider) {
            alloc_debug_println!("allocate_dynamic: {}", self.block_size);
            alloc_debug_println!("free slots before allocation: {} {}", self.block_size, self.dynamic_slabs.borrow().as_ref().unwrap().get_free_slots());

            let ret = cell.borrow_mut().allocate(layout);
            alloc_debug_println!("free slots after allocation: {} {}", self.block_size,  self.dynamic_slabs.borrow().as_ref().unwrap().get_free_slots());
            if self.check_alloc(true, page_provider).is_err() {
                error!("SlabManager::allocate_dynamic: status check failed for slab of block size {} ending at {:x}, state: {:?}", self.block_size, cell.borrow().end_addr, self);
            }

            if ret.is_err(){
                error!("SlabManager::allocate_dynamic: allocation from slab ending at {:x} with {} free blocks failed", cell.borrow().end_addr, cell.borrow().free_blocks());
            }
            ret
        }else{
            error!("SlabManager::allocate_dynamic: cannot get slab");
            Err(AllocError)
        }
    }
    ///Deallocates a block
    pub fn deallocate<P: PageProvider>(&self, ptr: *mut u8, page_provider: Option<&P>, mode: DeallocMode) -> Result<(), ()>{
        alloc_debug_println!("SlabManager::deallocate: {}", self.block_size);
        let ret;
        if self.dynamic_slabs.borrow().is_none() {
            if mode != DeallocMode::Mock {
                self.initial_slab.borrow_mut().deallocate(ptr);
            }
            ret = Ok(())
        }else{
            ret = self.deallocate_dynamic(ptr, page_provider, mode)
        }
        if mode != DeallocMode::Mock && ret.is_ok() {
            self.blocks_allocated.set(self.blocks_allocated.get() - 1);
        }
        ret
    }
    ///Deallocates a block from the dynamic slab manager
    fn deallocate_dynamic<P: PageProvider>(&self, ptr: *mut u8, page_provider: Option<&P>, mode: DeallocMode) -> Result<(), ()>{
        let dynamic_slabs_opt = self.dynamic_slabs.borrow();
        let dynamic_slabs = dynamic_slabs_opt.as_ref().unwrap();
        let page_size = 1 << self.page_bits;
        let page_addr = ptr as usize & !(page_size - 1);
        let opt = dynamic_slabs.get_upper_bound_dealloc(page_addr,
            &mut |slab: UnsafeRef<RefCell<Slab>>, addr: usize|{
                self.get_slab_size(slab, addr)
            },
        );
        let slab_size = self.slab_size.get();
        if opt.is_none() {
            if mode == DeallocMode::FallThrough ||
                mode == DeallocMode::Mock {
                return Err(());
            }else{
                panic!("SlabManager::deallocate_dynamic: no slab found for block of size {} at {:p}, slab size: {}, allocator state: {:?}", self.block_size, ptr, slab_size, self);
            }
        }
        let (slab, slab_addr) = opt.unwrap();
        alloc_debug_println!("deallocate_dynamic: block size: {}, addr: {:x}", self.block_size, slab_addr);
        if (ptr as usize) < slab_addr || (ptr as usize) > slab.borrow().end_addr {
        if mode == DeallocMode::FallThrough ||
            mode == DeallocMode::Mock {
                return Err(());
            }else{
                panic!("SlabManager::deallocate_dynamic: no valid slab found for block of size {} at {:p}, slab address: {:x}, slab size: {}, allocator state: {:?}", self.block_size, ptr, slab_addr, slab_size, self);
            }
        }
        if mode == DeallocMode::Mock {
            return Ok(());
        }
        slab.borrow_mut().deallocate(ptr);
        alloc_debug_println!("free slots before deallocation: {} {}", self.block_size, self.dynamic_slabs.borrow().as_ref().unwrap().get_free_slots());

        let res = dynamic_slabs.check_dealloc(slab_addr,
            &mut |slab, addr|{
                if slab.is_none() {
                    page_provider.unwrap().deallocate_pages(addr, slab_size)
                }else{
                    Ok(())
                }
            },
            &mut |slab: UnsafeRef<RefCell<Slab>>, addr: usize|{
                self.get_slab_size(slab, addr)
            },
            &mut || {
                self.allocate_slab(page_provider).or_else(|_| { Err(()) })
            });
        alloc_debug_println!("free slots after deallocation: {} {}", self.block_size, self.dynamic_slabs.borrow().as_ref().unwrap().get_free_slots());

        if res.is_err() {
            panic!("SlabManager::deallocate_dynamic: failed to deallocate slab for block of size {} at {:p}, slab address: {:x}, slab size: {}, slab state: {:?}", self.block_size, ptr, slab_addr, self.slab_size.get(), self);
        }
        alloc_debug_println!("deallocation finished: {:p}", ptr);
        Ok(())
    }
    ///Acquires the recursion lock
    pub fn lock(&self){
        let dynamic_slabs = self.dynamic_slabs.borrow();
        if dynamic_slabs.is_some() {
            alloc_debug_println!("SlabManager::lock: {}", self.block_size);
            dynamic_slabs.as_ref().unwrap().lock_raw();  
        }
    }
    ///Releases the recursion lock
    pub fn unlock(&self){
        let dynamic_slabs = self.dynamic_slabs.borrow();
        if dynamic_slabs.is_some() {
            alloc_debug_println!("SlabManager::unlock: {}", self.block_size);
            dynamic_slabs.as_ref().unwrap().unlock_raw();
        }
    }
    ///Gets the block size
    pub fn get_block_size(&self) -> usize {
        self.block_size
    }
    ///Gets the minimum free blocks
    pub fn get_min_free(&self) -> usize {
        let dynamic_slabs = self.dynamic_slabs.borrow();
        if dynamic_slabs.is_some() {
            dynamic_slabs.as_ref().unwrap().get_min_free()
        }else{
            0
        }
    }
    ///Checks if the free block count is below the minimum and allocates a new
    ///slab if it is
    pub fn refill<P: PageProvider>(&self, page_provider: Option<&P>) {
        alloc_debug_println!("SlabManager::refill: {} {:p}", self.block_size, self);
        let dynamic_slabs = self.dynamic_slabs.borrow();
        if dynamic_slabs.is_some() {
            alloc_debug_println!("SlabManager present");
            alloc_debug_println!("free slots before refill: {} {}", self.block_size, dynamic_slabs.as_ref().unwrap().get_free_slots());
            if self.get_alloc(false, page_provider).is_err() {
                panic!("failed to refill slabs for block size {}, slab state: {:?}", self.block_size, self);
            }
            alloc_debug_println!("free slots after refill: {} {}", self.block_size, dynamic_slabs.as_ref().unwrap().get_free_slots());
        }
    }
    ///Drops deallocated slabs
    pub fn drop_slabs<P: PageProvider>(&self, page_provider: Option<&P>) {
        alloc_debug_println!("SlabManager::drop_slabs: {}", self.block_size);
        let dynamic_slabs = self.dynamic_slabs.borrow();
        let slab_size = self.slab_size.get();
        alloc_debug_println!("slab size: {}", slab_size);
        if dynamic_slabs.is_some() {
            alloc_debug_println!("free slots before slab deallocation: {} {}", self.block_size, dynamic_slabs.as_ref().unwrap().get_free_slots());
            if dynamic_slabs.as_ref().unwrap().drop_unused(
                &mut |slab, addr|{
                if slab.is_none(){
                    page_provider.unwrap().deallocate_pages(addr, slab_size)
                }else{
                    Ok(())
                }
            }).is_err() {
                panic!("failed to deallocate slabs for block size {}, slab state: {:?}", self.block_size, self);
            }
            alloc_debug_println!("free slots after slab deallocation: {} {}", self.block_size, dynamic_slabs.as_ref().unwrap().get_free_slots());
        }
        alloc_debug_println!("drop_slabs: done {}", self.block_size);
    }
    ///Gets the number of free blocks
    pub fn free_blocks(&self) -> usize {
        if self.dynamic_slabs.borrow().is_none() {
            self.initial_slab.borrow().free_blocks()
        }else{
            self.free_blocks_dynamic()
        }
    }
    ///Gets the number of free blocks from the dynamic slab manager
    pub fn free_blocks_dynamic(&self) -> usize {
        self.dynamic_slabs.borrow().as_ref().unwrap().get_free_slots()
    }
}

impl fmt::Debug for SlabManager {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}, used: {}, free: {}", self.block_size, self.blocks_allocated.get(), self.free_blocks()).unwrap();
        Ok(())
    }
}

///A fixed-size slab
pub struct Slab {
    end_addr: usize,
    bump_addr: usize,
    block_size: usize,
    free_block_list: FreeBlockList,
}

impl Slab {
    ///Creates a new slab. This function is unsafe because it could cause
    ///undefined behavior if the memory region is invalid
    pub unsafe fn new(start_addr: usize, slab_size: usize, block_size: usize) -> Slab {
        alloc_debug_println!("Slab::new: {:x} {:x} {} {}", start_addr, start_addr + slab_size, slab_size, block_size);
        assert!(
            start_addr % size_of::<usize>() == 0,
            "Start address must be aligned to size_of(usize)"
        );
        assert!(
            block_size < slab_size,
            "Block size must be less than slab size"
        );

        Slab {
            end_addr: start_addr + slab_size,
            bump_addr: start_addr,
            block_size,
            free_block_list: FreeBlockList::new_empty(),
        }
    }

    ///Returns the number of free blocks
    pub fn free_blocks(&self) -> usize {
        self.free_block_list.len() + ((self.end_addr - self.bump_addr) / self.block_size)
    }

    ///If there are still any available blocks that haven't been added to the
    ///free list, add one of them to the list
    pub unsafe fn bump_add_block(&mut self) {
        if self.bump_addr == self.end_addr || self.bump_addr + self.block_size > self.end_addr {
            return
        }
        let mut block_list = FreeBlockList::new(self.bump_addr, self.block_size, 1);
        self.bump_addr += self.block_size;
        while let Some(block) = block_list.pop() {
            self.free_block_list.push(block);
        }
    }

    ///Allocate a block
    pub fn allocate(&mut self, layout: Layout) -> Result<*mut u8, AllocError> {
        alloc_debug_println!("Slab::allocate: {}", self.block_size);
        if layout.size() > self.block_size {
            panic!("Slab::allocate: requested block size {} greater than block size {} (this should never happen)", self.block_size, layout.size());
        }
        unsafe { self.bump_add_block(); }
        if let Some(block) = self.free_block_list.pop() {
            Ok(block.addr() as *mut u8)
        }else{
            alloc_debug_println!("Slab::allocate: {} with end address {:x} out of memory", self.block_size, self.end_addr);
            Err(AllocError)
            //None => Err(AllocErr::Exhausted { request: layout }),
        }
    }

    ///Deallocate a block
    pub fn deallocate(&mut self, ptr: *mut u8) {
        let ptr = ptr as *mut FreeBlock;
        unsafe {self.free_block_list.push(&mut *ptr);}
    }

}

impl PartialEq for Slab {
    fn eq(&self, _: &Self) -> bool {
        false
    }
}

///A linked list of free blocks
struct FreeBlockList {
    len: usize,
    head: Option<&'static mut FreeBlock>,
}

impl FreeBlockList {
    unsafe fn new(start_addr: usize, block_size: usize, total_blocks: usize) -> FreeBlockList {
        let mut new_list = FreeBlockList::new_empty();
        for i in (0..total_blocks).rev() {
            alloc_debug_println!("block: {:x}", start_addr + i * block_size);
            let new_block = (start_addr + i * block_size) as *mut FreeBlock;
            new_list.push(&mut *new_block);
        }
        new_list
    }

    fn new_empty() -> FreeBlockList {
        FreeBlockList {
            len: 0,
            head: None,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn pop(&mut self) -> Option<&'static mut FreeBlock> {
        self.head.take().map(|node| {
            self.head = node.next.take();
            self.len -= 1;
            node
        })
    }
 
    fn push(&mut self, free_block: &'static mut FreeBlock) {
        free_block.next = self.head.take();
        self.len += 1;
        self.head = Some(free_block);
    }
    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

}

impl Drop for FreeBlockList {
    fn drop(&mut self) {
        while let Some(_) = self.pop() {}
    }
}

///An individual block
struct FreeBlock {
    next: Option<&'static mut FreeBlock>,
}

impl FreeBlock {
    fn addr(&self) -> usize {
        self as *const _ as usize
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    alloc_debug_println!("slab_allocator_core::add_custom_slabs: adding slab header slab");
    alloc.add_custom_slab(size_of::<RefCell<Slab>>(), 768, 64, 64, 2)?;
    alloc_debug_println!("slab_allocator_core::add_custom_slabs: adding node slab");
    sparse_array::add_custom_slabs_suballoc::<RefCell<Slab>, A>(alloc)
}
