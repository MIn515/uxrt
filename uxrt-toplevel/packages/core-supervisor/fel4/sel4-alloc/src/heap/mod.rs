// Copyright 2021 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Heap allocation

use core::fmt;
use core::alloc::Layout;

#[macro_export]
macro_rules! heap_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_heap")]
        debug!($($toks)*);
    })
}

pub use slab_allocator_core::{NUM_GENERIC_SLABS, BootstrapSlabInfo, DynamicSlabInfo, Heap, PageProvider};


pub struct SeL4Heap(Heap);

impl SeL4Heap {
    ///Initialize dynamic shrinking and growing of the heap.
    ///
    ///See the documentation of Heap::init_dynamic() in slab-allocator-core for
    ///more information.
    pub fn init_dynamic<P: PageProvider>(&self, slab_info: [DynamicSlabInfo; NUM_GENERIC_SLABS], page_provider: &P) {
        self.0.init_dynamic(slab_info, Some(page_provider))
    }

    ///Creates a new heap initialized with bootstrap slabs.
    ///
    ///See the documentation of Heap::new() in slab-allocator-core for more 
    ///information.
    pub unsafe fn new(slab_info: [BootstrapSlabInfo; NUM_GENERIC_SLABS], page_size: u32) -> Self {
        SeL4Heap(Heap::new(slab_info, page_size))
    }

    /// Adds a new custom slab.
    ///
    /// See the documentation of Heap::add_custom_slab() in slab-allocator-core
    /// for more information.
    pub fn add_custom_slab<P: PageProvider>(&self, block_size: usize, slab_size: usize, min_free: usize, dealloc_slots: usize, max_dealloc_rounds: usize, page_provider: &P) -> Result<(), ()>{
        self.0.add_custom_slab(block_size, slab_size, min_free, dealloc_slots, max_dealloc_rounds, Some(page_provider))
    }
    pub fn add_next_custom_slab(&self, slab_size: usize, min_free: usize, max_dealloc_slabs: usize, max_drop_rounds: usize) -> Result<(), ()>{
        self.0.add_next_custom_slab(slab_size, min_free, max_dealloc_slabs, max_drop_rounds)
    }
    /// Allocates from the heap.
    ///
    /// See the documentation of Heap::allocate_raw() in slab-allocator-core
    /// for more information.
    pub unsafe fn allocate_raw<P: PageProvider>(&self, layout: Layout, page_provider: &P) -> *mut u8 {
        self.0.allocate_raw(layout, Some(page_provider))
    }
    /// Deallocates from the heap.
    ///
    /// See the documentation of Heap::deallocate() in slab-allocator-core
    /// for more information.
    pub unsafe fn deallocate<P: PageProvider>(&self, ptr: *mut u8, layout: Layout, page_provider: &P) {
        self.0.deallocate(ptr, layout, Some(page_provider))
    }
    /// Reallocates a block from the heap.
    ///
    /// See the documentation of Heap::reallocate_raw() in slab-allocator-core
    /// for more information.
    pub unsafe fn reallocate_raw<P: PageProvider>(&self, ptr: *mut u8, layout: Layout, new_size: usize, page_provider: &P) -> *mut u8 {
        self.0.reallocate_raw(ptr, layout, new_size, Some(page_provider))
    }
    /// Acquires the recursion lock before allocating.
    ///
    /// See the documentation of Heap::lock_allocate() in slab-allocator-core
    /// for more information.
    pub fn lock_allocate<P: PageProvider>(&self, page_provider: &P){
        self.0.lock_allocate(Some(page_provider))
    }
    /// Acquires the recursion lock before deallocating.
    ///
    /// See the documentation of Heap::lock_deallocate() in slab-allocator-core
    /// for more information.
    pub fn lock_deallocate<P: PageProvider>(&self, page_provider: &P){
        self.0.lock_deallocate(Some(page_provider))
    }
    /// Releases the recursion lock after allocating.
    ///
    /// See the documentation of Heap::unlock_allocate() in slab-allocator-core
    /// for more information.
    pub fn unlock_allocate<P: PageProvider>(&self, page_provider: &P){
        self.0.unlock_allocate(Some(page_provider))
    }
    /// Releases the recursion lock after deallocating.
    ///
    /// See the documentation of Heap::unlock_deallocate() in
    /// slab-allocator-core for more information.
    pub fn unlock_deallocate<P: PageProvider>(&self, page_provider: &P){
        self.0.unlock_deallocate(Some(page_provider))
    }
}

impl fmt::Debug for SeL4Heap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{:?}", self.0).unwrap();
        Ok(())
    }
}

//unsafe impl<'a> Alloc for &'a LockedHeap {
//    unsafe fn alloc(&mut self, layout: Layout) -> Result<NonNull<u8>, AllocErr> {
//        if let Some(ref mut heap) = self.0.as_ref() {
//            heap.lock().allocate_nonnull(layout)
//        } else {
//            panic!("LockedHeap::alloc: heap not initialized");
//        }
//    }
//
//    unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) {
//        if let Some(ref mut heap) = self.0.as_ref() {
//            heap.lock().deallocate_nonnull(ptr, layout)
//        } else {
//            panic!("LockedHeap::dealloc: heap not initialized");
//        }
//    }

//    fn usable_size(&self, layout: &Layout) -> (usize, usize) {
//        if let Some(ref mut heap) = self.0.as_ref() {
//            heap.lock().usable_size(layout)
//        } else {
//            panic!("LockedHeap::usable_size: heap not initialized");
//        }
//    }

    //fn oom(&mut self, err: AllocErr) -> ! {
    //    panic!("Out of memory: {:?}", err);
    //}
//}

#[macro_export]
macro_rules! global_alloc {
    ($allocator_bundle: ty) => {
        use sel4_alloc::{
            AllocatorBundle, 
            cspace::CSpaceManager, 
            heap::{SeL4Heap},
            utspace::{UTSpaceManager, UtZone},
            vspace::VSpaceManager
        };
        use usync::{ReentrantMutex, ReentrantMutexGuard};
        use slab_allocator_core::{
            NUM_GENERIC_SLABS, 
            BootstrapSlabInfo, 
            DynamicSlabInfo, 
            PageProvider,
        };
        use custom_slab_allocator::CustomSlabAllocator;
        use sel4::{CapRights, PAGE_SIZE, PAGE_BITS};

        use core::alloc::{GlobalAlloc, Layout};
        use core::ops::Deref;
        use core::fmt;
        static HEAP: LockedHeap = LockedHeap::new();
        static mut BASE_HEAP: Option<SeL4Heap> = None;
        static mut KOBJ_ALLOC: Option<LockedAllocatorBundle> = None;
        static mut PAGE_PROVIDER: SeL4PageProvider = SeL4PageProvider{};

        ///Returns an acquired mutex guard wrapping the global allocator bundle.
        pub fn get_kobj_alloc() -> AllocatorBundleGuard<'static> {
            unsafe {
                if let Some(ref mut kobj_alloc) = KOBJ_ALLOC {
                    kobj_alloc.lock()
                } else {
                    panic!("GlobalAlloc::get_kobj_alloc: kernel allocators not initialized");
                }
            }
        }

        ///A global allocator implementation wrapping a LockedHeap
        pub struct GlobalSlabAllocator{}

        impl GlobalSlabAllocator {
            ///Creates a new uninitialized global allocator
            pub const fn new() -> GlobalSlabAllocator{
                GlobalSlabAllocator {
                }
            }
            ///Initializes the heap.
            ///
            ///See the documentation of Heap::new() in slab-allocator-core for
            ///more information (this method wraps it).
            pub unsafe fn init(&self, slab_info: [BootstrapSlabInfo; NUM_GENERIC_SLABS]) {
                BASE_HEAP = Some(SeL4Heap::new(slab_info, PAGE_BITS as u32));
            }
            ///Initialize dynamic shrinking and growing of the heap.
            ///
            ///See the documentation of Heap::init_dynamic() in
            ///slab-allocator-core for more information.
            pub unsafe fn init_dynamic(&self, kobj_alloc: $allocator_bundle, slab_info: [DynamicSlabInfo; NUM_GENERIC_SLABS]){
                KOBJ_ALLOC = Some(LockedAllocatorBundle::new(kobj_alloc));

                let heap = HEAP.lock();
                heap.init_dynamic(slab_info, &PAGE_PROVIDER);
                slab_allocator_core::add_custom_slabs(self).expect("failed to add custom slabs for slab_allocator_core");
                sel4_alloc::add_custom_slabs(self).expect("failed to add custom slabs for sel4_alloc");
                drop(heap);
            }
            /// Acquires the recursion lock before allocating.
            ///
            /// See the documentation of Heap::lock_allocate() in
            /// slab-allocator-core for more information.
            pub unsafe fn lock_alloc(&self) {
                HEAP.lock().lock_allocate(&PAGE_PROVIDER)
            }
            /// Acquires the recursion lock before deallocating.
            ///
            /// See the documentation of Heap::lock_deallocate() in
            /// slab-allocator-core for more information.
            pub unsafe fn lock_dealloc(&self) {
                HEAP.lock().lock_deallocate(&PAGE_PROVIDER)
            }
            /// Releases the recursion lock after allocating.
            ///
            /// See the documentation of Heap::unlock_allocate() in
            /// slab-allocator-core for more information.
            pub unsafe fn unlock_alloc(&self) {
                HEAP.lock().unlock_allocate(&PAGE_PROVIDER)
            }
            /// Releases the recursion lock after deallocating.
            ///
            /// See the documentation of Heap::unlock_deallocate() in
            /// slab-allocator-core for more information.
            pub unsafe fn unlock_dealloc(&self) {
                HEAP.lock().unlock_deallocate(&PAGE_PROVIDER)
            }
        }

        unsafe impl GlobalAlloc for GlobalSlabAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                heap_debug_println!("GlobalAlloc::alloc: {}", layout.size());
                HEAP.lock().allocate_raw(layout, &PAGE_PROVIDER)
            }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                heap_debug_println!("GlobalAlloc::dealloc: {:p} {}", ptr, layout.size());
                HEAP.lock().deallocate(ptr, layout, &PAGE_PROVIDER)
            }
            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                heap_debug_println!("GlobalAlloc::realloc: {} {} {}", layout.size(), layout.align(), new_size);
                HEAP.lock().reallocate_raw(ptr, layout, new_size, &PAGE_PROVIDER)
            }
        }

        impl fmt::Debug for GlobalSlabAllocator {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                unsafe {
                    if BASE_HEAP.is_some(){
                        unsafe { writeln!(f, "{:?}", HEAP.lock()) }
                    }else{
                        writeln!(f, "(heap uninitialized)")
                    }
                }
            }
        }

        impl CustomSlabAllocator for GlobalSlabAllocator {
            /// Adds a new custom slab.
            ///
            /// See the documentation of Heap::add_custom_slab() in
            /// slab-allocator-core for more information.
            fn add_custom_slab(&self, block_size: usize, slab_size: usize, min_free: usize, dealloc_slots: usize, max_dealloc_rounds: usize) -> Result<(), ()>{
                unsafe {
                    HEAP.lock().add_custom_slab(block_size, slab_size, min_free, dealloc_slots, max_dealloc_rounds, &PAGE_PROVIDER)
                }
            }
        } 

        struct SeL4PageProvider{}
        impl PageProvider for SeL4PageProvider {
            fn allocate_pages(&self, size: usize) -> Result<usize, ()>{
                heap_debug_println!("SeL4PageProvider::allocate_pages: {}", size);
                let alloc_mutex = unsafe{ KOBJ_ALLOC.as_ref().unwrap() };
                let alloc = alloc_mutex.lock();
                Ok(alloc.vspace().allocate_and_map(size, PAGE_BITS as usize, CapRights::all(), 0, UtZone::RamAny, &alloc).expect("failed to allocate heap pages"))
            }
            fn deallocate_pages(&self, addr: usize, size: usize) -> Result<(), ()>{
                heap_debug_println!("SeL4PageProvider::deallocate_pages: {:x} {}", addr, size);
                let alloc_mutex = unsafe{ KOBJ_ALLOC.as_ref().unwrap() };
                let alloc = alloc_mutex.lock();
                alloc.vspace().unreserve_and_free(addr, size, PAGE_BITS as usize, &alloc).expect("failed to free heap pages");
                Ok(())
            }
        }
        ///Wraps an object implementing AllocatorBundle in a mutex
        struct LockedAllocatorBundle {
            alloc: ReentrantMutex<$allocator_bundle>
        }
        impl LockedAllocatorBundle {
            ///Creates a new LockedAllocatorBundle
            fn new(alloc: $allocator_bundle) -> LockedAllocatorBundle {
                LockedAllocatorBundle {
                    alloc: ReentrantMutex::new(alloc),
                }
            }
            ///Acquires the mutex, returning a guard wrapping the allocator 
            ///bundle
            fn lock(&self) -> AllocatorBundleGuard<'_> {
                AllocatorBundleGuard {
                    guard: self.alloc.lock(),
                }
            }
        }
        ///A mutex guard around an allocator bundle
        pub struct AllocatorBundleGuard<'a>{
            guard: ReentrantMutexGuard<'a, $allocator_bundle>
        }

        impl<'a> AllocatorBundleGuard<'a> {
            pub fn add_next_custom_slab(&self, slab_size: usize, min_free: usize, max_dealloc_slabs: usize, max_drop_rounds: usize) -> Result<(), ()>{
                unsafe { 
                    let heap = BASE_HEAP.as_ref().expect("could not add custom slab to heap (this should never happen!)");
                    heap.add_next_custom_slab(slab_size, min_free, max_dealloc_slabs, max_drop_rounds)
                }
            }
        }

        impl<'a> AllocatorBundle for AllocatorBundleGuard<'a> {
            type CSpace = <$allocator_bundle as AllocatorBundle>::CSpace;
            type UTSpace = <$allocator_bundle as AllocatorBundle>::UTSpace;
            type VSpace = <$allocator_bundle as AllocatorBundle>::VSpace;

            fn cspace(&self) -> &Self::CSpace {
                self.guard.cspace()
            }

            fn utspace(&self) -> &Self::UTSpace {
                self.guard.utspace()
            }

            fn vspace(&self) -> &Self::VSpace {
                self.guard.vspace()
            }

            // it is OK to access BASE_HEAP directly here, since 
            // LockedHeap/HeapGuard is just a wrapper around this struct, 
            // meaning the lock has been acquired already
            fn lock_alloc(&self) -> Result<(), ()>{
                self.guard.lock_alloc_no_refill()?;
                unsafe {
                    BASE_HEAP.as_mut().unwrap().lock_allocate(&PAGE_PROVIDER);
                };
                self.guard.refill()
            }

            fn lock_dealloc(&self) -> Result<(), ()>{
                self.guard.lock_alloc_no_refill()?;
                unsafe {
                    BASE_HEAP.as_mut().unwrap().lock_deallocate(&PAGE_PROVIDER);
                };
                self.guard.refill()
            }

            fn unlock_alloc(&self) -> Result<(), ()>{
                self.guard.drop_unused()?;
                unsafe {
                    BASE_HEAP.as_mut().unwrap().unlock_allocate(&PAGE_PROVIDER);
                    heap_debug_println!("AllocatorBundleGuard::unlock_alloc: heap done");
                }
                self.guard.unlock_alloc_no_drop()
            }

            fn unlock_dealloc(&self) -> Result<(), ()>{
                self.guard.drop_unused()?;
                unsafe {
                    BASE_HEAP.as_mut().unwrap().unlock_deallocate(&PAGE_PROVIDER);
                    heap_debug_println!("AllocatorBundleGuard::unlock_dealloc: heap done");
                }
                self.guard.unlock_dealloc_no_drop()
            }

            fn lock_alloc_no_refill(&self) -> Result<(), ()> {
                unimplemented!()
            }
            fn lock_dealloc_no_refill(&self) -> Result<(), ()> {
                unimplemented!()
            }
            fn refill(&self) -> Result<(), ()> {
                unimplemented!()
            }
            fn drop_unused(&self) -> Result<(), ()> {
                unimplemented!()
            }
            fn unlock_alloc_no_drop(&self) -> Result<(), ()> {
                unimplemented!()
            }
            fn unlock_dealloc_no_drop(&self) -> Result<(), ()> {
                unimplemented!()
            }


            fn minimum_slots(&self) -> usize {
                self.guard.minimum_slots()
            }

            fn minimum_untyped(&self) -> usize {
                self.guard.minimum_untyped()
            }

            fn minimum_vspace(&self) -> usize {
                self.guard.minimum_vspace()
            }
        }

        impl<'a> CustomSlabAllocator for AllocatorBundleGuard<'a> {
            fn add_custom_slab(&self, block_size: usize, slab_size: usize, min_free: usize, dealloc_slots: usize, max_dealloc_rounds: usize) -> Result<(), ()>{
                unsafe { 
                    let heap = BASE_HEAP.as_ref().expect("could not add custom slab to heap (this should never happen!)");
                    heap.add_custom_slab(block_size, slab_size, min_free, dealloc_slots, max_dealloc_rounds, &PAGE_PROVIDER) 
                }
            }
        }

        static mut INIT_THREAD_ID: usize = 0;
        struct LockedHeap {
        }
        impl LockedHeap {
            const fn new() -> LockedHeap {
                LockedHeap {
                }
            }
            fn lock(&self) -> HeapGuard<'_> {
                #[thread_local]
                static THREAD_ID: bool = false;
                let guard = unsafe {
                    if let Some(ref mut kobj_alloc) = KOBJ_ALLOC {
                        Some(kobj_alloc.lock())
                    }else if INIT_THREAD_ID == 0 {
                        INIT_THREAD_ID = &THREAD_ID as *const _ as usize;
                        None
                    }else if &THREAD_ID as *const _ as usize != INIT_THREAD_ID {
                        panic!("attempted to access the heap in multiple threads without initializing kernel object allocators");
                    }else{
                        None
                    }
                };
                HeapGuard {
                    guard,
                }
            }
        }

        ///A mutex guard around the heap, which piggybacks on the mutex of th 
        ///kernel object allocators
        pub struct HeapGuard<'a>{
            guard: Option<AllocatorBundleGuard<'a>>
        }

        impl<'a> Deref for HeapGuard<'a> {
            type Target = SeL4Heap;
            fn deref(&self) -> &SeL4Heap {
                unsafe { BASE_HEAP.as_ref().expect("heap not initialized") }
            }
        }
        impl<'a> fmt::Debug for HeapGuard<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                unsafe {
                    if BASE_HEAP.is_some() {
                        writeln!(f, "{:?}", BASE_HEAP.as_ref().unwrap())
                    }else{
                        writeln!(f, "HeapGuard (uninitialized)")
                    }
                }
            }
        }         
    };
}
