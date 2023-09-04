// Copyright 2019-2020 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright 2017 Robigalia Project Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

///This is an allocator that wraps a buddy allocator and manages
///sub-allocators of a single type of kernel object, directing each request to
///the correct one. This is separate from the heap slab allocator (with the
///only connection being that it allocates metadata from the heap). Each
///sub-allocator allocates an entire untyped object at least one page in size
///and then retypes it into as many of the object type as can fit (using a
///CNode that is provided to it), allocating and freeing new untyped objects
///as necessary. All CNodes as well as all objects that are page-sized or
///larger are allocated directly from the underlying buddy allocator instead.

use core::{
    cell::{Cell, RefCell},
    fmt,
    mem::size_of,
};
use crate::{
    AllocatorBundle,
    cspace::{
        CSpaceError,
        CSpaceManager,
    },
    utspace::{
        LowerUTSpaceManager,
        Split, 
        UtBucket, 
        UTSpaceManager, 
        UtZone, 
        UTSpaceError,
    },
    utspace_debug_println,
};

use sel4_sys::{
    seL4_TCBObject,
    seL4_EndpointObject,
    seL4_NotificationObject,
    seL4_SchedContextObject, 
    seL4_ReplyObject,
    seL4_UntypedObject,
    seL4_MinSchedContextBits, 
    seL4_MaxUntypedBits, 
    seL4_ObjectTypeCount, 
};

use sel4::{
    PAGE_BITS,
    ToCap,
    raw::untyped_retype,
};

const NUM_SLABS: usize = 5;

//the minimum and maximum sizes are interpreted as the size_bits argument to 
//seL4_Untyped_Retype() and not as a raw byte order
const SLAB_OBJECTS: [(u32, u32, u32); NUM_SLABS] = [
    (seL4_TCBObject, 0, 0),
    (seL4_EndpointObject, 0, 0),
    (seL4_NotificationObject, 0, 0),
    (seL4_SchedContextObject, seL4_MinSchedContextBits, seL4_MaxUntypedBits),
    (seL4_ReplyObject, 0, 0),
];

use alloc::boxed::Box;

use sparse_array::{SparseArray, SubAllocatorManager, UnsafeRef};
use sel4::{
    seL4_CPtr, 
    CNodeInfo, 
    SlotRef, 
    Window, 
    get_object_size
};

use custom_slab_allocator::CustomSlabAllocator;

/// The dispatcher component of the slab allocator, which sends requests to 
/// either one of the slab managers or the inner buddy allocator
pub struct UtSlabAllocator {
    split: Split,
    slabs: RefCell<Option<Box<[Option<UtSlabManager>; seL4_ObjectTypeCount as usize]>>>,
}

impl UtSlabAllocator {
    pub fn new(zones: &[(usize, usize)], max_order: usize) -> UtSlabAllocator {
        UtSlabAllocator {
            split: Split::new(zones, max_order),
            slabs: RefCell::new(None),
        }
    }

    /// Add a UtBucket to this allocator.
    ///
    /// This function allocates from the heap to store metadata about the
    /// UtBucket.
    pub fn add_bucket<A: AllocatorBundle>(&self, alloc: &A, bucket: UtBucket) -> Result<(), UTSpaceError> {
        self.split.add_bucket(alloc, bucket)
    }
    ///Internal method to get the slab index for a given type and size
    fn slab_index(&self, objtype: usize, size_bits: usize) -> Option<usize> {
        utspace_debug_println!("UtSlabAllocator::slab_index: {} {}", objtype, size_bits);
        if self.slabs.borrow().is_none(){
            return None;
        }
        let opt = self.slabs.borrow();
        let slabs = opt.as_ref().unwrap();
        utspace_debug_println!("slabs.len(): {}", slabs.len());
        for i in 0..slabs.len(){
            if let Some(slab) = &slabs[i] {
                utspace_debug_println!("slab found: {} {} {} {}", slab.objtype, objtype, slab.objsize, size_bits);
                //this currently does not work with multiple slabs of 
                //different sizes for the same object type
                if slab.objtype == objtype as u32 && slab.size_bits == size_bits {
                    utspace_debug_println!("slab matched");
                    return Some(i);
                }
            }
        }
        None
    }
}

impl fmt::Debug for UtSlabAllocator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = writeln!(f, "UtSlabAllocator:");
        if let Some(slabs) = self.slabs.borrow().as_ref(){
            let _ = writeln!(f, "slabs:");
            for i in 0..slabs.len(){
                let _ = writeln!(f, "{:?}", slabs[i]);
            }
        }else{
            let _ = writeln!(f, "slabs uninitialized");
        }
        let _ = writeln!(f, "Lower allocator:");
        let _ = writeln!(f, "{:?}", self.split);
        Ok(())
    }
}

impl UTSpaceManager for UtSlabAllocator {
    fn init_slabs<A: AllocatorBundle>(&self, slab_size_overrides: &[(u32, u32)], alloc: &A) {
        if alloc.lock_alloc().is_err() {
            panic!("could not lock allocator before initializing UTSpace slabs");
        }

        let mut slabs: [Option<UtSlabManager>; seL4_ObjectTypeCount as usize] = Default::default();
        for i in 0..slab_size_overrides.len(){
            let (objtype, objsize) = slab_size_overrides[i];
            for i in 0..SLAB_OBJECTS.len(){
                let (base_type, base_min, base_max) = SLAB_OBJECTS[i];
                if base_type == objtype && base_min == base_max || objsize > base_max {
                    panic!("invalid object size {} for kernel object type {}", objsize, objtype);
                }
            }
            slabs[objtype as usize] = Some(UtSlabManager::new(objtype, objsize as usize, alloc).expect("cannot allocate UTSpace slab"));
        }
        for i in 0..SLAB_OBJECTS.len(){
            let (objtype, objsize, _) = SLAB_OBJECTS[i];
            if slabs[objtype as usize].is_some(){
                utspace_debug_println!("slab {} already present", i);
                continue;
            }
            utspace_debug_println!("adding slab {} {}", objtype, objsize);
            slabs[objtype as usize] = Some(UtSlabManager::new(objtype, objsize as usize, alloc).expect("cannot allocate UTSpace slab"));
        }
        self.slabs.replace(Some(Box::new(slabs)));
        if alloc.unlock_alloc().is_err() {
            panic!("could not lock allocator before initializing UTSpace slabs");
        }
    }
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        dest_info: CNodeInfo,
        size_bits: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        let ret;
        if alloc.lock_alloc().is_err() {
            warn!("UtSlabAllocator::allocate: failed to lock allocators");
            return Err((0, UTSpaceError::CapabilityAllocationFailure));
        }

        if let Some(index) = self.slab_index(T::object_type(), size_bits) {
            ret = self.slabs.borrow().as_ref().unwrap()[index].as_ref().unwrap().allocate::<T, A>(alloc, self, dest, dest_info, size_bits);
        }else{
            ret = self.split.allocate::<T, A>(alloc, dest, dest_info, size_bits, zone);
        }
        let _ = alloc.unlock_alloc();
        ret
    }
    fn allocate_raw<A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        dest_info: CNodeInfo,
        size_bits: usize,
        objtype: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        if alloc.lock_alloc().is_err() {
            warn!("UtSlabAllocator::allocate_raw: failed to lock allocators");
            return Err((0, UTSpaceError::CapabilityAllocationFailure));
        }

        let ret = if let Some(index) = self.slab_index(objtype, size_bits) {
            self.slabs.borrow().as_ref().unwrap()[index].as_ref().unwrap().allocate_raw(alloc, self, dest, dest_info)
        }else{
            self.split.allocate_raw(alloc, dest, dest_info, size_bits, objtype, zone)
        };
        let _ = alloc.unlock_alloc();
        ret
    }

    fn deallocate_raw<A: AllocatorBundle>(&self, 
        alloc: &A, 
        window: Window,
        info: CNodeInfo,
        objtype: usize,
        size_bits: usize, 
    ) -> Result<(), UTSpaceError> {
        utspace_debug_println!("UtSlabAllocator::deallocate_raw: {}", size_bits);
        if alloc.lock_dealloc().is_err() {
            warn!("UtSlabAllocator::deallocate_raw: failed to lock allocators");
            return Err(UTSpaceError::CapabilityAllocationFailure);
        }

        let index_opt = self.slab_index(objtype, size_bits);
        let mut ret = self.split.deallocate_raw_lower(alloc, window, info, objtype, size_bits, |paddr, objtype, offset| {
            if let Some(index) = index_opt {
                utspace_debug_println!("type {} size {} address {:x} offset {:x}", objtype, size_bits, paddr, offset);
                self.slabs.borrow().as_ref().unwrap()[index].as_ref().unwrap().deallocate_raw(alloc, self, paddr, objtype, offset, window, info)
            }else{
                panic!("no slab manager found for type {} size {} address {:x} offset {:x} (this should never happen!)", objtype, size_bits, paddr, offset);
            }
        });
        if let Some(index) = index_opt {
            ret = self.slabs.borrow().as_ref().unwrap()[index].as_ref().unwrap().drop_slabs(alloc);
        }
        let _ = alloc.unlock_alloc();
        ret
    }

    fn slot_to_paddr(&self, cnode: SlotRef, slot_idx: usize) -> Result<usize, ()> {
        self.split.slot_to_paddr(cnode, slot_idx)
    }

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

impl LowerUTSpaceManager for UtSlabAllocator {
    fn add_to_used_list(&self, paddr: usize, dest: Window, extra: usize) {
        self.split.add_to_used_list(paddr, dest, extra)
    }
    fn deallocate_raw_lower<A: AllocatorBundle, F>(&self, 
        alloc: &A, 
        window: Window,
        info: CNodeInfo,
        objtype: usize,
        size_bits: usize,
        upper_dealloc_fn: F,
    ) -> Result<(), UTSpaceError> where
        F: FnMut(usize, usize, usize) -> Result<(), UTSpaceError> 
    {
        self.split.deallocate_raw_lower(alloc, window, info, objtype, size_bits, upper_dealloc_fn)
    }
}


///The slab manager, which manages all slabs of a given size, allocating and 
///deallocating them as necessary
struct UtSlabManager {
    contents: SubAllocatorManager<UtSlab>,
    to_drop: RefCell<Option<UnsafeRef<UtSlab>>>,
    objtype: u32,
    objsize: usize,
    size_bits: usize,
    allocated: Cell<usize>,
}

impl UtSlabManager {
    ///Creates a new slab manager
    fn new<A: AllocatorBundle>(objtype: u32, size_bits: usize, alloc: &A) -> Result<UtSlabManager, UTSpaceError> {
        let objsize = get_object_size(objtype, size_bits).expect("object type has no defined size") as usize;
        if core::mem::size_of::<usize>() * 8 - (objsize.leading_zeros() + objsize.trailing_zeros()) as usize != 1{
            panic!("object size {} for type {} and size bits {} not a power of two", objsize, objtype, size_bits);
        }
        UtSlab::new(objsize, alloc).and_then(|initial_slab| {
            let start_paddr = initial_slab.get_start_paddr();
            let num_objects = initial_slab.get_total_objects();
            Ok(UtSlabManager {
                contents: SubAllocatorManager::new(
                    UnsafeRef::from_box(Box::new(initial_slab)),
                    start_paddr,
                    num_objects,
                    PAGE_BITS as u32,
                    0,
                    0,
                    0,
                    false,
                ),
                to_drop: Default::default(),
                objtype,
                objsize,
                size_bits,
                allocated: Cell::new(0),
            })
        }).or_else(|err| {
            Err(err)
        })
    }
    ///Method used in the allocation closure to allocate a new slab
    fn allocate_slab<A: AllocatorBundle>(&self, alloc: &A) -> Result<(UtSlab, usize, usize), UTSpaceError>{
        UtSlab::new(self.objsize, alloc).and_then(|slab| {
            let start_paddr = slab.get_start_paddr(); 
            let num_objects = slab.get_total_objects(); 
            Ok((slab, start_paddr, num_objects))
        }).or_else(|err| {
            warn!("UtSlabManager::allocate_slab: allocating new slab failed with {:?}", err);
            Err(err)
        })
    }
    ///Gets a free slab for allocation
    fn get_alloc<A: AllocatorBundle>(&self, alloc: &A) -> Result<UnsafeRef<UtSlab>, UTSpaceError> {
        let mut ret = Err(UTSpaceError::InternalError);
        if let Ok(slab) = self.contents.get_alloc(
            &mut ||{
                self.allocate_slab(alloc).or_else(|err| {
                    ret = Err(err);
                    Err(())
                })
            },
            &mut |slab: UnsafeRef<UtSlab>, _addr: usize|{
                (slab.get_total_objects(), slab.get_slots_remaining())
            }
        ){
            ret = Ok(slab)
        }else{
            warn!("SubAllocatorManager::get_alloc: getting slab failed with {:?}", ret);
        }
        ret
    }
    fn update_slots_alloc(&self, dest: sel4::Window, res: Result<(), (usize, UTSpaceError)>) {
        if let Err(err) = res {
            self.allocated.set(self.allocated.get() + err.0);
        }else{
            self.allocated.set(self.allocated.get() + dest.num_slots);
        }
    }
    ///Allocates an object given a wrapper type (which must match the one used
    ///when creating the manager)
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        ut_alloc: &UtSlabAllocator,
        dest: sel4::Window,
        dest_info: sel4::CNodeInfo,
        size_bits: usize,
    ) -> Result<(), (usize, UTSpaceError)> {
        match self.get_alloc(alloc){
            Ok(slab) => {
                let ret = slab.allocate::<T, A>(alloc, ut_alloc, dest, dest_info, size_bits);
                self.update_slots_alloc(dest, ret);
                ret
            },
            Err(err) => {
                warn!("UtSlabManager::allocate: getting slab for type {} and size {} failed with {:?}", self.objtype, self.objsize, err);
                Err((0, err))
            },
        }
    }
    ///Allocates an object given a raw type code (which must match the one
    ///used when creating the manager)
    fn allocate_raw<A: AllocatorBundle>(
        &self,
        alloc: &A,
        ut_alloc: &UtSlabAllocator,
        dest: Window,
        dest_info: sel4::CNodeInfo,
    ) -> Result<(), (usize, UTSpaceError)> {
        match self.get_alloc(alloc){
            Ok(slab) => {
                let ret = slab.allocate_raw(alloc, ut_alloc, dest, dest_info, self.objtype as usize, self.size_bits);
                self.update_slots_alloc(dest, ret);
                ret
            },
            Err(err) => {
                warn!("UtSlabManager::allocate_raw: getting slab for type {} and size {} failed with {:?}", self.objtype, self.objsize, err);
                Err((0, err))
            },
        }
    }
    ///Deallocates an object given a raw type code (which must match the one
    ///used when creating the manager)
    fn deallocate_raw<A: AllocatorBundle>(&self, 
        alloc: &A, 
        ut_alloc: &UtSlabAllocator,
        paddr: usize,
        objtype: usize,
        offset: usize,
        window: Window,
        info: CNodeInfo,
    ) -> Result<(), UTSpaceError> {
        utspace_debug_println!("UtSlabManager::deallocate_raw");
        if let Some(slab) = self.contents.get_dealloc(paddr,
            &mut |slab: UnsafeRef<UtSlab>, _: usize|{
                (slab.get_total_objects(), slab.get_slots_remaining())
            },
        ){
            let ret = Cell::new(slab.0.deallocate_raw(alloc, ut_alloc, window, info, offset));
            if ret.get().is_err(){
                warn!("UtSlabManager::deallocate_raw: deallocation of object of type {} and size {} failed with {:?}", self.objtype, self.objsize, ret.get());
                return ret.get();
            }
            ret.set(Err(UTSpaceError::InternalError));
            if self.contents.check_dealloc_no_refill(
                paddr,
                &mut |opt: Option<UnsafeRef<UtSlab>>, _: usize|{
                    if let Some(slab) = opt {
                        if self.to_drop.borrow().is_some(){
                            warn!("UtSlabManager::deallocate_raw: attempted to drop slab for object of type {} and size {} but another slab was still waiting to be dropped", self.objtype, self.objsize);
                            ret.set(Err(UTSpaceError::InternalError));
                            return Err(());
                        }
                        self.to_drop.replace(Some(slab));
                    }
                    Ok(())
                },
                &mut |slab: UnsafeRef<UtSlab>, _: usize|{
                    (slab.get_total_objects(), slab.get_slots_remaining())
                }
            ).is_ok(){
                utspace_debug_println!("deallocation successful");
                ret.set(Ok(()));
            }else{
                warn!("UtSlabManager::deallocate_raw: checking status of slab for object of type {} and size {} failed", self.objtype, self.objsize);
            }

            if ret.get().is_ok() {
                self.allocated.set(self.allocated.get() - window.num_slots);
            }

            ret.get()
        }else{
            warn!("no slab found for paddr {:x} objtype {} offset {} (object type incorrect?)", paddr, objtype, offset);
            Err(UTSpaceError::InvalidArgument { which: 3 })
        }
    }
    ///Drops any left-over deallocated slabs
    fn drop_slabs<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), UTSpaceError>{
        if self.to_drop.borrow().is_none() {
            return Ok(())
        }
        let slab = self.to_drop.replace(None).unwrap();
        let ret = slab.deinit(alloc);
        if ret.is_err(){
            warn!("UtSlabManager::drop_slabs: slab deinitialization failed for objtype {} size {} paddr {:x}", self.objtype, self.objsize, slab.get_start_paddr());
        }
        unsafe { drop(UnsafeRef::into_box(slab)) };
        ret
    }
    fn free_slots(&self) -> usize{
        self.contents.get_free_slots()
    }
    fn allocated_slots(&self) -> usize{
        self.allocated.get()
    }
}

impl fmt::Debug for UtSlabManager {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = write!(f, "UtSlabManager, objtype: {}, used: {}, free: {}", self.objtype, self.allocated_slots(), self.free_slots());
        Ok(())
    }
}


///The inner slab allocator, which wraps a UtBucket and a sparse array of
///capabilities allocated from it
struct UtSlab {
    bucket: UtBucket,
    caps: SparseArray<seL4_CPtr>,
    objsize: usize
}

impl UtSlab {
    ///Creates a new slab
    fn new<A: AllocatorBundle>(objsize: usize, alloc: &A) -> Result<UtSlab, UTSpaceError> {
        utspace_debug_println!("UtSlab::new: {}", objsize);
        match alloc.cspace().allocate_slot_with_object_raw_ref(
            PAGE_BITS as usize,
            seL4_UntypedObject as usize,
            UtZone::RamAny,
            alloc
        ){
            Ok(slot) => { 
                if let Ok(paddr) = alloc.cspace().slot_to_paddr(slot, alloc){
                    utspace_debug_println!("new slab: paddr {:x} cptr {:x} depth {}", paddr, slot.cptr, slot.depth);
                    Ok(UtSlab {
                        bucket: UtBucket::new(slot, PAGE_BITS as u8, paddr, false),
                        caps: SparseArray::new(),
                        objsize,
                    })
                }else{
                    warn!("UtSlab::new: failed to get address for slot {:?}", slot);
                    Err(UTSpaceError::CapabilityAllocationFailure)
                }
            },
            Err(err) => {
                warn!("UtSlab::new: allocation of untyped failed with {:?}", err);
                match err { 
                    CSpaceError::RetypeFailure { details } => Err(details),
                    CSpaceError::SyscallError { details } => Err(UTSpaceError::SyscallError { details }),
                    _ => {
                        Err(UTSpaceError::CapabilityAllocationFailure)
                    },
                }
            },
        }
    }
    ///Deallocates the underlying untyped object (revoking all objects
    ///allocated from it just to be sure)
    fn deinit<A: AllocatorBundle>(&self, alloc: &A) -> Result<(), UTSpaceError>{
        utspace_debug_println!("UtSlab::deinit: {:p}", self);
        let (mut _idx, mut cptr) = self.caps.take_first();
        while cptr != 0 {
            if let Err(err) = alloc.cspace().free_slot_raw(cptr, alloc){
                warn!("UtSlab::deinit: freeing object at {} failed with {:?}", cptr, err);
                return Err(UTSpaceError::InternalError);
            }
            (_idx, cptr) = self.caps.take_first();
        }
        let slot = self.bucket.get_slot();
        if let Err(err) = slot.revoke(){
            warn!("UtSlab::deinit: revoking untyped at {:?} failed with {:?}",slot, err);
            return Err(UTSpaceError::SyscallError { details: err })
        }
        if let Err(err) = alloc.cspace().free_and_delete_slot_with_object_raw_ref(slot, seL4_UntypedObject as usize, PAGE_BITS as usize, alloc){
            warn!("UtSlab::deinit: freeing untyped at {:?} failed with {:?}", slot, err);
            match err {
                CSpaceError::SyscallError { details } => Err(UTSpaceError::SyscallError { details }),
                _ => {
                    Err(UTSpaceError::CapabilityAllocationFailure)
                },
            }
        }else{
            Ok(())
        }
    }
    ///Gets the start address of the underlying untyped
    fn get_start_paddr(&self) -> usize {
        self.bucket.get_start_paddr()
    }
    ///Gets the number of free slots in this slab
    fn get_slots_remaining(&self) -> usize {
        let ret = self.caps.visible_len() + self.bucket.get_bytes_remaining() / self.objsize;
        utspace_debug_println!("UtSlab::get_slots_remaining: {:p}: objsize: {}, slots remaining: {}", self, self.objsize, ret);
        ret
    }
    ///Gets the total number of objects in this slab
    fn get_total_objects(&self) -> usize {
        self.bucket.get_total_bytes() / self.objsize
    }
    ///Allocates an object given a wrapper type (which must match the one used
    ///when creating the slab)
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        ut_alloc: &UtSlabAllocator,
        dest: Window,
        dest_info: CNodeInfo,
        size_bits: usize,
    ) -> Result<(), (usize, UTSpaceError)> {
        self.allocate_raw(alloc, ut_alloc, dest, dest_info, T::object_type(), size_bits)
    }
    ///Allocates an object given a raw type code (which must match the one
    ///used when creating the slab)
    fn allocate_raw<A: AllocatorBundle>(
        &self,
        alloc: &A,
        ut_alloc: &UtSlabAllocator,
        dest: Window,
        _dest_info: CNodeInfo,
        objtype: usize,
        size_bits: usize,
    ) -> Result<(), (usize, UTSpaceError)> {
        utspace_debug_println!("UtSlab::allocate_raw: {:p} {:x} {} {}", self, self.bucket.get_start_paddr(), objtype, size_bits);
        if self.caps.visible_len() == 0 {
            if self.bucket.get_bytes_remaining() >= get_object_size(objtype as u32, size_bits).expect("UtSlab::allocate_slot_raw: get_object_size returned None (this should never happen!)") as usize {
                let res = alloc.cspace().allocate_slot_raw(alloc);
                match res {
                    Ok(cptr) => {
                        let window = alloc.cspace().slot_window_raw(cptr).expect("CSpace failed to return window for slot it allocated (this should never happen!)");
                        let info = alloc.cspace().slot_info_raw(cptr).expect("CSpace failed to return window for slot it allocated (this should never happen!)");
                        if let Err(err) = self.bucket.allocate_raw(alloc, window, info, self.objsize.trailing_zeros() as usize, seL4_UntypedObject as usize, UtZone::RamAny) {
                            warn!("UtSlab::allocate_slot_raw: failed to allocate new object from slab (slots remaining: {})", alloc.cspace().slots_remaining());
                            return Err(err);
                        }
                        let offset = self.bucket.get_bytes_used() / self.objsize;
                        self.caps.put(offset, cptr);
                    },
                    Err(err) => {
                        warn!("UtSlab::allocate_slot_raw: allocating slot for new object of type {} and size {} failed with {:?} (slots remaining: {})", objtype, self.objsize, err, alloc.cspace().slots_remaining());
                        return Err((0, UTSpaceError::CapabilityAllocationFailure));
                    },
                }
            }else{
                warn!("slots remaining: {} bytes used: {}", self.get_slots_remaining(), self.bucket.get_bytes_used());
                warn!("UtSlab::allocate_slot_raw: slab of type {} and size {} exhausted", objtype, self.objsize);
                return Err((0, UTSpaceError::CapabilityAllocationFailure));
            }
        }
        let (offset, cptr) = self.caps.hide_first();
        utspace_debug_println!("internal offset: {:x}, internal cptr: {:x}", offset, cptr);
        utspace_debug_println!("root: {:x} cptr: {:x} depth: {} num_slots: {} idx: {}", dest.cnode.root.to_cap(), dest.cnode.cptr, dest.cnode.depth, dest.num_slots, dest.first_slot_idx);


        let retype_res = untyped_retype(
                cptr,
                objtype,
                size_bits,
                dest.cnode.root.to_cap(),
                dest.cnode.cptr,
                dest.cnode.depth,
                dest.first_slot_idx,
                dest.num_slots,
        );

        #[cfg(feature = "debug_utspace")]{
            let dest_slot = dest.slotref_to(&dest_info, 0).unwrap();
            utspace_debug_println!("raw dest cptr: {:x}", dest.cptr_to(&dest_info, 0).unwrap());
            utspace_debug_println!("dest root: {:x} dest cptr: {:x} dest depth: {}", dest_slot.root.to_cap(), dest_slot.cptr, dest_slot.depth);
        }
        if retype_res == 0 {
            ut_alloc.add_to_used_list(self.bucket.get_start_paddr() & !((1 << PAGE_BITS) - 1), dest, offset);
            utspace_debug_println!("retype succeeded");
            Ok(())
        }else{
            let err = sel4::Error::copy_from_ipcbuf(retype_res);
            #[cfg(feature = "debug_utspace")]
            warn!("UtSlab::allocate_raw: retyping object of type {} and size {} from internal slot {:?} to destination slot {:?} failed with {:?}", objtype, self.objsize, src_slot, dest_slot, err);
            Err((0, UTSpaceError::SyscallError { details: err }))
        }
    }
    ///Deallocates an object given a raw type code (which must match the one
    ///used when creating the slab)
    fn deallocate_raw<A: AllocatorBundle>(&self, 
        alloc: &A, 
        _ut_alloc: &UtSlabAllocator,
        _window: Window,
        _info: CNodeInfo,
        offset: usize,
    ) -> Result<(), UTSpaceError> {
        utspace_debug_println!("UtSlab::deallocate_raw: {:x} {:x}", self.bucket.get_start_paddr(), offset);
        #[cfg(feature = "debug_utspace")]{
            let (offset, cptr) = self.caps.get_first_any();
            utspace_debug_println!("{:x} {:x}", offset, cptr);
        }
        let cptr = self.caps.show(offset);
        if cptr == 0 {
            warn!("UtSlab::deallocate_raw: could not find cptr for offset {:x}", offset);
            Err(UTSpaceError::InternalError)
        }else if let Ok(slot) = alloc.cspace().cptr_to_slot(cptr){
            utspace_debug_println!("root: {:x} cptr: {:x} depth: {} num_slots: {} idx: {}", window.cnode.root.to_cap(), window.cnode.cptr, window.cnode.depth, window.num_slots, window.first_slot_idx);

            if let Err(err) = slot.revoke(){
                warn!("UtSlab::deallocate_raw: revoking cptr {:x} offset {:x} failed with {:?}", cptr, offset, err);
                self.caps.show(offset);
                return Err(UTSpaceError::SyscallError { details: err });
            }
            Ok(())
        }else{
            utspace_debug_println!("UtSlab::deallocate_raw: failed to convert cptr {:x} offset {:x} to slot", cptr, offset);
            Err(UTSpaceError::InternalError)
        }
    }
}

impl PartialEq for UtSlab {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl Drop for UtSlab {
    fn drop(&mut self) {
        utspace_debug_println!("dropping slab {:p}", self);
    }
}

impl fmt::Debug for UtSlab {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = write!(f, "UtSlab, bucket: {:?}, objsize: {}", self.bucket, self.objsize);
        Ok(())
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    utspace_debug_println!("utspace::slab::add_custom_slabs");
    alloc.add_custom_slab(size_of::<UtSlab>(), 32, 8, 8, 2)?;
    sparse_array::add_custom_slabs_suballoc::<UtSlab, A>(alloc)?;
    Ok(())
}
