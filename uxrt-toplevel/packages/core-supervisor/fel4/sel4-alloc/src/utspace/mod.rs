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

//! Untyped allocation

mod slab;
mod split;
mod utbucket;

use sel4::{CNodeInfo, SlotRef, Window};

use crate::AllocatorBundle;
pub use self::slab::UtSlabAllocator;
pub use self::split::Split;
pub use self::utbucket::UtBucket;
use custom_slab_allocator::CustomSlabAllocator;

#[macro_export]
macro_rules! utspace_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_utspace")]
        debug!($($toks)*);
    })
}

///Error codes returned by UTSpace allocators
#[derive(Clone, Copy, Debug, Fail)]
pub enum UTSpaceError {
    #[fail(display = "System call error")]
    SyscallError { details: sel4::Error },
    #[fail(display = "Invalid argument")]
    InvalidArgument { which: usize },
    #[fail(display = "Capability allocation failure")]
    CapabilityAllocationFailure,
    #[fail(display = "Internal error")]
    InternalError,
}

impl UTSpaceError {
    fn syscall_from_details(details: sel4::ErrorDetails) -> Self{
        UTSpaceError::SyscallError {
            details: sel4::Error::from_details(details)
        }
    }
}

///Specifies the zone from which to perform an allocation
///
///RamAny allows the allocation to occur anywhere in RAM
///RamAtOrBelow forces the allocation to be in or below the given zone, mostly 
///for DMA on IOMMU-less systems (zone indices are architecture-dependent and
///can be found in bootstrap::arch_consts::UTSPACE_ZONES)
///Device allocates device memory starting at the given address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtZone {
    RamAny,
    RamAtOrBelow(usize),
    Device(usize),
}

/// Manager of some amount of untyped memory.
pub trait UTSpaceManager {
    ///Initializes slab allocation of kernel objects (which is distinct from 
    ///slab heap allocation; see utspace::slab for more information)
    ///
    ///Panics if the allocator is not a slab allocator or a wrapper around one
    fn init_slabs<A: AllocatorBundle>(&self, _slab_size_overrides: &[(u32, u32)], _alloc: &A){
        unimplemented!()
    }

    /// Allocate objects into a window.
    ///
    /// The window is entirely filled with objects, so if there are 3 slots in the window, three
    /// objects will be allocated. It is not guaranteed that all objects will come from the same
    /// underlying untyped memory object. If allocation fails, some of the slots may contain
    /// live caps.
    ///
    /// See the manual for the interpretation of `size_bits`. It is only used for CNode,
    /// Untyped Memory objects, and schedule context objects.
    ///
    /// Returns Ok if allocation of all objects succeeded. Otherwise, returns Err with the number
    /// of objects allocated and the error token of the allocation that failed.
    ///
    /// **NOTE:** failure semantics are not yet finalised.
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        window: Window,
        info: CNodeInfo,
        size_bits: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)>;

    /// Deallocate objects from a window.
    ///
    /// Note that deallocation with this method does not guarantee the objects will ever be revoked
    /// or deleted.
    ///
    /// The `size_bits` must be the same that was used to allocate the objects in the
    /// window; this is to allow efficient implementations.
    ///
    /// **NOTE:** failure semantics are not yet finalised.
    fn deallocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        window: Window,
        info: CNodeInfo,
        size_bits: usize,
    ) -> Result<(), UTSpaceError> {
        self.deallocate_raw(alloc, window, info, T::object_type(), size_bits)
    }

    /// Same semantics as `allocate`, but with the object type given explicitly 
    /// instead of via a trait.
    ///
    fn allocate_raw<A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        info: CNodeInfo,
        size_bits: usize,
        objtype: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)>;

    /// Same semantics as `deallocate`, but with the object type given explicitly instead of via a
    /// trait.
    fn deallocate_raw<A: AllocatorBundle>(&self, 
        alloc: &A, 
        window: Window, 
        info: CNodeInfo,
        objtype: usize,
        size_bits: usize, 
    ) -> Result<(), UTSpaceError>;

    ///Looks up the physical address for an object from this allocator
    ///
    ///The capability is given as the SlotRef of the containing CNode and the
    ///index within the CNode.
    fn slot_to_paddr(&self, cnode: SlotRef, slot_idx: usize) -> Result<usize, ()>;

    fn minimum_slots(&self) -> usize;

    fn minimum_untyped(&self) -> usize;

    fn minimum_vspace(&self) -> usize;
}

///A UTSpace manager that can share its used list with a higher-level allocator
pub trait LowerUTSpaceManager: UTSpaceManager {
    ///Adds an object to the used list.
    ///
    ///`paddr` is the physical address of the object, which must be page-aligned
    ///(if the object is smaller than a page, the address of the containing 
    ///untyped may be used)
    ///
    ///`dest` is the window containing the object
    ///
    ///`extra` can be whatever the upper allocator needs to be able to identify
    ///the object, as long as it fits within seL4_PageBits - 1 bits (one bit is
    ///reserved to distinguish objects allocated by the upper allocator from 
    ///those allocated by the lower one
    fn add_to_used_list(&self, paddr: usize, dest: Window, extra: usize);
    ///Deallocates an object, calling `dealloc_fn` for objects allocated by the
    ///upper allocator.
    ///
    ///dealloc_fn is passed the physical address, object type, and extra 
    ///argument from add_to_used_list.
    ///
    ///All other arguments are the same as deallocate_raw, and this method is
    ///intended to be called from the deallocate_raw implementation of the upper
    ///allocator directly
    fn deallocate_raw_lower<A: AllocatorBundle, F>(&self, 
        alloc: &A, 
        window: Window,
        info: CNodeInfo,
        objtype: usize,
        size_bits: usize,
        upper_dealloc_fn: F,
    ) -> Result<(), UTSpaceError> where 
        F: FnMut(usize, usize, usize) -> Result<(), UTSpaceError>;
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    self::slab::add_custom_slabs(alloc)?;
    self::split::add_custom_slabs(alloc)?;
    Ok(())
}

