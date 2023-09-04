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

//TODO: use a stack-allocated array for the first few slots of a MemRegion and an Option<Vec<seL4_CPtr>> for any beyond that, so that smaller allocations don't have to inner allocate anything from the heap

//! VSpace allocation

mod hier;

use sel4::{CapRights, ToCap, Mappable, seL4_CPtr, SlotRef};
use sel4_sys::seL4_ObjectTypeCount;
use alloc::vec::Vec;

use crate::{
    AllocatorBundle,
    cspace::{
        AllocatableSlotRef,
        CSpaceManager,
        CSpaceError,
    },
    utspace::{
        UTSpaceError,
        UtZone,
    },
    seL4_ARCH_VMAttributes,
};

#[macro_export]
macro_rules! vspace_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_vspace")]
        debug!($($toks)*);
    })
}

/// Gets the page object type for a given byte order
pub(crate) fn get_page_type(size_bits: usize) -> usize {
    for i in 0..PAGE_SIZES.len(){
        if size_bits == PAGE_SIZES[i].1 {
            return PAGE_SIZES[i].0;
        }
    }

    return seL4_ObjectTypeCount as usize;
}

/// A physical memory region, which holds an array of page capabilities. Must be
/// mapped into a VSpace to use.
pub struct MemRegion {
    caps: Vec<seL4_CPtr>,
    size_bits: usize,
    rights: CapRights,
    attrs: seL4_ARCH_VMAttributes,
}

impl MemRegion {
    /// Creates a new empty MemRegion.
    pub fn new_empty(size_bits: usize, rights: CapRights, attrs: seL4_ARCH_VMAttributes) -> MemRegion {
        MemRegion::new_from_vec(Vec::new(), size_bits, rights, attrs)
    }
    /// Creates a new MemRegion from an existing Vec of page capabilities and 
    /// the associated parameters.
    pub fn new_from_vec(caps: Vec<seL4_CPtr>, size_bits: usize, rights: CapRights, attrs: seL4_ARCH_VMAttributes) -> MemRegion {
        vspace_debug_println!("MemRegion::new_from_vec: len: {} first: {:x}", caps.len(), caps[0]);
        MemRegion {
            caps,
            size_bits,
            rights,
            attrs,
        }
    }
    /// Allocates page capabilities and creates a new MemRegion from them.
    pub fn new<A: AllocatorBundle, C: CSpaceManager>(bytes: usize, size_bits: usize, rights: CapRights, attrs: seL4_ARCH_VMAttributes, zone: UtZone, alloc: &A, cspace: &C) -> Result<MemRegion, VSpaceError> {
        vspace_debug_println!("MemRegion::new");
        let objtype = get_page_type(size_bits);
        if objtype == seL4_ObjectTypeCount as usize{
            return Err( VSpaceError::InvalidArgument { which: 2 });
        }

        let page_size = 1 << size_bits;
        let bytes = (bytes + (page_size - 1)) & (!(page_size - 1));
        let pages = bytes / page_size;
        let mut caps = Vec::new();
        for _ in 0..pages {
            match cspace.allocate_slot_with_object_raw(size_bits, objtype, zone, alloc) {
                Ok(cptr) => {
                    vspace_debug_println!("allocated cap: {:x}", cptr);
                    caps.push(cptr);
                },
                Err(err) => {
                    for i in 0..caps.len(){
                        let _ = cspace.free_and_delete_slot_with_object_raw(caps[i], objtype, size_bits, alloc);
                    }
                    return Err(VSpaceError::CSpaceError{ err })
                },
            }
        }
        
        Ok(MemRegion::new_from_vec(caps, size_bits, rights, attrs))
    }
    /// Creates a shallow copy of this region (the capabilities are copied to
    /// new slots for the new region)
    pub fn new_clone<A: AllocatorBundle, C: CSpaceManager>(&self, alloc: &A, rights: Option<CapRights>, attrs: Option<seL4_ARCH_VMAttributes>, cspace: &C) -> Result<MemRegion, (usize, VSpaceError)>{
        vspace_debug_println!("MemRegion::new_clone");
        let clone_rights = if let Some(r) = rights {
            r
        }else{
            self.rights
        };
        let clone_attrs = if let Some(r) = attrs {
            r
        }else{
            self.attrs
        };
        let mut new_caps = Vec::new();
        for i in 0..self.caps.len() {
            let cap = self.caps[i];
            if let Ok(slot) = cspace.cptr_to_slot(cap) {
                match slot.copy_to_new(cspace, clone_rights, alloc) {
                    Ok(new_slot) => new_caps.push(new_slot.to_cap()),
                    Err(err) => {
                        return Err((i, VSpaceError::CSpaceError { err } ))
                    },
                }
            }else{
                return Err((i, VSpaceError::InvalidArgument { which: 1 }));
            }

        }
        Ok(MemRegion::new_from_vec(new_caps, self.size_bits, self.rights, clone_attrs))
    }

    /// Frees the contents of the region (both the pages themselves and their 
    /// slots. The CSpace manager must be the same one used to allocate the 
    /// region, or this will almost certainly fail.
    pub fn free<A: AllocatorBundle, C: CSpaceManager>(&mut self, alloc: &A, cspace: &C) -> Result<(), (usize, VSpaceError)> {
        let objtype = get_page_type(self.size_bits);
        if objtype == seL4_ObjectTypeCount as usize{
            return Err((0, VSpaceError::InvalidArgument { which: 2 }));
        }

        let mut caps_freed = 0;
        for i in 0..self.caps.len() {
            let cap = self.caps[i];
            vspace_debug_println!("freeing cap: {:x}", cap);
            if let Err(err) = cspace.free_and_delete_slot_with_object_raw(cap, self.size_bits, objtype, alloc) {
                return Err((caps_freed, VSpaceError::CSpaceError{ err }));
            }
            caps_freed += 1;
        }
        self.caps.drain(0..self.caps.len());
        Ok(())
    }
    /// Gets a reference the underlying array of page capabilities
    pub fn get_caps(&self) -> &Vec<seL4_CPtr> {
        vspace_debug_println!("MemRegion::get_caps: {:p} {:x}", self, self.caps[0]);
        &self.caps
    }
    ///Gets a mutable reference the underlying array of page capabilities
    pub fn get_caps_mut(&mut self) -> &mut Vec<seL4_CPtr> {
        vspace_debug_println!("MemRegion::get_caps_mut: {:p} {:x}", self, self.caps[0]);
        &mut self.caps
    }
    ///Gets the order of the pages in the region.
    pub fn get_size_bits(&self) -> usize {
        self.size_bits
    }
}

impl Drop for MemRegion {
    fn drop(&mut self) {
        if self.caps.len() > 0 {
            panic!("attempted to drop non-empty MemRegion; address: {:p}, first CPtr {:x}, caps: {}", self, self.caps[0], self.caps.len());
        }
    }
}

pub use self::{hier::arch::PAGE_SIZES, hier::Hier, hier::add_custom_slabs};
pub use self::hier::Reservation as HierReservation;

/// VSpace error codes
#[derive(Clone, Copy, Debug, Fail)]
pub enum VSpaceError {
    #[fail(display = "Invalid argument")]
    InvalidArgument { which: usize },
    #[fail(display = "Capability allocation error")]
    CSpaceError { err: CSpaceError },
    #[fail(display = "Untyped allocation error")]
    UTSpaceError { err: UTSpaceError },
    #[fail(display = "Page mapping failure")]
    MapFailure { details: sel4::Error },
    #[fail(display = "Reservation failure")]
    ReservationFailure,
    #[fail(display = "Internal error")]
    InternalError,
}

/// Specifies how pages should be deallocated when unmapping.
///
/// NoDeallocation: does nothing (which leaks the page if it isn't referenced 
///     elsewhere)
/// FreeSlotOnly: frees and deletes the slot, but not the page itself
/// FreeObject: frees and deletes the slot and the underlying page
/// Retrieve: pushes the pages into a Vec
pub enum PageDeallocType<'a> {
    NoDeallocation,
    FreeSlotOnly,
    FreeObject(usize),
    Retrieve(&'a mut Vec<seL4_CPtr>),
}

/// A VSpace reservation
pub trait VSpaceReservation {
    /// Gets the start address of this reservation
    fn start_vaddr(&self) -> usize;
    /// Gets the end address of this reservation
    fn end_vaddr(&self) -> usize;
}

impl VSpaceReservation for (usize, usize) {
    fn start_vaddr(&self) -> usize {
        self.0
    }

    fn end_vaddr(&self) -> usize {
        self.1
    }
}

/// Manager of a virtual address space.
pub trait VSpaceManager {
    type Reservation: VSpaceReservation;

    /// Maps the page capabilities given as wrapper objects into the VSpace at
    /// the first available address range (no guarantees as to which range will
    /// be chosen if multiple suitable ranges are present).
    ///
    /// Returns the start virtual address at which the pages were mapped.
    fn map<A: AllocatorBundle, M: Copy + Mappable + ToCap>(
        &self,
        caps: &[M],
        size_bits: usize,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<usize, VSpaceError> {
        if let Some(res) = self.reserve(caps.len() * (1 << size_bits), alloc){
            if let Err(err) = self.map_at_vaddr(caps, res.start_vaddr(), size_bits, &res, rights, attrs, alloc){
                Err(err)
            }else{
                Ok(res.start_vaddr())
            }
        }else{
            Err(VSpaceError::ReservationFailure)
        }
    }
    /// Maps the page capabilities given as SlotRefs into the VSpace at
    /// the first available address range (no guarantees as to which range will
    /// be chosen if multiple suitable ranges are present).
    ///
    /// Returns the start virtual address at which the pages were mapped.
    fn map_ref<A: AllocatorBundle>(
        &self,
        caps: &[SlotRef],
        size_bits: usize,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<usize, VSpaceError> {
        if let Some(res) = self.reserve(caps.len() * (1 << size_bits), alloc){
            if let Err(err) = self.map_at_vaddr_ref(caps, res.start_vaddr(), size_bits, &res, rights, attrs, alloc){
                Err(err)
            }else{
                Ok(res.start_vaddr())
            }
        }else{
            Err(VSpaceError::ReservationFailure)
        }
    }
    /// Maps the page capabilities given as raw CPtrs into the VSpace at
    /// the first available address range (no guarantees as to which range will
    /// be chosen if multiple suitable ranges are present).
    ///
    /// Returns the start virtual address at which the pages were mapped.
    fn map_raw<A: AllocatorBundle>(
        &self,
        caps: &[seL4_CPtr],
        size_bits: usize,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<usize, VSpaceError> {
        if let Some(res) = self.reserve(caps.len() * (1 << size_bits), alloc){
            if let Err(err) = self.map_at_vaddr_raw(caps, res.start_vaddr(), size_bits, &res, rights, attrs, alloc){
                Err(err)
            }else{
                Ok(res.start_vaddr())
            }
        }else{
            Err(VSpaceError::ReservationFailure)
        }
    }
    /// Maps the region into the VSpace at the first available address range (no
    /// guarantees as to which range will be chosen if multiple suitable ranges
    /// are present).
    ///
    /// Returns the start virtual address at which the region was mapped.
    fn map_region<A: AllocatorBundle>(
        &self,
        region: &MemRegion,
        alloc: &A,
    ) -> Result<usize, VSpaceError> {
        self.map_raw(&region.caps, region.size_bits, region.rights, region.attrs, alloc)
    }

    /// Maps the page capabilities given as wrapper objects into the VSpace
    /// starting at the given virtual address
    fn map_at_vaddr<A: AllocatorBundle, M: Copy + Mappable + ToCap>(
        &self,
        caps: &[M],
        vaddr: usize,
        size_bits: usize,
        reservation: &Self::Reservation,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError>;
    /// Maps the page capabilities given as SlotRefs into the VSpace starting at
    /// the given virtual address
    fn map_at_vaddr_ref<A: AllocatorBundle>(
        &self,
        caps: &[SlotRef],
        vaddr: usize,
        size_bits: usize,
        reservation: &Self::Reservation,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError>;
    /// Maps the page capabilities given as raw CPtrs into the VSpace starting
    /// at the given virtual address
    fn map_at_vaddr_raw<A: AllocatorBundle>(
        &self,
        caps: &[seL4_CPtr],
        vaddr: usize,
        size_bits: usize,
        reservation: &Self::Reservation,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError>;
    /// Maps the region into the VSpace starting at the given virtual address
    fn map_at_vaddr_region<A: AllocatorBundle>(
        &self,
        region: &MemRegion,
        vaddr: usize,
        reservation: &Self::Reservation,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        self.map_at_vaddr_raw(&region.caps, vaddr, region.size_bits, reservation, region.rights, region.attrs, alloc) 
    }


    /// Allocates new pages placing the capabilities into the allocator bundle's
    /// CSpace allocator and maps them at the first available address, returning
    /// the start virtual address
    fn allocate_and_map<A: AllocatorBundle>(
        &self,
        bytes: usize,
        size_bits: usize,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        zone: UtZone,
        alloc: &A,
    ) -> Result<usize, VSpaceError> {
        self.allocate_and_map_with_cspace(bytes,
                                          size_bits,
                                          rights,
                                          attrs,
                                          zone,
                                          alloc,
                                          alloc.cspace())
    }
    ///Allocates new pages placing the capabilities into the given CSpace
    ///allocator and maps them at the first available address, returning the
    ///start virtual address
    fn allocate_and_map_with_cspace<A: AllocatorBundle, C: CSpaceManager>(
        &self,
        bytes: usize,
        size_bits: usize,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        zone: UtZone,
        alloc: &A,
        cspace: &C,
    ) -> Result<usize, VSpaceError> {
        if let Some(res) = self.reserve(bytes, alloc){
            if let Err(err) = self.allocate_and_map_at_vaddr_with_cspace(res.start_vaddr(), bytes, size_bits, &res, rights, attrs, zone, alloc, cspace) {
                return Err(err);
            }
            #[cfg(feature = "debug_vspace")]
            for i in (res.start_vaddr()..res.start_vaddr() + bytes).step_by(4096) {
                vspace_debug_println!("allocate_and_map_with_cspace: {:x}", i);
            }
            Ok(res.start_vaddr())
        }else{
            Err(VSpaceError::ReservationFailure)
        }
    }
    ///Allocates new pages placing the capabilities into the allocator bundle's
    ///CSpace allocator and maps them at the given virtual address
    fn allocate_and_map_at_vaddr<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        size_bits: usize,
        reservation: &Self::Reservation,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        zone: UtZone,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        self.allocate_and_map_at_vaddr_with_cspace(vaddr,
                                          bytes,
                                          size_bits,
                                          reservation,
                                          rights,
                                          attrs,
                                          zone,
                                          alloc,
                                          alloc.cspace())
    }
    /// Allocates new pages placing the capabilities into the given CSpace
    /// allocator and maps them at the given virtual address

    fn allocate_and_map_at_vaddr_with_cspace<A: AllocatorBundle, C: CSpaceManager>(
        &self,
        vaddr: usize,
        bytes: usize,
        size_bits: usize,
        reservation: &Self::Reservation,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        zone: UtZone,
        alloc: &A,
        cspace: &C,
    ) -> Result<(), VSpaceError> {
        vspace_debug_println!("VSpaceManager::allocate_and_map_at_vaddr_with_cspace");
        let mut region = MemRegion::new(bytes, size_bits, rights, attrs, zone, alloc, cspace)?;
        let res = if let Err(err) = self.map_at_vaddr_raw(region.get_caps(), vaddr, size_bits, reservation, rights, attrs, alloc){
            Err(err)
        }else{
            Ok(())
        };
        region.get_caps_mut().clear();
        res
    }

    /// Change the protection on all pages mapped starting at `vaddr` going for `bytes` to `rights`
    /// and `attrs`.
    fn change_protection<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        rights: CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError>;

    /// Unmap pages which cover the region starting at `vaddr` going for `bytes` bytes.
    ///
    /// Pages will be deallocated according to `dealloc_type`. See the 
    /// PageDeallocType documentation for more information.
    fn unmap<A: AllocatorBundle>(&self,
        vaddr: usize,
        bytes: usize,
        dealloc_type: PageDeallocType, 
        alloc: &A) -> Result<usize, (usize, VSpaceError)>;

    /// Same as unmap, but also unreserves the address range(s)
    fn unreserve_and_unmap<A: AllocatorBundle>(&self,
        vaddr: usize,
        bytes: usize,
        dealloc_type: PageDeallocType,
        alloc: &A) -> Result<usize, (usize, VSpaceError)>{
        let res = self.unmap(vaddr, bytes, dealloc_type, alloc);
        if let Err(err) = res {
            Err(err)
        }else if let Err(err) = self.unreserve_range_at_vaddr(vaddr, bytes, alloc) {
            Err((bytes, err))
        }else{
            Ok(res.unwrap())
        }
    }

    /// Same as unmap, but frees the underlying objects and their CSpace slots
    /// instead of returning their capabilities.
    ///
    /// Only works if the capabilities were allocated from the allocator
    /// bundle's CSpace.
    fn unmap_and_free<A: AllocatorBundle>(&self,
        vaddr: usize,
        bytes: usize,
        size_bits: usize,
        alloc: &A) -> Result<usize, (usize, VSpaceError)>{
        self.unmap_and_free_with_cspace(vaddr,
                                   bytes,
                                   size_bits,
                                   alloc,
                                   alloc.cspace())
    }
    /// Same as unmap_and_free, but also unreserves the associated address
    /// range(s)
    fn unreserve_and_free<A: AllocatorBundle>(&self,
        vaddr: usize,
        bytes: usize,
        size_bits: usize,
        alloc: &A) -> Result<usize, (usize, VSpaceError)>{
        self.unmap(vaddr, bytes, PageDeallocType::FreeObject(size_bits), alloc)
    }
    /// Same as unmap_and_free, but frees capabilities from a caller-provided
    /// CSpace
    fn unmap_and_free_with_cspace<A: AllocatorBundle, C: CSpaceManager>(&self,
        vaddr: usize,
        bytes: usize,
        size_bits: usize,
        alloc: &A,
        cspace: &C) -> Result<usize, (usize, VSpaceError)>{
        vspace_debug_println!("VSpaceManager::unmap_and_free_with_cspace");

        let mut caps = Vec::new();
        let res = self.unmap(vaddr, bytes, PageDeallocType::Retrieve(&mut caps), alloc);
        if let Err(err) = res{
            return Err(err);
        }
        let mut region = MemRegion::new_from_vec(caps, size_bits, CapRights::all(), 0);
        region.free(alloc, cspace)?;
        Ok(res.unwrap())
    }
    /// Same as unreserve_and_free, but frees capabilities from a
    /// caller-provided CSpace
    fn unreserve_and_free_with_cspace<A: AllocatorBundle, C: CSpaceManager>(&self,
        vaddr: usize,
        bytes: usize,
        size_bits: usize,
        alloc: &A,
        cspace: &C) -> Result<(), (usize, VSpaceError)>{
        if let Err(err) = self.unmap_and_free_with_cspace(vaddr, bytes, size_bits, alloc, cspace){
            return Err(err);
        }
        if self.unreserve_range_at_vaddr(vaddr, bytes, alloc).is_ok(){
            Ok(())
        }else{
            Err((bytes, VSpaceError::ReservationFailure))
        }
    }

    /// Reserve a region of virtual memory.
    ///
    /// This will reserve at least `bytes` worth of virtual memory, possibly rounded up to some
    /// multiple of some page size.
    fn reserve<A: AllocatorBundle>(&self, bytes: usize, alloc: &A) -> Option<Self::Reservation>;

    /// Reserve a region of virtual memory at a specific address.
    ///
    /// This will fail if the requested region overlaps an existing reservation somewhere.
    ///
    /// This will reserve at least `bytes` worth of virtual memory, possibly rounded up to some
    /// multiple of some page size.
    fn reserve_at_vaddr<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        alloc: &A,
    ) -> Option<Self::Reservation>;

    /// Get the reservation associated with an address.
    fn get_reservation(&self, vaddr: usize) -> Result<Self::Reservation, ()>;

    /// Unreserve a region.
    fn unreserve<A: AllocatorBundle>(&self, reservation: Self::Reservation, alloc: &A) -> Result<(), VSpaceError>;

    /// Unreserve a region given a pointer into it.
    ///
    /// `vaddr` can be any address in a region, it does not need to be the start address.
    fn unreserve_at_vaddr<A: AllocatorBundle>(&self, vaddr: usize, alloc: &A) -> Result<(), VSpaceError>;

    /// Unreserve only part of a region given a pointer into it and a length.
    fn unreserve_range_at_vaddr<A: AllocatorBundle>(&self, vaddr: usize, bytes: usize, alloc: &A) -> Result<(), VSpaceError>;

    /// Get the cap mapped in at an address.
    fn get_cap(&self, vaddr: usize) -> Option<seL4_CPtr>;

    /// Get the cap to the top-level paging structure.
    fn root(&self) -> seL4_CPtr;

    fn minimum_slots(&self) -> usize;

    fn minimum_untyped(&self) -> usize;

    fn minimum_vspace(&self) -> usize;
}
