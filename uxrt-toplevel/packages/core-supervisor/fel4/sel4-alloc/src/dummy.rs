// Copyright 2019 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright 2016 Robigalia Project Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use sel4::{CNode, CNodeInfo, seL4_CPtr, SlotRef, Window, Mappable};

use crate::{
    AllocatorBundle,
    cspace::{
        BulkCSpaceManager,
        CSpaceError,
        CSpaceManager,
    },
    utspace::{
        UTSpaceManager,
        UtZone,
        UTSpaceError,
    },
    vspace::{
        PageDeallocType,
        VSpaceManager,
        VSpaceError,
    },
    seL4_ARCH_VMAttributes,
};

///A dummy allocator for use in bootstrap_allocators(). All methods panic
///immediately.
#[derive(Copy, Clone, Debug)]
pub struct DummyAlloc;

#[allow(unused_variables)]
impl VSpaceManager for DummyAlloc {
    type Reservation = (usize, usize);


    fn map<A: AllocatorBundle, M: Mappable>(
        &self,
        _: &[M],
        _: usize,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: &A,
    ) -> Result<usize, VSpaceError> {
        unimplemented!()
    }

    fn map_ref<A: AllocatorBundle>(
        &self,
        _: &[SlotRef],
        _: usize,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: &A,
    ) -> Result<usize, VSpaceError> {
        unimplemented!()
    }

    fn map_raw<A: AllocatorBundle>(
        &self,
        _: &[seL4_CPtr],
        _: usize,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: &A,
    ) -> Result<usize, VSpaceError> {
        unimplemented!()
    }

    fn map_at_vaddr<A: AllocatorBundle, M: Mappable>(
        &self,
        _: &[M],
        _: usize,
        _: usize,
        _: &Self::Reservation,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: &A,
    ) -> Result<(), VSpaceError> {
        unimplemented!()
    }

    fn map_at_vaddr_ref<A: AllocatorBundle>(
        &self,
        _: &[SlotRef],
        _: usize,
        _: usize,
        _: &Self::Reservation,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: &A,
    ) -> Result<(), VSpaceError> {
        unimplemented!()
    }


    fn map_at_vaddr_raw<A: AllocatorBundle>(
        &self,
        _: &[seL4_CPtr],
        _: usize,
        _: usize,
        _: &Self::Reservation,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: &A,
    ) -> Result<(), VSpaceError> {
        unimplemented!()
    }


    fn allocate_and_map<A: AllocatorBundle>(
        &self,
        _: usize,
        _: usize,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: UtZone,
        _: &A,
    ) -> Result<usize, VSpaceError> {
        unimplemented!()
    }

    fn allocate_and_map_with_cspace<A: AllocatorBundle, C: CSpaceManager>(
        &self,
        _: usize,
        _: usize,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: UtZone,
        _: &A,
        _: &C,
    ) -> Result<usize, VSpaceError> {
        unimplemented!()
    }

    fn allocate_and_map_at_vaddr<A: AllocatorBundle>(
        &self,
        _: usize,
        _: usize,
        _: usize,
        _: &Self::Reservation,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: UtZone,
        _: &A,
    ) -> Result<(), VSpaceError> {
        unimplemented!()
    }

    fn allocate_and_map_at_vaddr_with_cspace<A: AllocatorBundle, C: CSpaceManager>(
        &self,
        _: usize,
        _: usize,
        _: usize,
        _: &Self::Reservation,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: UtZone,
        _: &A,
        _: &C,
    ) -> Result<(), VSpaceError> {
        unimplemented!()
    }

    fn change_protection<A: AllocatorBundle>(
        &self,
        _: usize,
        _: usize,
        _: sel4::CapRights,
        _: seL4_ARCH_VMAttributes,
        _: &A,
    ) -> Result<(), VSpaceError> {
        unimplemented!()
    }

    fn unmap<A: AllocatorBundle>(&self, _: usize, _: usize, _: PageDeallocType, _: &A) -> Result<usize, (usize, VSpaceError)> {
        unimplemented!()
    }

   fn get_reservation(&self, _: usize) -> Result<Self::Reservation, ()> {
       unimplemented!()
    }

    fn reserve<A: AllocatorBundle>(&self, _: usize, _: &A) -> Option<Self::Reservation> {
        unimplemented!()
    }

    fn reserve_at_vaddr<A: AllocatorBundle>(
        &self,
        _: usize,
        _: usize,
        _: &A,
    ) -> Option<Self::Reservation> {
        unimplemented!()
    }

    fn unreserve<A: AllocatorBundle>(&self, _: Self::Reservation, _: &A) -> Result<(), VSpaceError> {
        unimplemented!()
    }

    fn unreserve_at_vaddr<A: AllocatorBundle>(&self, _: usize, _: &A) -> Result<(), VSpaceError> {
        unimplemented!()
    }

    fn unreserve_range_at_vaddr<A: AllocatorBundle>(&self, _: usize, _: usize, _: &A) -> Result<(), VSpaceError> {
        unimplemented!()
    }

    fn get_cap(&self, _: usize) -> Option<seL4_CPtr> {
        unimplemented!()
    }

    fn root(&self) -> seL4_CPtr {
        unimplemented!()
    }

    fn minimum_slots(&self) -> usize {
        unimplemented!()
    }

    fn minimum_untyped(&self) -> usize {
        unimplemented!()
    }

    fn minimum_vspace(&self) -> usize {
        unimplemented!()
    }
}

#[allow(unused_variables)]
impl CSpaceManager for DummyAlloc {
    fn window(&self) -> Option<Window> {
        unimplemented!()
    }

    fn info(&self) -> Option<CNodeInfo> {
        unimplemented!()
    }

    fn parent_root(&self) -> Option<CNode> {
        unimplemented!()
    }

    fn slots_remaining(&self) -> usize {
        unimplemented!()
    }

    fn num_slots(&self) -> usize {
        unimplemented!()
    }

    fn allocate_slot<A: AllocatorBundle>(&self, _: &A) -> Result<SlotRef, CSpaceError> {
        unimplemented!()
    }

    fn allocate_slot_raw<A: AllocatorBundle>(&self, _: &A) -> Result<seL4_CPtr, CSpaceError> {
        unimplemented!()
    }

    fn free_slot<A: AllocatorBundle>(&self, _: SlotRef, _: &A) -> Result<(), CSpaceError> {
        unimplemented!()
    }

    fn free_slot_raw<A: AllocatorBundle>(&self, _: seL4_CPtr, _: &A) -> Result<(), CSpaceError> {
        unimplemented!()
    }

    fn slot_info_raw(&self, _: seL4_CPtr) -> Option<sel4::CNodeInfo> {
        unimplemented!()
    }

    fn slot_window_raw(&self, _: seL4_CPtr) -> Option<sel4::Window> {
        unimplemented!()
    }

    fn minimum_slots(&self) -> usize {
        unimplemented!()
    }

    fn minimum_untyped(&self) -> usize {
        unimplemented!()
    }

    fn minimum_vspace(&self) -> usize {
        unimplemented!()
    }
}

#[allow(unused_variables)]
impl BulkCSpaceManager for DummyAlloc {
    type Token = &'static sel4::Window;

    fn allocate_slots<A: AllocatorBundle>(&self, _: usize, _: &A) -> Result<Self::Token, ()> {
        unimplemented!()
    }

    fn free_slots<A: AllocatorBundle>(&self, _: Self::Token, _: &A) -> Result<(), ()> {
        unimplemented!()
    }

    fn slots_info(&self, _: &Self::Token) -> Option<sel4::CNodeInfo> {
        unimplemented!()
    }
}

#[allow(unused_variables)]
impl UTSpaceManager for DummyAlloc {
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        _: &A,
        _: Window,
        _: CNodeInfo,
        _: usize,
        _: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        unimplemented!()
    }


    fn allocate_raw<A: AllocatorBundle>(
        &self,
        _: &A,
        _: Window,
        _: CNodeInfo,
        _: usize,
        _: usize,
        _: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        unimplemented!()
    }

    fn deallocate_raw<A: AllocatorBundle>(&self,
        _: &A,
        _: Window,
        _: CNodeInfo,
        _: usize,
        _: usize,
    ) -> Result<(), UTSpaceError> {
        unimplemented!()
    }
    fn slot_to_paddr(&self, 
        _: SlotRef, 
        _: usize
    ) -> Result<usize, ()>{
        unimplemented!()   
    }

    fn minimum_slots(&self) -> usize {
        unimplemented!()
    }

    fn minimum_untyped(&self) -> usize {
        unimplemented!()
    }

    fn minimum_vspace(&self) -> usize {
        unimplemented!()
    }
}
