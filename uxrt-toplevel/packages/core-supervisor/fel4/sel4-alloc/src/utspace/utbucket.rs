// Copyright 2019-2020 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright 2016 Robigalia Project Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::cell::Cell;

use sel4::{self, CNodeInfo, SlotRef, ToCap, Window, get_object_size};
use sel4::raw::untyped_retype;

use crate::{
    AllocatorBundle,
    bootstrap::arch_consts::UTSPACE_ZONES,
    cspace::CSpaceManager,
    utspace::{
        UTSpaceManager,
        UtZone,
        UTSpaceError,
    },
    utspace_debug_println,
};

/// Untyped region tracking.
///
/// Tracks how many objects have been allocated in an untyped region, as well as its size and the
/// number of remaining bytes.
///
/// This roughly mirrors the kernel's internal state about untyped objects, and is useful for
/// knowing whether object allocation into an untyped will be possible. All other utspace
/// allocators come down to managing these buckets.
///
/// Note that if deallocation is done without calling `deallocate`, tracking will become
/// desynchronized with the kernel and memory will be wasted.
///
/// Similarly, if allocation is done without informing this object, it will think there is more
/// free memory than there actually is.
#[derive(Debug)]
pub struct UtBucket {
    slot: SlotRef,
    objects: Cell<usize>,
    start_paddr: usize,
    bytes_used: Cell<usize>,
    size_bits: u8,
    is_device: bool,
}

impl UtBucket {
    /// Create a new `UtBucket` given a reference to an untyped memory capability, the size_bits
    /// it was created with, and its starting physical memory address.
    pub fn new(slot: SlotRef, size_bits: u8, start_paddr: usize, is_device: bool) -> UtBucket {
        UtBucket {
            slot,
            objects: Cell::new(0),
            start_paddr,
            bytes_used: Cell::new(0),
            size_bits,
            is_device,
        }
    }

    ///Returns true if this bucket has enough space for the given object
    pub fn has_space<T: sel4::Allocatable>(&self, window: Window, size_bits: usize) -> bool {
        let bytes_needed = window.num_slots * T::object_size(size_bits) as usize;
        let bytes_used = self.bytes_used.get();

        !(bytes_used + (bytes_used % bytes_needed) + bytes_needed > self.get_total_bytes())
    }

    ///Returns true if this bucket has the given number of bytes free
    pub fn has_space_in_bytes(&self, window: Window, size_in_bytes: usize) -> bool {
        let bytes_needed = window.num_slots * size_in_bytes;
        let bytes_used = self.bytes_used.get();

        !(bytes_used + (bytes_used % bytes_needed) + bytes_needed > self.get_total_bytes())
    }

    ///Returns true if this bucket has space for the given object at the given
    ///address
    pub fn has_space_at_paddr<T: sel4::Allocatable>(
        &self,
        paddr: usize,
        window: Window,
        size_bits: usize,
    ) -> bool {
        self.has_space_at_paddr_raw(paddr, window, T::object_type(), size_bits)
    }
    ///Returns true if this bucket has space for the given object (specified
    ///by a raw type code) at the given address
    pub fn has_space_at_paddr_raw(
        &self,
        paddr: usize,
        window: Window,
        objtype: usize,
        size_bits: usize,
    ) -> bool {
        let bytes_used = self.bytes_used.get();

        if paddr < self.start_paddr + bytes_used
            || paddr >= self.start_paddr + self.get_total_bytes()
        {
            return false;
        }
        let size_opt = get_object_size(objtype as u32, size_bits);
        if size_opt.is_none() {
            return false;
        }

        let bytes_needed = window.num_slots * size_opt.unwrap() as usize;
        paddr + bytes_needed <= self.start_paddr + self.get_total_bytes()
    }

    ///Gets the next address that will be allocated from this bucket
    pub fn get_next_paddr(&self) -> usize {
        self.start_paddr + self.bytes_used.get()
    }

    ///Gets the number of bytes used in this bucket
    pub fn get_bytes_used(&self) -> usize {
        self.bytes_used.get()
    }
    ///Gets the number of bytes remaining in this bucket
    pub fn get_bytes_remaining(&self) -> usize {
        self.get_total_bytes() - self.bytes_used.get()
    }

    /// Mark `count` objects as deleted.
    ///
    /// If the object count becomes 0, revoke the untyped capability, ensuring it has no children
    /// and can be reused. The return value is the attempt of that revoke, if there was one.
    fn delete(&self, count: usize) -> Option<sel4::Result> {
        self.objects.set(self.objects.get() - count);
        if self.objects.get() == 0 {
            match self.slot.revoke() {
                c @ Ok(_) => {
                    self.bytes_used.set(0);
                    Some(c)
                }
                c => Some(c),
            }
        } else {
            None
        }
    }

    ///Gets the size of this bucket in bytes
    pub fn get_total_bytes(&self) -> usize {
        1 << self.size_bits as usize
    }

    ///Gets the starting address of this bucket
    pub fn get_start_paddr(&self) -> usize {
        self.start_paddr
    }

    ///Gets the slot of the underlying untyped object
    pub fn get_slot(&self) -> SlotRef {
        self.slot
    }

    /// Allocate a new untyped with the goal of making the next available paddr from this UtBucket
    /// up_to_paddr, so that specific paddr can be allocated from.
    ///
    /// If it isn't possible to do this without wasting any space due to alignment/size constraints,
    /// allocate the largest untyped that is possible that does not waste any space.
    ///
    /// Callers should repeatedly call this function to keep allocating UtBuckets until up_to_paddr
    /// is the next available paddr from this UtBucket.
    pub fn split<A: AllocatorBundle>(
        &self,
        alloc: &A,
        up_to_paddr: usize,
    ) -> Result<UtBucket, UTSpaceError> {
        let bytes_used = self.bytes_used.get();

        utspace_debug_println!("UTBucket::split: {:x} {:x} {:x} {:x}", up_to_paddr, self.start_paddr, self.start_paddr + bytes_used, self.start_paddr + self.get_total_bytes());

        assert!(up_to_paddr % (1 << ::sel4_sys::seL4_MinUntypedBits) == 0);

        if up_to_paddr <= self.start_paddr + bytes_used
            || up_to_paddr >= self.start_paddr + self.get_total_bytes()
        {
            warn!("UtBucket::split: split address {:x} out of range", up_to_paddr);
            debug_assert!(false);
            return Err(UTSpaceError::InvalidArgument { which: 1 });
        }

        let mut bits = self.size_bits - 1;

        // TODO: This seems incredibly naive
        while bits >= ::sel4_sys::seL4_MinUntypedBits as u8 {
            let bytes_needed = 1 << bits;

            if self.start_paddr + bytes_used + bytes_needed > up_to_paddr {
                // bits is too big, we jumped past our target
                bits -= 1;
                continue;
            }

            if bytes_used + (bytes_used % bytes_needed) != bytes_used {
                // wastes due to alignment issues, reject
                bits -= 1;
                continue;
            }

            // found a good size!
            let cptr = alloc.cspace().allocate_slot_raw(alloc);
            if let Err(err) = cptr {
                warn!("UtBucket::split: allocating slot for new untyped (end address: {:x}) failed with {:?}", up_to_paddr, err);
                return Err(UTSpaceError::CapabilityAllocationFailure);
            }
            let slotinfo = alloc.cspace().slot_info_raw(cptr.unwrap()).unwrap();
            let window = alloc.cspace().slot_window_raw(cptr.unwrap()).unwrap();

            if let Err((_, e)) = self.allocate_raw(
                alloc,
                window,
                slotinfo,
                bits as usize,
                ::sel4_sys::seL4_UntypedObject as usize,
                UtZone::RamAny
            ) {
                warn!("UtBucket::split: allocating new untyped (end address: {:x}, cptr {:x}) failed with {:?}", up_to_paddr, cptr.unwrap(), e);
                return Err(e);
            }else{
                return Ok(UtBucket::new(
                    window.slotref_to(&slotinfo, 0).unwrap(),
                    bits,
                    self.start_paddr + bytes_used,
                    self.is_device,
                ))
            }
        }

        panic!("shouldn't get here");
    }

    ///Returns true if this is a device bucket
    pub fn is_device(&self) -> bool {
        self.is_device
    }
}

impl UTSpaceManager for UtBucket {
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        _alloc: &A,
        dest: Window,
        _dest_info: CNodeInfo,
        size_bits: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        let size_in_bytes = T::object_size(size_bits) as usize;
        let old_bytes_used = self.bytes_used.get();
        let old_bytes_used_plus_waste = old_bytes_used + (old_bytes_used % size_in_bytes);
        let alloc_paddr = self.start_paddr + old_bytes_used_plus_waste;
        let new_bytes_used = old_bytes_used_plus_waste + dest.num_slots * size_in_bytes;

        utspace_debug_println!(
            "Doing an Allocable::create with dest {:?}, size bits {}, size in bytes {}",
            dest, size_bits, size_in_bytes
        );

        match zone {
            UtZone::RamAtOrBelow(zone_id) => assert!(alloc_paddr <= UTSPACE_ZONES[zone_id].1),
            UtZone::Device(paddr) => {
                assert!(alloc_paddr == paddr);
                assert!(self.is_device());
            },
            _ => (),
        }

        if let Err(e) = T::create(self.slot.to_cap(), dest, size_bits){
            warn!("UtBucket::allocate: retype failed with {:?}, paddr: {:x}, root: {:x}, cptr: {:x}, depth: {}, first_slot_idx: {:x}, num_slots: {}", e, alloc_paddr, dest.cnode.root.to_cap(), dest.cnode.depth, dest.cnode.cptr, dest.first_slot_idx, dest.num_slots);
            Err((0, UTSpaceError::SyscallError { details: e }))
        }else{
            self.bytes_used.set(new_bytes_used);
            self.objects.set(self.objects.get() + dest.num_slots);
            Ok(())
        }
    }

    fn allocate_raw<A: AllocatorBundle>(
        &self,
        _alloc: &A,
        dest: Window,
        _dest_info: CNodeInfo,
        size_bits: usize,
        objtype: usize,
        _zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        let opt = get_object_size(objtype as u32, size_bits);
        if opt.is_none(){
            return Err((0, UTSpaceError::InvalidArgument { which: 3 }));
        }
        let size_in_bytes = opt.unwrap() as usize;

        utspace_debug_println!(
            "Doing an UntypedRetype with dest {:?}, size bits {}, objtype {}, size in bytes {}",
            dest, size_bits, objtype, size_in_bytes
        );

        let res = untyped_retype(
            self.slot.to_cap(),
            objtype,
            size_bits,
            dest.cnode.root.to_cap(),
            dest.cnode.cptr,
            dest.cnode.depth,
            dest.first_slot_idx,
            dest.num_slots,
        );

        if res == 0 {
            self.bytes_used.set(
                self.bytes_used.get()
                    + (self.bytes_used.get() % size_in_bytes)
                    + dest.num_slots * size_in_bytes,
            );
            self.objects.set(self.objects.get() + dest.num_slots);
            Ok(())
        } else {
            let err = UTSpaceError::SyscallError { details: sel4::Error::copy_from_ipcbuf(res) };
            warn!("UtBucket::allocate: retype failed with {:?}, objtype: {}, size_bits: {}, root: {:x}, cptr: {:x}, depth: {}, first_slot_idx: {:x}, num_slots: {}", err, objtype, size_bits, dest.cnode.root.to_cap(), dest.cnode.depth, dest.cnode.cptr, dest.first_slot_idx, dest.num_slots);
            Err((0, err))
        }
    }

    fn deallocate_raw<A: AllocatorBundle>(&self,
        _alloc: &A,
        window: Window,
        _info: CNodeInfo,
        objtype: usize,
        size_bits: usize,
    ) -> Result<(), UTSpaceError> {
        //TODO: actually check if the capability was the last one (although
        //the slab allocator will only deallocate entire untyped objects rather
        //than individual objects within them, so this isn't really a problem
        //because nothing else deallocates from this
        if let Some(e) = self.delete(window.num_slots) {
            if let Err(details) = e {
                warn!("UtBucket::allocate: retype failed with {:?}, objtype: {}, size_bits: {}, root: {:x}, cptr: {:x}, depth: {}, first_slot_idx: {:x}, num_slots: {}", details, objtype, size_bits, window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);
                Err(UTSpaceError::SyscallError { details })
            }else{
                Ok(())
            }
        }else{
            Ok(())
        }
    }

    fn slot_to_paddr(&self, _cnode: SlotRef, _slot_idx: usize) -> Result<usize, ()>{
        //this allocator doesn't support looking up physical addresses of
        //allocated capabilities; it doesn't really need to because it is only
        //used internally
        Err(())
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
