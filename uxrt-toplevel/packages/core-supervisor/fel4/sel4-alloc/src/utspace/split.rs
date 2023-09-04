// Copyright 2019-2021 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright 2017 Robigalia Project Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// This is the main allocator for untyped objects. It manages both RAM and 
/// device memory, and supports multiple zones for RAM in order to support DMA
/// devices with limited address ranges. There are independent sub-allocators
/// for each memory zone. Multiple RAM zones are supported in order to allow 
/// allocating memory within the address ranges of DMA devices with limited 
/// address spaces, and device memory is treated as a single zone. The RAM zones
/// function as buddy allocators. The device zone uses a single RBTree ordered 
/// by physical address, since it is simpler to implement allocation at specific
/// addresses than with buddy allocation. A single mapping of used capabilities 
/// to physical addresses is used for all zones.
///

//TODO: add seL4_Untyped_Merge and seL4_Untyped_Replace invocations to the kernel to allow retyping from the highest-order blocks rather than having to create two child untyped objects per split; for each order, there should be a bitmap to store all free blocks that are sub-regions of a larger block rather than having their own capabilities; the existing mappings of addresses to capabilities should still be retained of course, and should be searched before the corresponding bitmap
//

use core::{
    cell::RefCell,
    fmt
};

use sparse_array::{ShiftedSparseArray, SparseArray};

use alloc::{
    boxed::Box,
    vec::Vec,
};
use intrusive_collections::{
    intrusive_adapter, rbtree, Bound, KeyAdapter, RBTree, UnsafeRef,
};
use sel4::raw::untyped_retype;
use sel4::{
    PAGE_BITS,
    PAGE_SIZE,
    WORD_BITS,
    CNodeInfo,
    ErrorDetails,
    LookupFailureKind,
    SlotRef,
    seL4_CPtr,
    seL4_Word,
    ToCap,
    Window,
    get_object_size,
};

use custom_slab_allocator::CustomSlabAllocator;

use core::mem::size_of;

use crate::{
    AllocatorBundle,
    cspace::CSpaceManager,
    utspace::{
        LowerUTSpaceManager,
        UtBucket,
        UTSpaceManager,
        UtZone,
        UTSpaceError
    },
    utspace_debug_println,
};

fn page_order(size: usize) -> usize {
    let mut num_pages = size >> PAGE_BITS;
    if num_pages == 0 {
        num_pages = 1;
    }
    let mut order = WORD_BITS as usize - num_pages.leading_zeros() as usize - 1;
    if order != num_pages.trailing_zeros() as usize {
        order += 1;
    }
    order
}

pub struct UsedCPtrNode {
    cptr: seL4_Word,
    caps: SparseArray<usize>,
    link: rbtree::Link,
}

intrusive_adapter!(UsedCPtrAdapter = UnsafeRef<UsedCPtrNode>: UsedCPtrNode { link: rbtree::Link });

impl<'a> KeyAdapter<'a> for UsedCPtrAdapter {
    type Key = usize;
    fn get_key(&self, node: &'a UsedCPtrNode) -> usize {
        node.cptr
    }
}

pub struct UsedDepthNode {
    depth: u8,
    nodes: RefCell<RBTree<UsedCPtrAdapter>>,
    link: rbtree::Link,
}

intrusive_adapter!(UsedDepthAdapter = UnsafeRef<UsedDepthNode>: UsedDepthNode { link: rbtree::Link });

impl<'a> KeyAdapter<'a> for UsedDepthAdapter {
    type Key = u8;
    fn get_key(&self, node: &'a UsedDepthNode) -> u8 {
        node.depth
    }
}

pub struct UsedRootNode {
    root: seL4_CPtr,
    nodes: RefCell<RBTree<UsedDepthAdapter>>,
    link: rbtree::Link,
}

intrusive_adapter!(UsedRootAdapter = UnsafeRef<UsedRootNode>: UsedRootNode { link: rbtree::Link });

impl<'a> KeyAdapter<'a> for UsedRootAdapter {
    type Key = usize;
    fn get_key(&self, node: &'a UsedRootNode) -> usize {
        node.root
    }
}

///The dispatcher component of the buddy allocator, which directs 
///allocations/deallocations to the appropriate zone, as well as managing the 
///used list that maps capabilities to physical addresses

pub struct Split {
    ram: Vec<RAMZone>, 
    device: DeviceZone,
    used: RefCell<RBTree<UsedRootAdapter>>,
}

impl Split {
    ///Creates a new buddy allocator with the given list of zones and maximum
    ///page order
    pub fn new(zones: &[(usize, usize)], max_order: usize) -> Split {
        utspace_debug_println!("Split::new {}", max_order);
        let mut ram: Vec<RAMZone> = Vec::new();
        for i in 0..zones.len() {
            utspace_debug_println!("{:x} {:x}", zones[i].0, zones[i].1);
            ram.push(RAMZone::new(zones[i], max_order));
        }
        ram.push(RAMZone::new(zones[zones.len() - 1], max_order));
        Split {
            ram,
            device: DeviceZone::new(),
            used: RefCell::new(Default::default()),
        }
    }

    /// Add a UtBucket to this allocator.
    ///
    /// This function allocates from the heap to store metadata about the
    /// UtBucket.
    pub fn add_bucket<A: AllocatorBundle>(&self, alloc: &A, bucket: UtBucket) -> Result<(), UTSpaceError> {
        utspace_debug_println!(
            "Split::add_bucket: paddr {:x} - {:x}     {:?}",
            bucket.get_start_paddr(),
            bucket.get_start_paddr() + bucket.get_total_bytes(),
            bucket
        );
        if bucket.is_device() {
            self.device.add_bucket(alloc, bucket)
        } else {
            self.add_ram_bucket(alloc, bucket)
        }
    }
    ///Internal method to add a UTBucket to the appropriate RAM zone(s)
    fn add_ram_bucket<A: AllocatorBundle>(&self, alloc: &A, mut bucket: UtBucket) -> Result<(), UTSpaceError>{
        utspace_debug_println!("Split::add_ram_bucket");
        for i in 0..self.ram.len(){
            let zone = &self.ram[i];
            if bucket.get_start_paddr() < zone.end {
                if bucket.get_start_paddr() + bucket.get_total_bytes() > zone.end {
                    let mut new_bucket = bucket;
                    //if the bucket straddles a zone boundary, split it into
                    //separate buckets on either side

                    // recursively split bucket until we get to zone.end
                    loop {
                        utspace_debug_println!("{:x} {:x}", new_bucket.get_next_paddr(), zone.end);
                        if new_bucket.get_next_paddr() >= zone.end {
                            bucket = new_bucket;
                            break;
                        }
                        new_bucket = new_bucket.split(alloc, zone.end).expect("Split::add_ram_bucket: failed to split bucket that straddles zone boundary");

                        if let Err(err) = zone.add_bucket(alloc, &new_bucket){
                            return Err(err);
                        }
                        utspace_debug_println!("split: success");
                    }
                }else{
                    if let Err(err) = zone.add_bucket(alloc, &bucket){
                        return Err(err);
                    }
                    utspace_debug_println!("contiguous: success");
                }
            }
        }
        utspace_debug_println!("success");
        Ok(())
    }

    ///Internal implementation of add_to_used_list()
    fn add_to_used_list_internal(&self, paddr: usize, dest: Window, extra: usize){
        let root = dest.cnode.root.to_cap();
        let depth = dest.cnode.depth;
        let cptr = dest.cnode.cptr;
        utspace_debug_println!("add_to_used_list_internal: root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {:x}, paddr: {:x}, extra: {:x}", root, depth, cptr, dest.first_slot_idx, dest.num_slots, paddr, extra);

        let mut root_nodes = self.used.borrow_mut();
        let mut root_cursor = root_nodes.upper_bound_mut(Bound::Included(&root));
        if root_cursor.is_null() || root_cursor.get().unwrap().root < root {
            let new_root_node = UsedRootNode {
                root,
                nodes: Default::default(),
                link: Default::default(),
            };
            root_cursor.insert_after(UnsafeRef::from_box(Box::new(new_root_node)));
            root_cursor.move_next();
        }
        let root_node = root_cursor.get().unwrap();

        let depth_node;
        let mut depth_nodes = root_node.nodes.borrow_mut();
        let mut depth_cursor = depth_nodes.upper_bound_mut(Bound::Included(&depth));
        if depth_cursor.is_null() || depth_cursor.get().unwrap().depth < depth {
            let new_depth_node = UsedDepthNode {
                depth,
                nodes: Default::default(),
                link: Default::default(),
            };
            depth_cursor.insert_after(UnsafeRef::from_box(Box::new(new_depth_node)));
            depth_cursor.move_next();
        }
        depth_node = depth_cursor.get().unwrap();

        let mut cptr_nodes = depth_node.nodes.borrow_mut();
        let mut cptr_cursor = cptr_nodes.upper_bound_mut(Bound::Included(&cptr));
        if cptr_cursor.is_null() || cptr_cursor.get().unwrap().cptr < cptr {
            let new_cptr_node = UsedCPtrNode {
                cptr,
                caps: SparseArray::new(),
                link: Default::default(),
            };
            cptr_cursor.insert_after(UnsafeRef::from_box(Box::new(new_cptr_node)));
            cptr_cursor.move_next();
        }
        let cptr_node = cptr_cursor.get().unwrap();
        let paddr_and_extra = paddr | extra;
        utspace_debug_println!("Split::add_to_used_list_internal: {} {:x}", dest.first_slot_idx, paddr_and_extra);
        //TODO: support multiple slots per window
        utspace_debug_println!("cptr_node: {:p} paddr_and_extra: {:x}", cptr_node, paddr_and_extra);
        cptr_node.caps.put(dest.first_slot_idx, paddr_and_extra);
    }
    ///Internal implementation for allocate_ram() and allocate_raw_ram()
    fn allocate_ram_base<A: AllocatorBundle, F>(
        &self,
        alloc: &A,
        num_slots: usize,
        order: usize,
        zone: UtZone,
        retype_fn: &mut F,
    ) -> Result<(), (usize, UTSpaceError)> where F: FnMut(usize, usize, usize, usize) -> Result<(), UTSpaceError> {
        utspace_debug_println!("Split::allocate_ram_base: {} {}", num_slots, order);

        if alloc.lock_alloc().is_err() {
            warn!("Split::allocate_ram_base: failed to acquire recursion lock");
            return Err((0, UTSpaceError::CapabilityAllocationFailure));
        }

        let max_index;
        match zone {
            UtZone::RamAny => {
                   max_index = self.ram.len() - 1;
                },
            UtZone::RamAtOrBelow(index) => {
                   max_index = index; 
                },
            UtZone::Device(_) => {
                    panic!("attempt to allocate device memory with allocate_ram_base() (this should never happen!)");
                },
        }
        //allocate from the highest zone with free blocks, allowing allocation
        //to spill over into a lower zone if the original highest free one has
        //insufficient free blocks
        let mut slots_remaining = num_slots;
        for i in (0..max_index + 1).rev() {
            let mut alloc_slots = self.ram[i].slots_available(alloc, slots_remaining, order);
            if alloc_slots < slots_remaining {
                if i == 0 {
                    warn!("Split::allocate_ram_base: insufficient free blocks remaining (required: {}, remaining: {})", alloc_slots, slots_remaining);
                    let err = UTSpaceError::syscall_from_details(
                            ErrorDetails::NotEnoughMemory { bytes_available: 0 }
                    );
                    let _ = alloc.unlock_alloc();
                    return Err((num_slots - slots_remaining, err));
                }
            }else{
                alloc_slots = slots_remaining;
            }
            if let Err((slots_allocated, err)) = self.ram[i].allocate(alloc, 
                        alloc_slots, 
                        order, 
                        &mut |paddr, cap, num_slots| { retype_fn(paddr, cap, num_slots, i) }) {
                slots_remaining -= slots_allocated;
                let _ = alloc.unlock_alloc();
                return Err((num_slots - slots_remaining, err));
            }
            slots_remaining -= alloc_slots;
            if slots_remaining == 0 {
                if alloc.unlock_alloc().is_err() {
                    warn!("Split::allocate_ram_base: failed to release recursion lock");
                    return Err((num_slots - slots_remaining, UTSpaceError::CapabilityAllocationFailure));
                }
                return Ok(());
            }
        }
        let _ = alloc.unlock_alloc();
        Err((0, UTSpaceError::InternalError))
    }

    ///Internal method called by allocate() to allocate from RAM zones
    fn allocate_ram<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        _info: CNodeInfo,
        size_bits: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        let mut slots_allocated = 0;
        let order = page_order(T::object_size(size_bits) as usize);

        utspace_debug_println!("Split::allocate_ram: root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", dest.cnode.root.to_cap(), dest.cnode.depth, dest.cnode.cptr, dest.first_slot_idx, dest.num_slots);

        self.allocate_ram_base(alloc, dest.num_slots, order, zone, &mut |paddr, cap, num_slots, zone_index| {
            utspace_debug_println!("allocate_ram inner: {}", slots_allocated);
            if num_slots > 1 {
                panic!("TODO: add support for allocating multiple objects within a single invocation of a retype closure");
            }
            let single_dest = Window {
                cnode: dest.cnode,
                first_slot_idx: dest.first_slot_idx + slots_allocated,
                num_slots
            };
            if let Err(err) = T::create(cap, single_dest, size_bits){
                warn!("Split::allocate_ram: allocation failed with {:?}, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", err, dest.cnode.root.to_cap(), dest.cnode.depth, dest.cnode.cptr, dest.first_slot_idx, dest.num_slots);
                return Err(UTSpaceError::SyscallError {details: err})
            }
            slots_allocated += num_slots;
            self.add_to_used_list_internal(paddr, single_dest, zone_index);
            Ok(())
        })
    }
    ///Internal method called by allocate_raw() to allocate from RAM zones
    fn allocate_raw_ram<A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        _info: CNodeInfo,
        size_bits: usize,
        objtype: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        utspace_debug_println!("Split::allocate_raw_ram: root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", dest.cnode.root.to_cap(), dest.cnode.depth, dest.cnode.cptr, dest.first_slot_idx, dest.num_slots);

        let mut objs_allocated = 0;
        let size_in_bytes = get_object_size(objtype as u32, size_bits);
        if size_in_bytes.is_none(){
            return Err((0, UTSpaceError::InvalidArgument { which: 3 }));
        }
        let order = page_order(size_in_bytes.unwrap() as usize);

        self.allocate_ram_base(alloc, dest.num_slots, order, zone, &mut |paddr, cap, num_slots, zone_index| {
            utspace_debug_println!("allocate_raw_ram inner: {}", objs_allocated);
            if num_slots > 1 {
                panic!("TODO: add support for allocating multiple objects within a single invocation of a retype closure");
            }
            let res = untyped_retype(
                cap,
                objtype,
                size_bits,
                dest.cnode.root.to_cap(),
                dest.cnode.cptr,
                dest.cnode.depth,
                dest.first_slot_idx + objs_allocated,
                num_slots,
            );
            if res == 0 {
                self.add_to_used_list_internal(paddr, Window {
                    cnode: dest.cnode,
                    first_slot_idx: dest.first_slot_idx + objs_allocated,
                    num_slots,
                }, zone_index);
                objs_allocated += num_slots;

                Ok(())
            } else {
                let err = sel4::Error::copy_from_ipcbuf(res);
                warn!("Split::allocate_raw_ram: allocation failed with {:?}, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", err, dest.cnode.root.to_cap(), dest.cnode.depth, dest.cnode.cptr, dest.first_slot_idx, dest.num_slots);

                Err(UTSpaceError::SyscallError { 
                    details: err,
                })
            }
        })
    }
}

impl UTSpaceManager for Split {
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        info: CNodeInfo,
        size_bits: usize,
        zone: UtZone,
    ) -> Result<(), (usize, UTSpaceError)> {
        match zone {
            UtZone::RamAny => {
                self.allocate_ram::<T, A>(alloc, dest, info, size_bits, zone)
                },
            UtZone::RamAtOrBelow(_) => {
                self.allocate_ram::<T, A>(alloc, dest, info, size_bits, zone)
                },
            UtZone::Device(addr) => {
                self.device.allocate::<T, A>(alloc, dest, info, size_bits, addr)
            },
        }
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
        match zone {
            UtZone::RamAny => {
                self.allocate_raw_ram(alloc, dest, dest_info, size_bits, objtype, zone)
                },
            UtZone::RamAtOrBelow(_) => {
                self.allocate_raw_ram(alloc, dest, dest_info, size_bits, objtype, zone)
                },
            UtZone::Device(addr) => {
                self.device.allocate_raw(alloc, dest, dest_info, objtype, size_bits, addr)
            },
        }
    }
    fn deallocate_raw<A: AllocatorBundle>(&self, 
        alloc: &A, 
        window: Window, 
        info: CNodeInfo,
        objtype: usize,
        size_bits: usize, 
    ) -> Result<(), UTSpaceError> {
        self.deallocate_raw_lower(alloc, window, info, objtype, size_bits, |_, _, _| {
            Err(UTSpaceError::InternalError)
        })
    }

    fn slot_to_paddr(&self, cnode: SlotRef, slot_idx: usize) -> Result<usize, ()> {
        let root = cnode.root.to_cap();
        let depth = cnode.depth;
        let cptr = cnode.cptr;

        utspace_debug_println!("Split::slot_to_paddr {:x} {:x} {} {:x}", root, cptr, depth, slot_idx);
        let root_nodes = self.used.borrow();
        let root_cursor = root_nodes.find(&root);
        if root_cursor.is_null() {
            return Err(());
        }
        let root_node = root_cursor.get().unwrap();

        let depth_nodes = root_node.nodes.borrow_mut();
        let depth_cursor = depth_nodes.find(&depth);
        if depth_cursor.is_null() {
            return Err(());
        }
        let depth_node = depth_cursor.get().unwrap();

        let cptr_nodes = depth_node.nodes.borrow_mut();
        let cptr_cursor = cptr_nodes.find(&cptr);
        if cptr_cursor.is_null() {
            return Err(());
        }
        let cptr_node = cptr_cursor.get().unwrap();
        let paddr_and_extra = cptr_node.caps.get(slot_idx);
        utspace_debug_println!("cptr_node: {:p} paddr_and_extra: {:x}", cptr_node, paddr_and_extra);
        return Ok(paddr_and_extra & !((PAGE_SIZE) - 1));
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

impl LowerUTSpaceManager for Split {
    fn add_to_used_list(&self, paddr: usize, dest: Window, extra: usize) {
        utspace_debug_println!("Split::add_to_used_list: {:x} {:x}", paddr, extra);
        self.add_to_used_list_internal(paddr, dest, extra | 1 << (PAGE_BITS - 1))
    }
    fn deallocate_raw_lower<A: AllocatorBundle, F>(&self, 
        alloc: &A, 
        window: Window,
        _info: CNodeInfo,
        objtype: usize,
        size_bits: usize,
        mut upper_dealloc_fn: F,
    ) -> Result<(), UTSpaceError> where
        F: FnMut(usize, usize, usize) -> Result<(), UTSpaceError> 
    {
        if alloc.lock_dealloc().is_err() {
            warn!("Split::deallocate_raw_lower: acquiring recursion lock failed, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);
            return Err(UTSpaceError::CapabilityAllocationFailure);
        }

        let size_in_bytes = get_object_size(objtype as u32, size_bits);
        if size_in_bytes.is_none(){
            warn!("Split::deallocate_raw_lower: invalid object type {} and order in bytes {}, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", objtype, size_bits, window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);
            return Err(UTSpaceError::InvalidArgument { which: 3 });
        }

        let root = window.cnode.root.to_cap();
        let depth = window.cnode.depth;
        let cptr = window.cnode.cptr;

        let root_nodes = self.used.borrow();

        let root_cursor = root_nodes.find(&root);

        utspace_debug_println!("Split::deallocate_raw: root: {:x}, depth: {:x}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {:x}", root, depth, cptr, window.first_slot_idx, window.num_slots);

        if root_cursor.is_null() {
            warn!("Split::deallocate_raw_lower: root not found in used list, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);
            return Err(UTSpaceError::syscall_from_details(
                        ErrorDetails::FailedLookup {
                            failed_for_source: true,
                            lookup_kind: LookupFailureKind::InvalidRoot
                        } 
                    ));
        }
        let root_node = root_cursor.get().unwrap();
 
        let mut depth_nodes = root_node.nodes.borrow_mut();
        let depth_cursor = depth_nodes.find_mut(&depth);
        if depth_cursor.is_null() {
            warn!("Split::deallocate_raw_lower: depth not found in used list, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);
            return Err(UTSpaceError::syscall_from_details(
                        ErrorDetails::FailedLookup {
                            failed_for_source: true,
                            lookup_kind: sel4::LookupFailureKind::DepthMismatch {
                                bits_remaining: depth as usize,
                                bits_resolved: 0,
                            } 
                        }
                    ));
        }
        let depth_node = depth_cursor.get().unwrap();

        let mut cptr_nodes = depth_node.nodes.borrow_mut();
        let cptr_cursor = cptr_nodes.find_mut(&cptr);
        if cptr_cursor.is_null() {
            warn!("Split::deallocate_raw_lower: cptr not found in used list, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);
            return Err( UTSpaceError::syscall_from_details(
                    ErrorDetails::InvalidCapability {
                            which: 0,
                        } 
                    ));
        }
        let cptr_node = cptr_cursor.get().unwrap();

        for slot_idx in window.first_slot_idx..window.first_slot_idx + window.num_slots {
            utspace_debug_println!("{:x}", slot_idx);
            let paddr_and_zone = cptr_node.caps.get(slot_idx);
            utspace_debug_println!("{:x}", paddr_and_zone);
            if paddr_and_zone == 0 {
                warn!("Split::deallocate_raw_lower: slot {:x} not found in used list, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", slot_idx, window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);
                return Err(UTSpaceError::syscall_from_details(
                    ErrorDetails::InvalidCapability {
                            which: 0,
                        } 
                    ));
            }
        }
        for slot_idx in window.first_slot_idx..window.first_slot_idx + window.num_slots {
            let paddr_and_extra = cptr_node.caps.take(slot_idx);
            let paddr = paddr_and_extra & !((PAGE_SIZE) - 1);
            let extra = paddr_and_extra & ((1 << PAGE_BITS - 1) - 1);
            let order = page_order(size_in_bytes.unwrap() as usize);
            utspace_debug_println!("paddr_and_extra: {:x}, paddr: {:x}, extra: {}", paddr_and_extra, paddr, extra);
            //the high bit of the part of the address within the page is high
            //if the object was added by an upper allocator rather than this
            //one
            if paddr_and_extra & (1 << (PAGE_BITS - 1)) != 0{
                if let Err(err) = upper_dealloc_fn(paddr, objtype, extra) {
                    let _ = alloc.unlock_dealloc();
                    return Err(err)
                }
            }else if extra == self.ram.len() {
                if let Err(err) = self.device.free(alloc, paddr, order) {
                    let _ = alloc.unlock_dealloc();
                    return Err(err);
                }
            }else{
                if let Err(err) = self.ram[extra].free(alloc, paddr, order) {
                    let _ = alloc.unlock_dealloc();
                    return Err(err);
                }
            }
        }
        //TODO: delete any RBTree nodes that were emptied by this deallocation
        if alloc.unlock_dealloc().is_err() {
            return Err(UTSpaceError::CapabilityAllocationFailure);
        }
        Ok(())
    }
}

impl fmt::Debug for Split {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = writeln!(f, "RAM zones:");
        for zone in 0..self.ram.len(){
            let _ = writeln!(f, "{:?}:", zone);
            let _ = writeln!(f, "{:?}", self.ram[zone]);
        }
        Ok(())
    }
}

///Sub-allocator that manages a single RAM zone
struct RAMZone {
    start: usize,
    end: usize,
    contents: Vec<ShiftedSparseArray<usize>>,
}

impl RAMZone {
    ///Create a new sub-allocator with the given bounds and maximum order
    fn new(bounds: (usize, usize), max_order: usize) -> RAMZone {
        let mut contents: Vec<ShiftedSparseArray<usize>> = Vec::new();
        for order in 0..max_order as u32 + 1 {
            contents.push(ShiftedSparseArray::new(order + PAGE_BITS as u32));
        }
        RAMZone {
            start: bounds.0,
            end: bounds.1,
            contents,
        }
    }
    ///Add a UTBucket to this zone
    fn add_bucket<A: AllocatorBundle>(&self, alloc: &A, bucket: &UtBucket) -> Result<(), UTSpaceError> {
        utspace_debug_println!(
            "RAMZone::add_bucket: paddr {:x} - {:x}     {:?}",
            bucket.get_start_paddr(),
            bucket.get_start_paddr() + bucket.get_total_bytes(),
            bucket
        );

        //TODO: instead of retyping from each bucket here, use an excess list 
        //that is a single-level RBTree of UTBuckets ordered by address, and 
        //add all blocks in each bucket to the bitmap of no-capability blocks; 
        //to allocate a block that has no capability associated with it, look 
        //for the bucket with the nearest address at or below the maximum-order 
        //block when retyping from the excess list; if the address of a block at
        //the requested order is at the watermark of a bucket in the excess list
        //when allocating, retype directly from the bucket, and if it is higher 
        //than the watermark, allocate filler blocks (placing them at the 
        //appropriate order in the free list) until the address is reached; 
        //always look for blocks that have their own capability before looking 
        //for sub-blocks of a higher-order block 

        while bucket.get_bytes_remaining() >= PAGE_SIZE {
            utspace_debug_println!("remaining: {}", bucket.get_bytes_remaining());
            let mut order = page_order(bucket.get_bytes_remaining());
            if order > self.contents.len() - 1{
                order = self.contents.len() - 1;
            }
            let paddr = bucket.get_next_paddr();
            match alloc.cspace().allocate_slot_raw(alloc) {
                Ok(cptr) => {
                    let window = alloc.cspace().slot_window_raw(cptr).expect("could not get window for top-level capability; this should never happen");
                    let info = alloc.cspace().slot_info_raw(cptr).expect("could not get window for top-level capability; this should never happen");
                    let zone = if bucket.is_device() { 
                        UtZone::Device(paddr) 
                    }else{ 
                        UtZone::RamAny 
                    };
                    if let Err((_, e)) = bucket.allocate_raw(
                            alloc,
                            window,
                            info,
                            order + PAGE_BITS as usize,
                            ::sel4_sys::seL4_UntypedObject as usize,
                            zone) 
                    {
                        warn!("RAMZone::add_bucket: allocating from bucket failed with {:?}, paddr: {:x} root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}, num_slots: {}", e, paddr, window.cnode.root.to_cap(), window.cnode.depth, window.cnode.cptr, window.first_slot_idx, window.num_slots);

                        return Err(e)
                    }
                    utspace_debug_println!("add_bucket: order: {} paddr: {:x} cptr: {:x}", order, paddr, cptr);
                    self.contents[order].put(paddr, cptr);
                    utspace_debug_println!("block done");
                },
                Err(e) => {
                    warn!("RAMZone::add_bucket: allocating capability slot failed with {:?} for paddr: {:x}", e, paddr);
                    return Err(UTSpaceError::CapabilityAllocationFailure);
                }
            }
            utspace_debug_println!("RAMZone::add_bucket: done");
        }
        Ok(())
    }
    ///Get the number of slots of the given order available
    fn slots_available<A: AllocatorBundle>(
        &self,
        _alloc: &A,
        _num_slots: usize,
        order: usize,
    ) -> usize {
        let slot_order = 0;
        let mut slots_available = 0;
        for o in order..self.contents.len(){
            slots_available += self.contents[o].visible_len() * (1 << slot_order);
        }
        return slots_available;
    }
    ///Allocate an object from this zone
    fn allocate<A: AllocatorBundle, F>(
        &self,
        alloc: &A,
        num_slots: usize,
        order: usize,
        retype_fn: &mut F,
    ) -> Result<(), (usize, UTSpaceError)> where F: FnMut(usize, usize, usize) -> Result<(), UTSpaceError> {
        utspace_debug_println!("RAMZone::allocate {} {}", num_slots, order);
        //TODO: if multiple capabilities are requested, try to allocate them in as few retype operations as possible (which will require iteratively trying to allocate as large a block as possible that will fit the requested number of objects without any leftover space)
        #[cfg(feature = "debug_utspace")]
        for o in order..self.contents.len(){
            utspace_debug_println!("order: {}, free: {}", o, self.contents[o].visible_len());
        }
        for s in 0..num_slots {
            utspace_debug_println!("slot: {}", s);
            let mut start_order = 0;
            for o in order..self.contents.len(){
                utspace_debug_println!("order: {}, free: {}", o, self.contents[o].visible_len());
                if self.contents[o].visible_len() > 0 {
                    start_order = o;
                    break;
                } else if o == self.contents.len() {
                    warn!("RAMZone::allocate: out of memory after allocating {} out of {} slots", s, num_slots);
                    return Err((s, UTSpaceError::syscall_from_details(
                            ErrorDetails::NotEnoughMemory { bytes_available: 0 }
                    )));
                }
            }
            utspace_debug_println!("start_order: {}", start_order);
            for o in (order..start_order + 1).rev(){
                let (paddr, cap) = self.contents[o].hide_first();
                utspace_debug_println!("order: {}, paddr: {:x}, cap: {:x}", o, paddr, cap);
                if o == order {
                    if let Err(err) = retype_fn(paddr, cap, 1) {
                        return Err((s, err));
                    }
                } else {
                    //TODO: don't allocate a second untyped for the free buddy block; instead, set the address in a sparse array bitmap for the order below the current one, and search the bitmap before the address-to-capability list when searching for free blocks
                    match alloc.cspace().allocate_slot_raw(alloc) {
                        Ok(first_cptr) => {
                            let first_cptr_window = alloc.cspace().slot_window_raw(first_cptr).expect("could not get window for first cptr; this should never happen");
                            utspace_debug_println!("cap: {:x}, first_cptr: {:x}, size_bits: {}, root: {:x}, cptr: {:x}, depth: {}, first_slot_idx: {:x}, num_slots: {}", cap, first_cptr, (o - 1) + PAGE_BITS as usize, first_cptr_window.cnode.root.to_cap(), first_cptr_window.cnode.cptr, first_cptr_window.cnode.depth, first_cptr_window.first_slot_idx, first_cptr_window.num_slots);

                            let res = untyped_retype(
                                cap,
                                ::sel4_sys::seL4_UntypedObject as usize,
                                (o - 1) + PAGE_BITS as usize,
                                first_cptr_window.cnode.root.to_cap(),
                                first_cptr_window.cnode.cptr,
                                first_cptr_window.cnode.depth,
                                first_cptr_window.first_slot_idx,
                                first_cptr_window.num_slots,
                            );
                            utspace_debug_println!("res: {}", res);
                            if res != 0 {
                                let err = sel4::Error::copy_from_ipcbuf(res);
                                warn!("RAMZone::allocate: retyping first buddy block of order {} failed with {:?}, paddr: {:x}, root: {:x}, depth: {}, cptr: {:x}, first_slot_idx: {:x}", o, err, paddr, first_cptr_window.cnode.root.to_cap(), first_cptr_window.cnode.depth, first_cptr_window.cnode.cptr, first_cptr_window.first_slot_idx);

                                return Err((s, UTSpaceError::SyscallError { 
                                    details: err}))
                            }
                            utspace_debug_println!("allocate/0: {:x} {:x}", paddr, first_cptr);
                            self.contents[o - 1].put(paddr, first_cptr);
                        },
                        Err(err) => {
                            warn!("RAMZone::allocate: allocating slot for first buddy block of order {} failed with {:?}, paddr: {:x}", o, err, paddr);
                            return Err((s, UTSpaceError::CapabilityAllocationFailure))
                        },
                    }
                    match alloc.cspace().allocate_slot_raw(alloc) {
                        Ok(second_cptr) => {
                            let second_cptr_window = alloc.cspace().slot_window_raw(second_cptr).expect("could not get window for second cptr; this should never happen");
                            utspace_debug_println!("cap: {:x}, second_cptr: {:x}, size_bits: {}, root: {:x}, cptr: {:x}, depth: {}, first_slot_idx: {:x}", cap, second_cptr, (o - 1) + PAGE_BITS as usize, second_cptr_window.cnode.root.to_cap(), second_cptr_window.cnode.cptr, second_cptr_window.cnode.depth, second_cptr_window.first_slot_idx);


                            let res = untyped_retype(
                                cap,
                                ::sel4_sys::seL4_UntypedObject as usize,
                                (o - 1) + PAGE_BITS as usize,
                                second_cptr_window.cnode.root.to_cap(),
                                second_cptr_window.cnode.cptr,
                                second_cptr_window.cnode.depth,
                                second_cptr_window.first_slot_idx,
                                second_cptr_window.num_slots,
                            );
                            utspace_debug_println!("res: {}", res);
                            if res != 0 {
                                let err = sel4::Error::copy_from_ipcbuf(res);
                                warn!("RAMZone::allocate: retyping second buddy block of order {} failed with {:?}, paddr: {:x}, root: {:x}, depth: {}, cptr: {:x}, second_slot_idx: {:x}", o, err, paddr, second_cptr_window.cnode.root.to_cap(), second_cptr_window.cnode.depth, second_cptr_window.cnode.cptr, second_cptr_window.first_slot_idx);

                                return Err((s, UTSpaceError::SyscallError { 
                                    details: err}))
                            }
                            utspace_debug_println!("allocate/1: {:x} {:x}", paddr, second_cptr);
                            self.contents[o - 1].put(paddr + (1 << (o - 1 + PAGE_BITS as usize)), second_cptr);
                        },
                        Err(err) => {
                            warn!("RAMZone::allocate: allocating slot for second buddy block of order {} failed with {:?}, paddr: {:x}", o, err, paddr);
                            return Err((s, UTSpaceError::CapabilityAllocationFailure))
                        },
                    }
                }
                utspace_debug_println!("allocate/2: {:x} {:x}", paddr, cap);
            }
        }
        Ok(())
    }
    ///Deallocate an object from this zone
    fn free<A: AllocatorBundle>(
        &self,
        alloc: &A,
        freed_address: usize,
        order: usize,
    ) -> Result<(), UTSpaceError> {
        utspace_debug_println!("free {:x} {}", freed_address, order);
        let mut current_address = freed_address;
        for o in order..self.contents.len(){
            let address = current_address;
            utspace_debug_println!("{} {:x}", o, current_address);
            let cap = self.contents[o].take_hidden(current_address);
            utspace_debug_println!("{:x}", cap);
            if cap == 0 {
                if o == order{
                    warn!("RAMZone::free: no used capability found for address {:x} and order {}", freed_address, order);
                    return Err(UTSpaceError::InternalError);
                }else{
                    break;
                }
            }
            let buddy_address;
            //check if this is the first or second block of the parent (after 
            //this, current_address is only used as the address of the parent
            //and not of the original block)
            if current_address & ((1 << (order + 1 + PAGE_BITS as usize)) - 1) != 0{
                //this is the second, so use the first block as the address of 
                //the parent as well as the buddy block
                buddy_address = address - (1 << (order + PAGE_BITS as usize));
                current_address = buddy_address;
            }else{
                //this is the first block, so the parent will also have the same 
                //address
                buddy_address = address + (1 << (order + PAGE_BITS as usize));
            }

            utspace_debug_println!("free/0: {} {:x} {:x}", o, current_address, buddy_address);
            let mut buddy_cap = self.contents[o].get_hidden(buddy_address);
            utspace_debug_println!("free/1: {:x}", buddy_cap);
            if buddy_cap != 0 || o == self.contents.len() || 
                        self.contents[o + 1].get_hidden(current_address) == 0 ||
                            self.contents[o].get(buddy_address) == 0 {
                utspace_debug_println!("free/2: {:x} {:x}", address, cap);
                self.contents[o].put(address, cap);
                break;
            }else{
                //the buddy block of the current block is free and the 
                //parent block is used, so delete both and move the parent 
                //to the free list
                utspace_debug_println!("free/3: {:x} {}", buddy_address, o);
                buddy_cap = self.contents[o].take(buddy_address);
                if let Err(err) = alloc.cspace().free_and_delete_slot_raw(cap, alloc) {
                    warn!("RAMZone::free: freeing requested block with cptr {:x}, address {:x}, and order {} failed with {:?}", cap, freed_address, o, err);
                    return Err(UTSpaceError::CapabilityAllocationFailure);
                }
                if let Err(err) = alloc.cspace().free_and_delete_slot_raw(buddy_cap, alloc) {
                    warn!("RAMZone::free: freeing buddy block with cptr {:x}, address {:x}, and order {} failed with {:?}", cap, freed_address, o, err);
                    return Err(UTSpaceError::CapabilityAllocationFailure) 
                }
                utspace_debug_println!("free/4: {:x} {}", current_address, o + 1);
                self.contents[o + 1].show(current_address);
                utspace_debug_println!("free/5: {:x} {:x}", address, cap);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for RAMZone {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = writeln!(f, "RAMZone({:x}, {:x}):", self.start, self.end);
        for order in 0..self.contents.len() {
            let _ = writeln!(f, " order: {} free: {} used: {}", order, self.contents[order].visible_len(), self.contents[order].hidden_len());
        }
        Ok(())
    }
}

///A node of the device sub-allocator
#[derive(Debug)]
struct DeviceZoneNode {
    bucket: UtBucket,
    address_link: rbtree::Link,
}

impl DeviceZoneNode {}

intrusive_adapter!(AddressOrder = UnsafeRef<DeviceZoneNode>: DeviceZoneNode { address_link: rbtree::Link });

impl<'a> KeyAdapter<'a> for AddressOrder {
    type Key = usize;
    fn get_key(&self, container: &'a DeviceZoneNode) -> usize {
        container.bucket.get_next_paddr()
    }
}

///Sub-allocator for device memory
struct DeviceZone {
    nodes_by_address: RefCell<RBTree<AddressOrder>>,
}

impl DeviceZone {
    ///Creates a new device sub-allocator
    fn new() -> DeviceZone {
        DeviceZone {
            nodes_by_address: RefCell::new(Default::default()),
        }
    }
    ///Adds a bucket to this sub-allocator
    pub fn add_bucket<A: AllocatorBundle>(&self, _alloc: &A, bucket: UtBucket) -> Result<(), UTSpaceError>{
        let mut addr = self.nodes_by_address.borrow_mut();

        utspace_debug_println!(
            "DeviceZone::add_bucket: paddr {:x} - {:x}     {:?}",
            bucket.get_start_paddr(),
            bucket.get_start_paddr() + bucket.get_total_bytes(),
            bucket
        );

        let new_entry = UnsafeRef::from_box(Box::new(DeviceZoneNode {
            bucket,
            address_link: Default::default(),
        }));

        addr.insert(new_entry);
        Ok(())
    }
    ///Allocates an object from device memory given a wrapper type (must be
    ///either a user page or an untyped)
    fn allocate<T: sel4::Allocatable, A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        dest_info: CNodeInfo,
        size_bits: usize,
        paddr: usize,
    ) -> Result<(), (usize, UTSpaceError)> {
        self.allocate_raw(alloc, dest, dest_info, size_bits, T::object_type(), paddr)
    }
    ///Allocates an object from device memory given a raw type code (must be
    ///either a user page or an untyped)
    fn allocate_raw<A: AllocatorBundle>(
        &self,
        alloc: &A,
        dest: Window,
        dest_info: CNodeInfo,
        size_bits: usize,
        objtype: usize,
        paddr: usize,
    ) -> Result<(), (usize, UTSpaceError)> {
        if paddr % (1 << sel4_sys::seL4_MinUntypedBits) != 0 {
            utspace_debug_println!(
                "DeviceZone::allocate: {:x} is not aligned to the minimum allocation size",
                paddr
            );

            return Err((0, UTSpaceError::InvalidArgument { which: 1 }));
        }

        let mut tree = self.nodes_by_address.borrow_mut();
        let mut cursor = tree.upper_bound_mut(Bound::Included(&paddr));

        if cursor.is_null() {
            warn!(
                "DeviceZone::allocate: could not find free node at {:x}",
                paddr
            );
            let err = UTSpaceError::syscall_from_details( 
                ErrorDetails::NotEnoughMemory { bytes_available: 0 }
            );
            return Err((0, err));
        }

        let node = cursor.get().unwrap();

        if paddr < node.bucket.get_next_paddr()
            || paddr >= node.bucket.get_start_paddr() + node.bucket.get_total_bytes()
        {
            warn!(
                "DeviceZone::allocate: could not find free node at {:x}",
                paddr
            );
            let err = UTSpaceError::syscall_from_details( 
                    ErrorDetails::NotEnoughMemory { bytes_available: 0 }
            );
            return Err((0, err));
        }

        if !node.bucket.is_device(){
            warn!(
                "DeviceZone::allocate: {:x} is not device memory",
                paddr
            );

            return Err((0, UTSpaceError::InternalError));
        }

        if !node.bucket.has_space_at_paddr_raw(paddr, dest, objtype, size_bits) {
            warn!(
                "DeviceZone::allocate: {:x} is already allocated or not enough space in \
                 untyped",
                paddr
            );

            return Err((0, UTSpaceError::InvalidArgument { which: 1 }));
        }
        // recursively split bucket until we get to paddr
        loop {
            let new_bucket;
            {
                let bucket = &(cursor.get().unwrap().bucket);
                if bucket.get_next_paddr() == paddr {
                    break;
                }
                new_bucket = bucket.split(alloc, paddr).unwrap();
            }
            // Insert before our node to keep the tree ordered by next paddr.
            // Since we are allocating new untypeds from ourself, our next paddr
            // will be after anything we create.

            cursor.insert_before(UnsafeRef::from_box(Box::new(DeviceZoneNode {
                bucket: new_bucket,
                address_link: Default::default(),
            })));
        }
        {
            let bucket = &(cursor.get().unwrap().bucket);

            utspace_debug_println!("DeviceZone::allocate: {:?}", bucket);
 
            let ret =
                bucket
                .allocate_raw(alloc, dest, dest_info, size_bits, objtype, UtZone::Device(paddr));
            ret
        }
    }
    ///Deallocates a device memory object.
    ///
    ///Currently unimplemented and just returns an error.
    fn free<A: AllocatorBundle>(
        &self,
        _alloc: &A,
        _freed_address: usize,
        _order: usize,

    ) -> Result<(), UTSpaceError> {
        Err(UTSpaceError::InternalError)
    }
}

impl fmt::Debug for DeviceZone {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = writeln!(f, "DeviceZone utspace tree:");
        for node in self.nodes_by_address.borrow().iter() {
            let _ = write!(f, "{} ", if node.bucket.is_device() { "D" } else { "r" });
            if node.bucket.get_next_paddr()
                != node.bucket.get_start_paddr() + node.bucket.get_total_bytes()
            {
                let _ = write!(
                    f,
                    "Free {:x}-{:x} ",
                    node.bucket.get_next_paddr(),
                    node.bucket.get_start_paddr() + node.bucket.get_total_bytes(),
                );
            }
            if node.bucket.get_next_paddr() > node.bucket.get_start_paddr() {
                let _ = write!(
                    f,
                    "USED {:x}-{:x}",
                    node.bucket.get_start_paddr(),
                    node.bucket.get_next_paddr(),
                );
            }
            let _ = write!(f, "\n");
        }
        Ok(())
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    utspace_debug_println!("utspace::split::add_custom_slabs: adding free node slab");
    sparse_array::add_custom_slabs_alloc::<usize, A>(alloc)?;
    utspace_debug_println!("utspace::split::add_custom_slabs_alloc: adding used CPtr node slab");
    alloc.add_custom_slab(size_of::<UsedCPtrNode>(), 119, 32, 32, 2)?;
    utspace_debug_println!("utspace::split::add_custom_slabs_alloc: adding used depth node slab");
    alloc.add_custom_slab(size_of::<UsedDepthNode>(), 768, 32, 32, 2)?;
    utspace_debug_println!("utspace::split::add_custom_slabs_alloc: adding used root node slab");
    alloc.add_custom_slab(size_of::<UsedRootNode>(), 768, 32, 32, 2)?;
    utspace_debug_println!("utspace::split::add_custom_slabs_alloc: adding device zone node slab");
    alloc.add_custom_slab(size_of::<DeviceZoneNode>(), 256, 8, 8, 2)?;
    Ok(())
}
