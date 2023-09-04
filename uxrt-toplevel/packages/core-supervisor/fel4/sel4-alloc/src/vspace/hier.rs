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

//TODO: allow storing a system-specific object in reservation nodes

//! Hierarchical virtual address space handling.
//!
//! This module assumes a particular flavor of paging structures. The paging structures are
//! hierarchical, with each level being able to store pages that are some power-of-two size. All
//! page sizes on level N are strictly greater than all page sizes on level N-1. An entry at level
//! N can store either a page of any size from level N, or a table whose entries are at level N-1.
//!
//! For example, x86 with PAE could be described as:
//!
//!  - Level 2: 4KiB, "PTE"
//!  - Level 1: 2MiB, "PDE"
//!  - Level 0: (no pages, only tables) "PDPT"
//!
//! ARMv7 could be described as:
//!
//!  - Level 2: 4KiB, 64KiB (pages)
//!  - Level 1: 1MiB, 16MiB (sections)
//!  - Level 0: (no pages, only tables)

use sel4_sys::seL4_ObjectTypeCount;
use sel4::raw::seL4_Error;
use sel4::{PAGE_SIZE, seL4_CPtr, Mappable, SlotRef, ToCap};
use core::{fmt, mem};
use core::cell::{Cell, RefCell};

use intrusive_collections::{
    rbtree, RBTree, Bound, UnsafeRef, KeyAdapter
};
use alloc::boxed::Box;
use alloc::alloc::{alloc_zeroed, Layout};

use crate::{
    AllocatorBundle,
    cspace::CSpaceManager,
    seL4_ARCH_VMAttributes,
    utspace::UtZone,
    vspace::{
        PageDeallocType,
        VSpaceError,
        VSpaceManager, 
        VSpaceReservation,
        get_page_type,
    },
    vspace_debug_println,
};

use custom_slab_allocator::CustomSlabAllocator;

// HIER_LEVELS is (objtype,         // seL4 object type constant for our page table object
//                 level_sizes,     // log2 size of page frames that can be directly mapped here
//                 bits_translated, // number of bits to use as an index into our table
//                 size_bits)       // log2 size of our page table object
//                Index 0 is the root page table object
// MAP_PAGE: sel4_sys function that maps a page frame for this architecture
// UNMAP_PAGE: sel4_sys function that unmaps a page frame for this architecture
// MAP_FNS is (table_map_fn,        // sel4_sys function to map next lower level page table
//             table_unmap_fn)      // sel4_sys function to unmap next lower level page table
//            Index 0 is the root page table object
//            None if not applicable
// VIRT_ADDR_BITS: Number of bits in a virtual address translated by these tables
// VADDR_LIMIT: The start of kernel-protected virtual address space

pub type MapFn = unsafe fn(seL4_CPtr, seL4_CPtr, usize, sel4::CapRights, seL4_ARCH_VMAttributes)
                           -> seL4_Error;
//pub type RemapFn = unsafe fn(seL4_CPtr, seL4_CPtr, sel4::CapRights, seL4_ARCH_VMAttributes) -> seL4_Error;
pub type UnmapFn = unsafe fn(seL4_CPtr) -> seL4_Error;

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
mod arch {
    use super::{MapFn, RemapFn, UnmapFn};
    pub type TblMapFn = unsafe fn(seL4_CPtr, seL4_CPtr, usize, seL4_ARM_VMAttributes) -> isize;
    pub const HIER_LEVELS: [(isize, [u8; 2], u8, u8); 2] =
        [
            (seL4_ARM_PageDirectoryObject as isize, [20, 24], 8, 14),
            (seL4_ARM_PageTableObject as isize, [12, 18], 12, 10),
        ];
    pub const MAP_PAGE: MapFn = seL4_ARM_Page_Map;
    pub const REMAP_PAGE: RemapFn = seL4_ARM_Page_Remap as RemapFn;
    pub const UNMAP_PAGE: UnmapFn = seL4_ARM_Page_Unmap;
    pub const MAP_FNS: [Option<(TblMapFn, UnmapFn)>; 2] =
        [
            Some((seL4_ARM_PageTable_Map as TblMapFn, seL4_ARM_PageTable_Unmap as UnmapFn)),
            None,
        ];
    pub const VADDR_BITS: u8 = 32;
    pub const VADDR_LIMIT: usize = 0xe0000000; // TODO: This depends on specific platform
    pub const BITS: u8 = 32;
}

#[cfg(all(target_arch = "x86", target_pointer_width = "32"))]
mod arch {
    use super::{MapFn, RemapFn, UnmapFn};

    // Note: no PAE
    pub type TblMapFn = unsafe fn(seL4_CPtr, seL4_CPtr, usize, seL4_X86_VMAttributes) -> isize;

    pub const HIER_LEVELS: [(isize, [u8; 1], u8, u8); 2] =
        [
            (seL4_X86_PageDirectoryObject as isize, [22], 10, 12),
            (seL4_X86_PageTableObject as isize, [12], 10, 12),
        ];
    pub const MAP_PAGE: MapFn = seL4_X86_Page_Map as MapFn;
    pub const REMAP_PAGE: RemapFn = seL4_X86_Page_Remap as RemapFn;
    pub const UNMAP_PAGE: UnmapFn = seL4_X86_Page_Unmap;
    pub const MAP_FNS: [Option<(TblMapFn, UnmapFn)>; 2] =
        [
            Some((seL4_X86_PageTable_Map as TblMapFn, seL4_X86_PageTable_Unmap as UnmapFn)),
            None,
        ];
    pub const VADDR_BITS: u8 = 32;
    pub const VADDR_LIMIT: usize = 0xe0000000;
    pub const BITS: u8 = 32;
}

#[cfg(target_arch = "x86_64")]

pub mod arch {
    use sel4::{
        PAGE_BITS,
        seL4_CPtr,
        seL4_X86_VMAttributes,
        seL4_X86_4K,
        seL4_X86_LargePageObject,
        seL4_X64_HugePageObject,
        seL4_X64_PML4Object,
        seL4_X86_PDPTObject,
        seL4_X86_PageDirectoryObject,
        seL4_X86_PageTableObject,
    };
    use sel4::raw::seL4_Error;
    use sel4_sys::{seL4_LargePageBits, seL4_HugePageBits};
    use super::{MapFn, UnmapFn};

    pub type TblMapFn = unsafe fn(seL4_CPtr, seL4_CPtr, usize, seL4_X86_VMAttributes) -> seL4_Error;
    pub const PAGE_SIZES: [(usize, usize); 3] = 
        [
            (seL4_X86_4K as usize, PAGE_BITS as usize),
            (seL4_X86_LargePageObject as usize, seL4_LargePageBits as usize),
            (seL4_X64_HugePageObject as usize, seL4_HugePageBits as usize),
        ];
    pub const HIER_LEVELS: [(isize, [u8; 1], u8, u8, usize, usize); 4] =
        [
            (seL4_X64_PML4Object as isize, [0], 9, 12, 16, 4),
            (seL4_X86_PDPTObject as isize, [30], 9, 12, 16, 4),
            (seL4_X86_PageDirectoryObject as isize, [21], 9, 12, 16, 4),
            (seL4_X86_PageTableObject as isize, [12], 9, 12, 16, 4),
        ];
    pub const MAP_PAGE: MapFn = sel4::arch_raw::page_map;
    pub const UNMAP_PAGE: UnmapFn = sel4::arch_raw::page_unmap;
    pub const MAP_FNS: [Option<(TblMapFn, UnmapFn)>; 4] =
        [
            Some((sel4::arch_raw::pdpt_map, sel4::arch_raw::pdpt_unmap)),
            Some((sel4::arch_raw::page_directory_map, sel4::arch_raw::page_directory_unmap)),
            Some((sel4::arch_raw::page_table_map, sel4::arch_raw::page_table_unmap)),
            None,
        ];
    pub const VADDR_BITS: u8 = 48;
    #[cfg(not(KernelEnableSMPSupport))]
    pub const VADDR_LIMIT: usize = 0xff80_00000000;
    #[cfg(KernelEnableSMPSupport)]
    // PPTR_BASE - TLBBITMAP_ROOT_ENTRIES * BIT(PML4_INDEX_OFFSET)
    pub const VADDR_LIMIT: usize = 0xff80_00000000 -
        (((CONFIG_MAX_NUM_NODES - 1) / ((1 << 6) - 1)) + 1) * (1 << 39);
    pub const BITS: u8 = 64;
    pub const MAX_ALLOC_PAGES: usize = 8;
}

use self::arch::*;

/// This is the header which tracks information about a level in the paging hierarchy.
pub struct LevelNode {
    /// Cap for this table, passed to MAP_FNS[self.depth].1
    table_cap: seL4_CPtr,
    /// Index into HIER_LEVELS and MAP_FNS.
    depth: u8,
    /// Number of entries in this table.
    log2_size: u8,
}

/// This tracks individual entries within a level
#[derive(Clone)]
enum LevelEntry {
    Table(*mut LevelNode),
    Page {
        cap: seL4_CPtr,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
    },
    Free,
}

fn get_n_bits_at(word: usize, n: u8, start: u8) -> usize {
    debug_assert!(n <= VADDR_BITS);
    debug_assert!(start < VADDR_BITS);
    debug_assert!(VADDR_BITS <= 64); // y'know, just in case.
    debug_assert!(VADDR_BITS <= BITS);
    (word >> start as usize) & (!0 >> ((BITS - n) as usize % BITS as usize))
}

/// Create a new, empty level for use at `depth` in the paging hierarchy.
fn new_level<A: AllocatorBundle>(alloc: &A, depth: u8, table_cap: Option<seL4_CPtr>) -> Result<&LevelNode, VSpaceError> {
    let cptr;

    vspace_debug_println!("new_level: {} {:?}", depth, table_cap);
    if let Some(cap) = table_cap {
        cptr = Ok(cap);
    }else{
        cptr = alloc.cspace().allocate_slot_with_object_raw(
                    HIER_LEVELS[depth as usize].3 as usize,
                    HIER_LEVELS[depth as usize].0 as usize,
                    UtZone::RamAny,
                    alloc,
        );
        if let Err(err) = cptr {
            warn!("new_level: allocating new level failed with {:?}, depth: {}, cap: {:?}", err, depth, table_cap);
            return Err(VSpaceError::CSpaceError { err } );
        }
    }

    let ptr = unsafe {
        alloc_zeroed(
            Layout::from_size_align(
                LevelNode::total_size(HIER_LEVELS[depth as usize].2),
                mem::align_of::<LevelNode>(),
            ).expect("new_level/Layout::from_size_align"),
        ) as *mut LevelNode
    };

    if ptr.is_null() {
        panic!("new_level/alloc_zeroed: out of memory");
    }

    let obj = unsafe { &mut *(ptr as *mut LevelNode) };
    obj.table_cap = cptr.unwrap();
    obj.depth = depth;
    obj.log2_size = HIER_LEVELS[depth as usize].2;

    let tb = obj.get_table_pointer();

    for i in 0..1 << obj.log2_size {
        unsafe { *tb.offset(i) = LevelEntry::Free }
    }

    unsafe { Ok(&*(obj as *const LevelNode)) }
}

impl LevelNode {
    /// Calculate the number of bytes used to store this level, including the header, alignment,
    /// and table after it.
    fn total_size(log2_size: u8) -> usize {
        let mut sz = 0;
        sz += mem::size_of::<LevelNode>();
        sz += mem::align_of::<LevelEntry>() - sz % mem::align_of::<LevelEntry>();
        sz += (1 << log2_size as usize) * mem::size_of::<LevelEntry>();
        sz
    }

    /// Get a pointer to the first entry in the table.
    fn get_table_pointer(&self) -> *mut LevelEntry {
        let mut ptr = self as *const _ as usize;
        ptr += mem::size_of::<LevelNode>();
        ptr += mem::align_of::<LevelEntry>() - ptr % mem::align_of::<LevelEntry>();
        debug_assert_eq!(ptr % mem::align_of::<LevelEntry>(), 0);
        ptr as *mut LevelEntry
    }

    /// Given a virtual address and the number of bits already translated, return the index into
    /// this level of the paging hierarchy which should be used to continue lookup.
    fn get_level_index(&self, vaddr: usize, bits_translated: usize) -> usize {
        let n = HIER_LEVELS[self.depth as usize].2;
        get_n_bits_at(vaddr, n, VADDR_BITS - bits_translated as u8 - n)
    }

    /// Walk the paging hierarchy, calling back for each level which influences the lookup of
    /// `vaddr`.
    ///
    /// If the callback returns `None`, walking continues. Otherwise, it returns the return value
    /// of the callback. If the entire table is traversed without the callback returning `Some`,
    /// `None` is returned.
    fn walk_table<T, F: FnMut(u8, *mut LevelEntry) -> Option<T>>(
        &self,
        vaddr: usize,
        mut f: F,
    ) -> Option<T> {
        let mut cur: &'static _ = unsafe { &*(self as *const LevelNode) };
        let mut bits_translated = 0;
        let mut depth = 0;

        loop {
            let tp = cur.get_table_pointer();
            let n = HIER_LEVELS[depth as usize].2;
            let tbidx = get_n_bits_at(vaddr, n, VADDR_BITS - bits_translated as u8 - n);
            let ptr = unsafe { tp.offset(tbidx as isize) };

            if let c @ Some(_) = f(depth, ptr) {
                return c;
            }

            match unsafe { (*ptr).clone() } {
                LevelEntry::Table(p) => {
                    cur = unsafe { &*(p as *const LevelNode) };
                },
                _ => return None,
            }

            bits_translated += n;
            depth += 1;
        }
    }

    /// Walk the paging hierarchy, calling back for each `LevelEntry` in a given range of
    /// addresses.
    ///
    /// If the callback returns `None`, walking continues. Otherwise, it returns the return value
    /// of the callback. If the entire range is traversed without the callback returning `Some`,
    /// `None` is returned.
    fn walk_table_range<T, F: FnMut(u8, usize, *const LevelNode, *mut LevelEntry) -> Option<T>>(
        &self,
        start: usize,
        end: usize,
        mut f: F,
    ) -> Option<T> {
        // vaddr is sign-extended to the full 64-bit range for addresses >= 0x800000000000
        // mask off the high bits to ignore that.
        self.walk_table_range_inner(
            start & (!0 >> (BITS as usize - VADDR_BITS as usize)),
            (end & (!0 >> (BITS as usize - VADDR_BITS as usize))) - 1,
            0,
            0,
            &mut f,
        )
    }

    ///Internal implementation of walk_table_range
    fn walk_table_range_inner<T,
                              F: FnMut(u8, usize, *const LevelNode, *mut LevelEntry) -> Option<T>>
        (&self,
         target_start: usize,
         target_end: usize,
         table_start: usize,
         bits_translated: usize,
         f: &mut F) -> Option<T>{
        let cur: &'static _ = unsafe { &*(self as *const LevelNode) };
        // table_end = table start + num table entries * virt memory used by 1 entry in table - 1
        //             (the -1 is to prevent overflow)
        let table_end = (table_start +
                             (1 << HIER_LEVELS[cur.depth as usize].2) *
                                 (1 <<
                                      (VADDR_BITS - bits_translated as u8 -
                                           (HIER_LEVELS[cur.depth as usize].2)))) -
            1;
        // If the start or end address isn't inside the virtual address space covered by our node
        // then we're somewhere in the middle of the target range and we need to traverse every
        // entry.
        let start_lvidx = if target_start >= table_start && target_start <= table_end {
            self.get_level_index(target_start, bits_translated)
        } else {
            0
        };
        let end_lvidx = if target_end >= table_start && target_end <= table_end {
            self.get_level_index(target_end, bits_translated) + 1
        } else {
            1 << HIER_LEVELS[cur.depth as usize].2
        };
        let tp = cur.get_table_pointer();
        for i in start_lvidx..end_lvidx {
            let ptr = unsafe { tp.offset(i as isize) };
            if let c @ Some(_) = f(
                cur.depth,
                table_start +
                    i * // table_start + i * vm_used_by_table_entry
                        (1 << (VADDR_BITS - bits_translated as u8 -
                        (HIER_LEVELS[cur.depth as usize].2))),
                cur,
                ptr,
            )
            {
                return c;
            }
            if let LevelEntry::Table(p) = unsafe { (*ptr).clone() } {
                let p: &'static _ = unsafe { &*(p as *const LevelNode) };
                if let c @ Some(_) = p.walk_table_range_inner(
                    target_start,
                    target_end,
                    table_start +
                        i *
                            (1 <<
                                 (VADDR_BITS - bits_translated as u8 -
                                      (HIER_LEVELS[cur.depth as usize].2))),
                    bits_translated +
                        (HIER_LEVELS[cur.depth as usize].2 as usize),
                    f,
                )
                {
                    return c;
                }
            }
        }
        None
    }

    ///Gets the LevelEntry for an address
    fn get_level_entry(&self, vaddr: usize) -> Option<&LevelEntry> {
        self.walk_table(vaddr, |_, entry| match unsafe { (*entry).clone() } {
            LevelEntry::Page {
                ..
            } => Some(unsafe { &*(entry as *const LevelEntry) }),
            _ => None,
        })
    }
}

///Internal representation of an address range reservation
pub struct ReservationNode {
    num_bytes: Cell<usize>,
    start_addr: Cell<usize>,
    address_link: rbtree::Link,
    size_link: rbtree::Link,
}

impl ReservationNode {
    ///Returns a new node for splitting this reservation into two (but does not
    ///modify this node
    fn split(&self, num_bytes_to_take: usize) -> UnsafeRef<ReservationNode> {
        UnsafeRef::from_box(Box::new(ReservationNode {
            num_bytes: Cell::new(self.num_bytes.get() - num_bytes_to_take),
            start_addr: Cell::new(self.start_addr.get() + num_bytes_to_take),
            address_link: Default::default(),
            size_link: Default::default(),
        }))
    }
    ///Returns the end address of this reservation
    fn end(&self) -> usize {
        self.start_addr.get() + self.num_bytes.get()
    }
}

intrusive_adapter!(SizeOrder = UnsafeRef<ReservationNode>:
                       ReservationNode { size_link: rbtree::Link });
intrusive_adapter!(AddressOrder = UnsafeRef<ReservationNode>:
                       ReservationNode { address_link: rbtree::Link });

impl<'a> KeyAdapter<'a> for SizeOrder {
    type Key = usize;
    fn get_key(&self, container: &'a ReservationNode) -> usize {
        container.num_bytes.get()
    }
}

impl<'a> KeyAdapter<'a> for AddressOrder {
    type Key = usize;
    fn get_key(&self, container: &'a ReservationNode) -> usize {
        container.start_addr.get()
    }
}

pub struct Hier {
    free_blocks: RefCell<RBTree<SizeOrder>>,
    all_blocks: RefCell<RBTree<AddressOrder>>,
    top_level: *mut LevelNode,
}

unsafe impl Send for Hier {}
unsafe impl Sync for Hier {}

impl fmt::Debug for Hier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut saved_from_address = 0;
        let mut saved_to_address = 0;
        let mut saved_rights = sel4::CapRights::none();
        let mut saved_attrs: seL4_ARCH_VMAttributes = Default::default();
        let mut saved_depth = 0;
        let mut saved_pages = 0;
        let _ = write!(f, "Reservations:\n");
        let all = self.all_blocks.borrow();
        for block in all.iter() {
            let isfree = block.size_link.is_linked();
            let _ = write!(f,
                     "  {} from {:12x} to {:12x}\n",
                     if isfree { "    free" } else { "RESERVED"},
                     block.start_addr.get(),
                     block.start_addr.get() + block.num_bytes.get());
        }
        let _ = write!(f, "Mappings:\n");
        let _ = write!(f, "VSpace Root cptr={}\n", unsafe { &(*self.top_level).table_cap });
        unsafe { &*self.top_level }.walk_table_range(
            0,
            usize::max_value(),
            |depth,
             level_entry_vaddr,
             _,
             level_entry| {
                match unsafe { (*level_entry).clone() } {
                    LevelEntry::Free => {
                        if saved_pages > 0 {
                            fmt_page_info(
                                f,
                                saved_pages,
                                saved_from_address,
                                saved_to_address,
                                saved_rights,
                                saved_attrs,
                                saved_depth,
                            );
                            saved_pages = 0;
                        }
                    },
                    LevelEntry::Table(_) => {
                        if saved_pages > 0 {
                            fmt_page_info(
                                f,
                                saved_pages,
                                saved_from_address,
                                saved_to_address,
                                saved_rights,
                                saved_attrs,
                                saved_depth,
                            );
                            saved_pages = 0;
                        }
                        for _ in 0..depth {
                            let _ = f.write_str("      ");
                        }
                        let bits: u8 = (0..depth + 1).map(|x| HIER_LEVELS[x as usize].2).sum();
                        let _ = write!(f,
                           "PageTable --------{:->12x}--to--{:->12x}--------------------\n",
                           level_entry_vaddr,
                           level_entry_vaddr + (1 << (VADDR_BITS - bits)));
                    },
                    LevelEntry::Page {
                        rights,
                        attrs,
                        ..
                    } => {
                        if saved_pages > 0 &&
                            (depth != saved_depth || rights != saved_rights ||
                                 attrs != saved_attrs)
                        {
                            fmt_page_info(
                                f,
                                saved_pages,
                                saved_from_address,
                                saved_to_address,
                                saved_rights,
                                saved_attrs,
                                saved_depth,
                            );
                            saved_pages = 0;
                        }
                        if saved_pages == 0 {
                            saved_from_address = level_entry_vaddr;
                            saved_rights = rights;
                            saved_attrs = attrs;
                            saved_depth = depth;
                        }
                        saved_pages += 1;
                        let bits: u8 = (0..depth + 1).map(|x| HIER_LEVELS[x as usize].2).sum();
                        saved_to_address = level_entry_vaddr + (1 << (VADDR_BITS - bits));
                    },
                }

                None::<()>
            },
        );
        if saved_pages > 0 {
            fmt_page_info(
                f,
                saved_pages,
                saved_from_address,
                saved_to_address,
                saved_rights,
                saved_attrs,
                saved_depth,
            );
        }
        Ok(())
    }
}

///Writes the address range to the formatter
fn fmt_page_info(
    f: &mut fmt::Formatter,
    pages: usize,
    from: usize,
    to: usize,
    rights: sel4::CapRights,
    attrs: seL4_ARCH_VMAttributes,
    level: u8,
) {
    for _ in 0..level {
        let _ = f.write_str("      ");
    }
    let _ = write!(f,
                   "{:4} Pages  {:12x}  to  {:12x}  rights={}{}{} attrs={}\n",
                   pages,
                   from,
                   to,
                   if rights.get_cap_allow_grant() == 1 { "g" } else { "-" },
                   if rights.get_cap_allow_read() == 1 { "r" } else { "-" },
                   if rights.get_cap_allow_write() == 1 { "w" } else { "-" },
                   attrs as usize);
}

impl Hier {
    ///Returns a new Hier instance from a CPtr to a VSpace 
    pub fn new<A: AllocatorBundle>(alloc: &A, vspace: Option<seL4_CPtr>) -> Result<Hier, ()> {
        if let Ok(nl) = new_level(alloc, 0, vspace){
            let hier = Hier::from_toplevel(nl as *const LevelNode as *mut LevelNode);
            hier.init_block_lists();
            Ok(hier)
        }else{
            Err(())
        }
    }

    ///Returns a new Hier instance from an existing top-level node
    pub fn from_toplevel(top_level: *mut LevelNode) -> Hier {
        Hier {
            free_blocks: RefCell::new(Default::default()),
            all_blocks: RefCell::new(Default::default()),
            top_level,
        }
    }

    ///Initializes the block lists
    fn init_block_lists(&self) {
        let mut free = self.free_blocks.borrow_mut();
        let mut all = self.all_blocks.borrow_mut();

        let new_entry = UnsafeRef::from_box(Box::new(ReservationNode {
            num_bytes: Cell::new(VADDR_LIMIT),
            start_addr: Cell::new(0),
            address_link: Default::default(),
            size_link: Default::default(),
        }));

        all.insert(new_entry.clone());
        free.insert(new_entry);
    }

    /// "Mock" mapping pages into the VSpace, updating internal bookkeeping but not modifying the
    /// paging structures at all.
    ///
    /// This is useful during bootstrap or to otherwise record actions on the vspace that did not
    /// occur via this manager.
    pub fn mock_map_at_vaddr_raw<A: AllocatorBundle>(
        &self,
        caps: &[seL4_CPtr],
        vaddr: usize,
        size_bits: usize,
        res: &Reservation,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        let end_vaddr = vaddr + (1 << size_bits) * caps.len();
        if vaddr < res.res().start_addr.get() ||
            end_vaddr > res.res().end()
        {
            warn!("mock_map_at_vaddr_raw: invalid range: {:x} {:x}, reservation: {:x} {:x}", vaddr, end_vaddr, res.res().start_addr.get(), res.res().end());
            return Err(VSpaceError::InvalidArgument { which: 1 });
        }
        self.map_pages_at_vaddr_base(vaddr, rights, size_bits as u8, attrs, alloc, true, caps.len(), &mut |index| {
                caps[index]
            })
    }

    /// "Mock" unmapping pages into the VSpace, updating internal bookkeeping but not modifying the
    /// paging structures at all.
    ///
    /// This is useful during bootstrap or to otherwise record actions on the vspace that did not
    /// occur via this manager.
    pub fn mock_unmap<A: AllocatorBundle>(&self, vaddr: usize, bytes: usize, dealloc_type: PageDeallocType, alloc: &A) -> Result<usize, (usize, VSpaceError)>{
        if alloc.lock_dealloc().is_err(){
            warn!("Hier::mock_unmap: could not acquire recursion lock, vaddr: {:x}, bytes: {}", vaddr, bytes);
            return Err((0, VSpaceError::InternalError));
        }
        let ret = self.unmap_base(vaddr, bytes, dealloc_type, true, alloc);
        if alloc.unlock_dealloc().is_err(){
            warn!("Hier::mock_unmap: could not release recursion lock, vaddr: {:x}, bytes: {}", vaddr, bytes);
            return Err((0, VSpaceError::InternalError));
        }
        ret
    }

    ///Mocks changing protection on an address range, similar to mock_map* and mock_unmap
    pub fn mock_change_protection<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        if alloc.lock_alloc().is_err(){
            warn!("Hier::mock_change_protection: could not acquire recursion lock, vaddr: {:x}, bytes: {}", vaddr, bytes);
            return Err(VSpaceError::InternalError);
        }
        let ret = self.change_protection_base(vaddr, bytes, rights, attrs, alloc, true);
        if alloc.unlock_alloc().is_err(){
            warn!("Hier::mock_change_protection: could not release recursion lock, vaddr: {:x}, bytes: {}", vaddr, bytes);
            return Err(VSpaceError::InternalError);
        }
        ret
    }


    ///Internal implementation of map_pages_at_vaddr()
    ///
    ///Since the recursion lock imposes an upper bound on the number of pages
    ///that may be mapped at once, this method breaks them up so that the lock
    ///is released and re-acquired at a set (architecture-dependent) interval
    ///during larger mappings.
    fn map_pages_at_vaddr_base<A: AllocatorBundle, F>(
        &self,  
        vaddr: usize,
        rights: sel4::CapRights,
        size_bits: u8,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
        mock: bool,
        num_caps: usize,
        get_cap: &F,
    ) -> Result<(), VSpaceError> where F: Fn(usize) -> seL4_CPtr {
        let mut caps_remaining = num_caps;
        let mut cur_vaddr = vaddr;
        //debug_println_unconditional!("map_pages_at_vaddr_base: {:x} {:x}", vaddr, num_caps);
        while caps_remaining > 0 {
            //debug_println_unconditional!("{:x} {:x}", cur_vaddr, caps_remaining);
            let mut cur_num_caps = caps_remaining;
            if cur_num_caps > MAX_ALLOC_PAGES {
                cur_num_caps = MAX_ALLOC_PAGES;
            }
            if let Err(err) = self.map_pages_at_vaddr_inner(cur_vaddr,
                                                            rights,
                                                            size_bits,
                                                            attrs,
                                                            alloc,
                                                            mock,
                                                            cur_num_caps,
                                                            &|offset| {
                                                                get_cap(num_caps - caps_remaining + offset)
                                                            }){
                warn!("Hier::map_pages_at_vaddr_base: mapping failed for range of {} pages of order {} starting at {:x}", num_caps, size_bits, vaddr);
                return Err(err)
            }
            caps_remaining -= cur_num_caps;
            cur_vaddr += PAGE_SIZE * cur_num_caps;
        }
        Ok(())
    }

    ///Internal method called by map_pages_at_vaddr() to map a fixed number
    ///of capabilities
    fn map_pages_at_vaddr_inner<A: AllocatorBundle, F>(
        &self,  
        vaddr: usize,
        rights: sel4::CapRights,
        size_bits: u8,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
        mock: bool,
        num_caps: usize,
        get_cap: &F,
    ) -> Result<(), VSpaceError> where F: Fn(usize) -> seL4_CPtr {
        if vaddr & (!0 >> (BITS - size_bits)) != 0 {
            warn!("Hier::map_pages_at_vaddr_inner: address {:x} not aligned, size_bits: {}, mock: {}, num_caps: {}", vaddr, size_bits, mock, num_caps);
            return Err(VSpaceError::InvalidArgument { which: 0 });
        }
        if size_bits == 0 {
            warn!("Hier::map_pages_at_vaddr_inner: invalid size {}, address {:x} not aligned, mock: {}, num_caps: {}", size_bits, vaddr, mock, num_caps);
            return Err(VSpaceError::InvalidArgument { which: 2 });
        }

        let page_size_bytes = 1 << size_bits;
        let total_mapping_bytes = page_size_bytes * num_caps;
        let vaddr_end = vaddr + total_mapping_bytes;
        assert!(vaddr_end > vaddr, "Hier::map_pages_at_vaddr_base: vaddr overflow");
        let vroot = unsafe { &*self.top_level }.table_cap;
        let mut cap_index = 0;
        let mut vaddr_cur = vaddr;
        let mut ret = Ok(());

        if alloc.lock_alloc().is_err() {
            warn!("Hier::map_pages_at_vaddr_inner: failed to acquire recursion lock before mapping range of {} pages of order {} at address {:x}", num_caps, size_bits, vaddr);
            return Err(VSpaceError::InternalError);
        }
        unsafe { &*self.top_level }.walk_table_range(vaddr, vaddr_end, |depth,
                                                                        level_entry_vaddr,
                                                                        _,
                                                                        level_entry| {
            if ret.is_err() {
                return None;
            }
            match unsafe { (*level_entry).clone() } {
                LevelEntry::Free => {
                    if HIER_LEVELS[depth as usize].1.contains(&size_bits) {
                        // map at this level
                        assert!(cap_index < num_caps, "Hier::map_pages_at_vaddr_base: capability index overrun when mapping");
                        assert!(vaddr_cur < vaddr_end, "Hier::map_pages_at_vaddr_base: virtual address overrun when mapping");
                        assert_eq!(vaddr_cur & (!0 >> (BITS as usize - VADDR_BITS as usize)),
                                   level_entry_vaddr, "Hier::map_pages_at_vaddr_base: virtual address mismatch when mapping");
                        unsafe {
                            *level_entry = LevelEntry::Page {
                                cap: get_cap(cap_index),
                                rights,
                                attrs,
                            }
                        };
                        if !mock {
                            vspace_debug_println!("Mapping page at level {} at vaddr {:x}", depth, vaddr_cur);
                            let res = unsafe {
                                MAP_PAGE(get_cap(cap_index),
                                         vroot,
                                         vaddr_cur,
                                         rights,
                                         attrs)
                            };
                            if res != 0 {
                                let err = sel4::Error::copy_from_ipcbuf(res);
                                warn!("Hier::map_pages_at_vaddr_inner: mapping page at level {} with capability {:x} at address {:x} failed with {:?}, starting address {:x}, size bits: {}", depth, get_cap(cap_index), vaddr_cur, err, vaddr, size_bits);
                                ret = Err(VSpaceError::MapFailure { details: err });
                                return None;
                            }
                        }
                        cap_index += 1;
                        vaddr_cur += page_size_bytes;
                    } else {
                        // create a page table
                        assert!(MAP_FNS[depth as usize].is_some(), "Hier::map_pages_at_vaddr_base: map function for depth {} is None (this shouldn't happen!)", depth);
                        let tb = new_level(alloc, depth + 1, None);

                        if let Err(err) = tb {
                            ret = Err(err);
                            return None;
                        }

                        unsafe {
                            *level_entry = LevelEntry::Table(tb.unwrap() as *const _ as *mut LevelNode)
                        };
                        if !mock {
                            vspace_debug_println!("Mapping page table level {} at vaddr {:x} for page at \
                                vaddr {:x}", depth, level_entry_vaddr, vaddr_cur);

                            let res = unsafe {
                                MAP_FNS[depth as usize].expect("map_pages_at_vaddr_base/map_fn").0((*(tb.unwrap())).table_cap,
                                                                   vroot,
                                                                   vaddr_cur,
                                                                   Default::default())
                            };
                            if res != 0 {
                                let err = sel4::Error::copy_from_ipcbuf(res);
                                warn!("Hier::map_pages_at_vaddr_inner: mapping page table at level {} with capability {:x} at address {:x} failed with {:?}, starting address {:x}, size bits: {}", depth, get_cap(cap_index), vaddr_cur, err, vaddr, size_bits);
                                ret = Err(VSpaceError::MapFailure { details: err });
                                return None;
                            }
                        }
                    }
                },
                LevelEntry::Table(_) => {
                    assert!(!HIER_LEVELS[depth as usize].1.contains(&size_bits),
                        // we're mapping at this level, entry should be free
                        "Hier::map_pages_at_vaddr_base: Unexepected page table found at vaddr {:x} at level {}
                            while attempting to map page index {} of size {} at vaddr {:x}
                            while mapping {} pages at vaddrs from {:x} to {:x}",
                        level_entry_vaddr,
                        depth,
                        cap_index,
                        page_size_bytes,
                        vaddr_cur,
                        num_caps,
                        vaddr,
                        vaddr_end
                    );
                },
                LevelEntry::Page { .. } => {
                    panic!("Unexepected page found at vaddr {:x} at level {}
                               while attempting to map page index {} of size {} at vaddr {:x}
                               while mapping {} pages at vaddrs from {:x} to {:x}",
                           level_entry_vaddr,
                           depth,
                           cap_index,
                           page_size_bytes,
                           vaddr_cur,
                           num_caps,
                           vaddr,
                           vaddr_end);
                },
            }
            None::<()>
        });

        if ret.is_ok(){
            assert_eq!(cap_index, num_caps, "Hier::map_pages_at_vaddr_base: no error return set, but mapping did not reach the end of the capability list");
            assert_eq!(vaddr_cur, vaddr_end, "Hier::map_pages_at_vaddr_base: no error return set, but mapping did not reach the end of the address range");
        }
        if alloc.unlock_alloc().is_err() {
            warn!("Hier::map_pages_at_vaddr_inner: failed to release recursion lock after mapping range of {} pages of order {} at address {:x}", num_caps, size_bits, vaddr);
            return Err(VSpaceError::InternalError);
        }
        ret
    }

    ///Internal implementation of unmap()
    fn unmap_base<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        mut dealloc_type: PageDeallocType,
        mock: bool,
        alloc: &A,
    ) -> Result<usize, (usize, VSpaceError)>{
        let mut remaining = bytes;
        let end_vaddr = vaddr + bytes;
        let mut cur_vaddr = vaddr;
        let mut unmapped = 0; //number of pages unmapped (in case of error)
        while cur_vaddr < end_vaddr {
            let mut cur_size = remaining;
            if cur_size > MAX_ALLOC_PAGES * PAGE_SIZE {
                cur_size = MAX_ALLOC_PAGES * PAGE_SIZE;
            }
            if let Err((cur_unmapped, err)) = self.unmap_inner(cur_vaddr,
                                               cur_size,
                                               &mut dealloc_type,
                                               mock,
                                               alloc){
                warn!("Hier::unmap_base: unmapping failed for range of {} bytes starting at {:x}", bytes, vaddr);
                return Err((cur_unmapped + unmapped, err));
            }
            unmapped += cur_size / PAGE_SIZE;
            cur_vaddr += cur_size;
            remaining -= cur_size;
        }
        Ok(unmapped)
    }

    ///Internal implementation of unmap()
    fn unmap_inner<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        dealloc_type: &mut PageDeallocType,
        mock: bool,
        alloc: &A,
    ) -> Result<(), (usize, VSpaceError)>{
        //TODO: free any page tables that are empty
        let mut ret = Ok(());
        let mut pages = 0;
        let bytes = bytes + bytes % PAGE_SIZE;

        if alloc.lock_alloc().is_err(){
            warn!("Hier::unmap_inner: could not acquire recursion lock; vaddr: {:x}, bytes: {:x}, mock: {}", vaddr, bytes, mock);
            return Err((pages, VSpaceError::InternalError));
        }

        unsafe { &*self.top_level }.walk_table_range(
            vaddr,
            vaddr + bytes,
            |_, _, _, level_entry| {
                if let LevelEntry::Page {
                    cap, ..
                } = unsafe { (*level_entry).clone() }
                {
                    if !mock {
                        let res = unsafe { UNMAP_PAGE(cap) };
                        if res != 0 {
                            let err = sel4::Error::copy_from_ipcbuf(res);
                            warn!("Hier::unmap_inner: unmapping page with capability {:x} failed with {:?}, starting address {:x}", cap, err, vaddr);
                            ret = Err((pages, VSpaceError::MapFailure { details: err }));
                            return None;
                        }
                    }

                    match dealloc_type {
                        PageDeallocType::NoDeallocation => {},
                        PageDeallocType::FreeSlotOnly => {
                            if let Err(err) = alloc.cspace().free_and_delete_slot_raw(cap, alloc){
                                ret = Err((pages, VSpaceError::CSpaceError { err }));
                                return None;
                            }
                        },
                        PageDeallocType::FreeObject(s) => {
                            let size_bits = *s as usize; 
                            let objtype = get_page_type(size_bits);
                            if objtype == seL4_ObjectTypeCount as usize{
                                ret = Err((pages, VSpaceError::InvalidArgument { which: 2 }));
                                return None;
                            }
                            if let Err(err) = alloc.cspace().free_and_delete_slot_with_object_raw(cap, size_bits, objtype, alloc){
                                ret = Err((pages, VSpaceError::CSpaceError { err }));
                                return None;
                            }
                        },
                        PageDeallocType::Retrieve(ref mut v) => {
                            v.push(cap);
                        },
                    }
                    pages += 1;
                    unsafe {
                        *level_entry = LevelEntry::Free;
                    }
                }

                None::<()>
            },
        );
        if alloc.unlock_alloc().is_err(){
            warn!("Hier::unmap_inner: could not release recursion lock; vaddr: {:x}, bytes: {:x}, mock: {}", vaddr, bytes, mock);
            return Err((pages, VSpaceError::InternalError));
        }
        ret
    }

    ///Internal implementation of change_protection()
    fn change_protection_inner<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
        mock: bool,
    ) -> Result<(), VSpaceError>{
        let bytes = bytes + bytes % PAGE_SIZE;
        let vroot = unsafe { &*self.top_level }.table_cap;
        let mut ret = Ok(());

        if alloc.lock_alloc().is_err(){
            warn!("Hier::change_protection_inner: could not acquire recursion lock; vaddr: {:x}, bytes: {:x}, mock: {}", vaddr, bytes, mock);
            return Err(VSpaceError::InternalError);
        }

        unsafe { &*self.top_level }.walk_table_range(
            vaddr,
            vaddr + bytes,
            |_, level_entry_vaddr, _, level_entry| {
                if ret.is_err() {
                    return None;
                }
                if let LevelEntry::Page {
                    cap, ..
                } = unsafe { (*level_entry).clone() }
                {
                    unsafe {
                        if !mock {
                            //XXX: make sure that this actually works
                            let res = MAP_PAGE(cap, vroot, level_entry_vaddr, rights, attrs);
                            if res != 0 {
                                let err = sel4::Error::copy_from_ipcbuf(res);
                                warn!("Hier::change_protection_inner: remapping page with capability {:x} failed with {:?}, starting address {:x}", cap, err, vaddr);
                                ret = Err(VSpaceError::MapFailure { details: err });
                                return None;
                            }
                        }
                        *level_entry = LevelEntry::Page {
                            cap,
                            rights,
                            attrs,
                        }
                    }
                }

                None::<()>
            },
        );
        if alloc.unlock_alloc().is_err(){
            warn!("Hier::change_protection_inner: could not release recursion lock; vaddr: {:x}, bytes: {:x}, mock: {}", vaddr, bytes, mock);
            return Err(VSpaceError::InternalError);
        }

        ret
    }
    ///Internal implementation of change_protection()
    fn change_protection_base<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
        mock: bool,
    ) -> Result<(), VSpaceError>{
        let mut remaining = bytes;
        let end_vaddr = vaddr + bytes;
        let mut cur_vaddr = vaddr;
        while cur_vaddr < end_vaddr {
            let mut cur_size = remaining;
            if cur_size > MAX_ALLOC_PAGES * PAGE_SIZE {
                cur_size = MAX_ALLOC_PAGES * PAGE_SIZE;
            }
            if let Err(err) = self.change_protection_inner(cur_vaddr,
                                               cur_size,
                                               rights,
                                               attrs,
                                               alloc,
                                               mock){
                warn!("Hier::change_protection_base: remapping failed for range of {} bytes starting at {:x}", bytes, vaddr);
                return Err(err)
            }
            cur_vaddr += cur_size;
            remaining -= cur_size;
        }
        Ok(())
    }
}

impl ToCap for Hier {
    fn to_cap(&self) -> seL4_CPtr {
        unsafe { (*self.top_level).table_cap }
    }
}

///A VSpace reservation
pub struct Reservation {
    reservation: UnsafeRef<ReservationNode>,
}

impl Reservation {
    fn res(&self) -> &ReservationNode {
        &*self.reservation
    }
}

impl VSpaceReservation for Reservation {
    fn start_vaddr(&self) -> usize {
        let mut vaddr = self.res().start_addr.get();
        // vaddr is sign-extended to the full 64-bit range for addresses >= 0x800000000000
        if VADDR_BITS < BITS && (vaddr & (1 << (VADDR_BITS - 1))) != 0 {
            vaddr |= ((!0 as u64) << VADDR_BITS) as usize;
        }
        vaddr
    }
    fn end_vaddr(&self) -> usize {
        let mut vaddr = self.res().end();
        // vaddr is sign-extended to the full 64-bit range for addresses >= 0x800000000000
        if VADDR_BITS < BITS && (vaddr & (1 << (VADDR_BITS - 1))) != 0 {
            vaddr |= ((!0 as u64) << VADDR_BITS) as usize;
        }
        vaddr
    }
}

impl Hier {
    fn coalesce(&self, block: &ReservationNode) {
        let mut all = self.all_blocks.borrow_mut();
        let mut free = self.free_blocks.borrow_mut();
        let mut start_addr = block.start_addr.get();
        let mut num_bytes = block.num_bytes.get();

        // coalesce forward, absorbing free ranges by adding their num_pages to our own.
        unsafe {
            let mut fwd = all.cursor_mut_from_ptr(block);
            fwd.move_next();

            while !fwd.is_null() && fwd.get().unwrap().size_link.is_linked() {
                let val = UnsafeRef::into_box(fwd.remove().unwrap());
                num_bytes += val.num_bytes.get();
                free.cursor_mut_from_ptr(&*val).remove();
                drop(val);
            }
        };

        // coalesce backward, absorbing free ranges by extending our start_addr.
        unsafe {
            let mut bkd = all.cursor_mut_from_ptr(block);
            bkd.move_prev();

            while !bkd.is_null() && bkd.get().unwrap().size_link.is_linked() {
                let val = UnsafeRef::into_box(bkd.remove().unwrap());
                start_addr = val.start_addr.get();
                num_bytes += val.num_bytes.get();
                free.cursor_mut_from_ptr(&*val).remove();
                drop(val);
                bkd.move_prev();
            }
        };

        // remove it from the tree
        unsafe {
            all.cursor_mut_from_ptr(block).remove();
        }

        if block.size_link.is_linked() {
            unsafe {
                free.cursor_mut_from_ptr(block).remove();
            }
        }

        block.num_bytes.set(num_bytes);
        block.start_addr.set(start_addr);

        unsafe {
            all.insert(UnsafeRef::from_raw(block as *const _ as *mut _));
            free.insert(UnsafeRef::from_raw(block as *const _ as *mut _));
        }
    }
}

impl VSpaceManager for Hier {
    type Reservation = Reservation;

    fn map_at_vaddr<A: AllocatorBundle, M: Copy + Mappable + ToCap>(
        &self,
        caps: &[M],
        vaddr: usize,
        size_bits: usize,
        res: &Self::Reservation,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        // vaddr is sign-extended to the full 64-bit range for addresses >= 0x800000000000
        // mask off the high bits to ignore that.
        if (vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) < res.res().start_addr.get() ||
            ((vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) +
                 (1 << size_bits) * caps.len()) > res.res().end()
        {
            return Err(VSpaceError::InvalidArgument { which: 1 });
        }

        // We can't mask off the high bits here because the correct vaddr needs to be sent
        // to the kernel.
        self.map_pages_at_vaddr_base(vaddr, rights, size_bits as u8, attrs, alloc, 
            false, caps.len(), &mut |index| {
                let obj: M = caps[index];
                obj.to_cap()
            })
    }

    fn map_at_vaddr_ref<A: AllocatorBundle>(
        &self,
        caps: &[SlotRef],
        vaddr: usize,
        size_bits: usize,
        res: &Self::Reservation,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        // vaddr is sign-extended to the full 64-bit range for addresses >= 0x800000000000
        // mask off the high bits to ignore that.
        if (vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) < res.res().start_addr.get() ||
            ((vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) +
                 (1 << size_bits) * caps.len()) > res.res().end()
        {
            return Err(VSpaceError::InvalidArgument { which: 1 });
        }

        // We can't mask off the high bits here because the correct vaddr needs to be sent
        // to the kernel.
        self.map_pages_at_vaddr_base(vaddr, rights, size_bits as u8, attrs, alloc, 
            false, caps.len(), &mut |index| {
                let slot_ref: SlotRef = caps[index];
                slot_ref.cptr
            })
    }

    fn map_at_vaddr_raw<A: AllocatorBundle>(
        &self,
        caps: &[seL4_CPtr],
        vaddr: usize,
        size_bits: usize,
        res: &Self::Reservation,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        // vaddr is sign-extended to the full 64-bit range for addresses >= 0x800000000000
        // mask off the high bits to ignore that.
        if (vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) < res.res().start_addr.get() ||
            ((vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) +
                 (1 << size_bits) * caps.len()) > res.res().end()
        {
            return Err(VSpaceError::InvalidArgument { which: 1 });
        }

        // We can't mask off the high bits here because the correct vaddr needs to be sent
        // to the kernel.
        self.map_pages_at_vaddr_base(vaddr, rights, size_bits as u8, attrs, alloc, 
            false, caps.len(), &mut |index| {
                caps[index]
            })
    }

    fn change_protection<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        bytes: usize,
        rights: sel4::CapRights,
        attrs: seL4_ARCH_VMAttributes,
        alloc: &A,
    ) -> Result<(), VSpaceError> {
        if alloc.lock_alloc().is_err(){
            return Err(VSpaceError::InternalError);
        }
        let ret = self.change_protection_base(vaddr, bytes, rights, attrs, alloc, false);
        if alloc.unlock_alloc().is_err(){
            return Err(VSpaceError::InternalError);
        }
        ret
    }

    fn unmap<A: AllocatorBundle>(&self, vaddr: usize, bytes: usize, dealloc_type: PageDeallocType, alloc: &A) -> Result<usize, (usize, VSpaceError)>{
        self.unmap_base(vaddr, bytes, dealloc_type, false, alloc)
    }

    fn reserve<A: AllocatorBundle>(&self, mut bytes: usize, alloc: &A) -> Option<Self::Reservation> {
        if alloc.lock_alloc().is_err(){
            return None;
        }
        if bytes % PAGE_SIZE != 0 {
            bytes += PAGE_SIZE - bytes % PAGE_SIZE;
        }
        let mut free = self.free_blocks.borrow_mut();
        let mut all = self.all_blocks.borrow_mut();
        let new;
        let opt_leftover;

        {
            let mut best_fit = free.lower_bound_mut(Bound::Included(&bytes));

            if let Some(block) = best_fit.get() {
                if block.num_bytes.get() > bytes {
                    opt_leftover = Some(block.split(bytes));
                    block.num_bytes.set(bytes);
                } else {
                    opt_leftover = None;
                    assert_eq!(block.num_bytes.get(), bytes, "Hier::reserve: best fit block was smaller than requested size (this shouldn't happen!)");
                }
            }else{
                let _ = alloc.unlock_alloc();
                return None;
            }
            new = best_fit.remove().unwrap();
        }

        if let Some(leftover) = opt_leftover {
            free.insert(leftover.clone());
            all.insert(leftover);
        }
        if alloc.unlock_alloc().is_err(){
            return None;
        }

        Some(Reservation {
            reservation: new,
        })
    }

    fn reserve_at_vaddr<A: AllocatorBundle>(
        &self,
        vaddr: usize,
        mut bytes: usize,
        alloc: &A,
    ) -> Option<Self::Reservation> {
        if vaddr > VADDR_LIMIT || vaddr + bytes > VADDR_LIMIT {
            return None;
        }
        if alloc.lock_alloc().is_err(){
            return None;
        }
        if bytes % PAGE_SIZE != 0 {
            bytes += PAGE_SIZE - bytes % PAGE_SIZE;
        }
        // vaddr is sign-extended to the full 64-bit range for addresses > 0x800000000000
        // mask off the high bits to ignore that.
        let vaddr = PAGE_SIZE * ((vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) / PAGE_SIZE);
        let mut all = self.all_blocks.borrow_mut();
        let mut free = self.free_blocks.borrow_mut();
        let new;
        let opt_leftover;
        let opt_newblock;

        {
            // see if the requested range is free.
            let mut containing = all.upper_bound_mut(Bound::Included(&vaddr));

            if !containing.get().expect("reserve_at_vaddr/containing.get").size_link.is_linked() {
                let _ = alloc.unlock_alloc();
                return None;
            }

            containing.move_next();

            if let Some(c) = containing.get() {
                if c.start_addr.get() <= vaddr + bytes {
                    vspace_debug_println!("none2");
                    let _ = alloc.unlock_alloc();
                    return None;
                }
            }

            containing.move_prev();

            let block = containing.get().unwrap();

            if block.start_addr.get() == vaddr {
                // |       free space       |
                // -----------to-------------
                // | block |    leftover    | (leftover could be empty)
                if block.num_bytes.get() > bytes {
                    opt_leftover = Some(block.split(bytes));
                    block.num_bytes.set(bytes);
                } else {
                    opt_leftover = None;
                    assert_eq!(block.num_bytes.get(), bytes, "Hier::reserve_at_vaddr: found block was smaller than requested size (this shouldn't happen!)");
                }
                new = unsafe { free.cursor_mut_from_ptr(&*block).remove().unwrap() };
                opt_newblock = None;
            } else {
                // |              free space             |
                // ------------------to-------------------
                // |   block    | newblock |   leftover  | (leftover could be empty)
                let newblock = block.split(vaddr - block.start_addr.get());
                block.num_bytes.set(vaddr - block.start_addr.get());
                if newblock.num_bytes.get() > bytes {
                    opt_leftover = Some(newblock.split(bytes));
                    newblock.num_bytes.set(bytes);
                } else {
                    opt_leftover = None;
                    assert_eq!(newblock.num_bytes.get(), bytes, "Hier::reserve_at_vaddr: found block was smaller than requested size after splitting (this shouldn't happen!)");
                }
                new = newblock.clone();
                opt_newblock = Some(newblock);
            }
        }

        if let Some(newblock) = opt_newblock {
            all.insert(newblock);
        }

        if let Some(leftover) = opt_leftover {
            free.insert(leftover.clone());
            all.insert(leftover);
        }

        if alloc.unlock_alloc().is_err(){
            return None;
        }

        Some(Reservation {
            reservation: new,
        })
    }

    fn get_reservation(&self, vaddr: usize) -> Result<Self::Reservation, ()> {
        let vaddr = PAGE_SIZE * ((vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) / PAGE_SIZE);

        let mut all = self.all_blocks.borrow_mut();
        let containing = all.upper_bound_mut(Bound::Included(&vaddr));
        if containing.is_null(){
            Err(())
        }else{
            Ok(Reservation {
                reservation: unsafe { UnsafeRef::from_raw(containing.get().unwrap()) },
            })
        }
    }

    fn unreserve<A: AllocatorBundle>(&self, reservation: Self::Reservation, alloc: &A) -> Result<(), VSpaceError> {
        if alloc.lock_dealloc().is_err(){
            return Err(VSpaceError::InternalError);
        }
        self.coalesce(&*reservation.reservation);
        if alloc.unlock_dealloc().is_err(){
            return Err(VSpaceError::InternalError);
        }
        Ok(())
    }

    fn unreserve_at_vaddr<A: AllocatorBundle>(&self, vaddr: usize, alloc: &A) -> Result<(), VSpaceError> {
        if vaddr > VADDR_LIMIT {
            return Err(VSpaceError::InvalidArgument { which: 0 });
        }
        // vaddr is sign-extended to the full 64-bit range for addresses >= 0x800000000000
        // mask off the high bits to ignore that.
        let vaddr = PAGE_SIZE * ((vaddr & (!0 >> (BITS as usize - VADDR_BITS as usize))) / PAGE_SIZE);

        let (ptr, is_free) = {
            let mut all = self.all_blocks.borrow_mut();
            let containing = all.upper_bound_mut(Bound::Included(&vaddr));
            let ptr = containing.get().expect("unreserve_at_vaddr/containing.get") as *const ReservationNode;
            let is_free = containing.get().unwrap().size_link.is_linked();

            (ptr, is_free)
        };

        if !is_free {
            if alloc.lock_dealloc().is_err(){
                return Err(VSpaceError::InternalError);
            }
            unsafe { self.coalesce(&*ptr) }
            if alloc.unlock_dealloc().is_err(){
                return Err(VSpaceError::InternalError);
            }

            Ok(())
        } else {
            Err(VSpaceError::InvalidArgument { which: 0 })
        }
    }

    fn unreserve_range_at_vaddr<A: AllocatorBundle>(&self, vaddr: usize, bytes: usize, alloc: &A) -> Result<(), VSpaceError> {
        let res_opt = self.get_reservation(vaddr);
        if res_opt.is_err(){
            return Err(VSpaceError::ReservationFailure);
        }
        let res = res_opt.unwrap();

        let start = res.start_vaddr();
        let end = res.end_vaddr();
        if vaddr + bytes > end {
            return Err(VSpaceError::InvalidArgument { which: 0 });
        }
        if let Err(err) = self.unreserve(res, alloc){
            return Err(err);
        }
        if vaddr > start && self.reserve_at_vaddr(start, vaddr - start, alloc).is_none() {
            return Err(VSpaceError::ReservationFailure);
        }
        if vaddr + bytes < end && self.reserve_at_vaddr(vaddr + bytes, end - (vaddr + bytes), alloc).is_none() {
            return Err(VSpaceError::ReservationFailure);
        }
        Ok(())
    }

    fn get_cap(&self, vaddr: usize) -> Option<seL4_CPtr> {
        match unsafe { (&*self.top_level).get_level_entry(vaddr) } {
            Some(&LevelEntry::Page {
                     cap, ..
                 }) => Some(cap),
            _ => None,
        }
    }

    fn root(&self) -> seL4_CPtr {
        unsafe { (*self.top_level).table_cap }
    }

    fn minimum_slots(&self) -> usize {
        // conservative - might need a handful of caps when creating deepl
        32
    }

    fn minimum_untyped(&self) -> usize {
        // conservative - 16KiB per hierarchy level is more than enough for storing paging
        // structures.
        HIER_LEVELS.len() * 16 * 1024
    }

    fn minimum_vspace(&self) -> usize {
        // conservative - 16KiB per hierarchy level is more than enough for storing LevelNodes.
        HIER_LEVELS.len() * 16 * 1024
    }
}

impl Drop for Hier {
    fn drop(&mut self){
        panic!("TODO: implement dropping of VSpaces");
    }
}

pub fn add_custom_slabs<A: CustomSlabAllocator>(alloc: &A) -> Result<(), ()>{
    vspace_debug_println!("vspace::hier::add_custom_slabs: adding reservation node slab");
    alloc.add_custom_slab(mem::size_of::<ReservationNode>(), 128, 32, 32, 2)?;
    for depth in 0..HIER_LEVELS.len(){
        vspace_debug_println!("vspace::hier::add_custom_slabs: adding level {} node slab", depth);
        alloc.add_custom_slab(LevelNode::total_size(HIER_LEVELS[depth as usize].2), HIER_LEVELS[depth as usize].4, HIER_LEVELS[depth as usize].5, HIER_LEVELS[depth as usize].5, 2)?;
    }

    Ok(())
}
