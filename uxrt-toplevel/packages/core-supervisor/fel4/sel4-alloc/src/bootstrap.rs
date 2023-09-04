// Copyright 2019-2020 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright 2016 Robigalia Project Developers
// 
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[macro_export]
macro_rules! bootstrap_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_bootstrap")]
        debug!($($toks)*);
    })
}

use core::ops;
use alloc::boxed::Box;

use sel4;

use sel4::{PAGE_SIZE, CNode, CNodeInfo, SlotRef, Window, CapRights, FromCap, seL4_CPtr};
use sel4_sys::seL4_CapInitThreadVSpace;

use sel4_start::get_stack_bottom_addr;

use crate::{
    cspace::{
        BitmapAllocator,
        SwitchingAllocator,
    },
    dummy::DummyAlloc,
    utspace::{
        UtSlabAllocator,
        UtBucket,
    },
    vspace::{
        Hier,
        VSpaceManager,
        VSpaceReservation,
    },
};

pub type BootstrapCSpaceManager = SwitchingAllocator;
pub type BootstrapUTSpaceManager = UtSlabAllocator;
pub type BootstrapVSpaceManager = Hier;
pub type BootstrapAllocatorBundle = (BootstrapCSpaceManager, BootstrapUTSpaceManager, BootstrapVSpaceManager);

extern "C" {
    static __executable_start: u8;
}

#[cfg(target_pointer_width = "32")]
mod consts {
    pub const BITS: u8 = 32;

    pub const LEN_SEG_HDR: isize = 0x2a;
    pub const OFFSET_SEG_HDR: isize = 0x1c;
    pub const NUM_SEG_HDRS: isize = 0x2c;

    pub const VADDR_START: isize = 0x08;
    pub const VADDR_END: isize = 0x14;
}

#[cfg(target_pointer_width = "64")]
mod consts {
    pub const BITS: u8 = 64;

    pub const LEN_SEG_HDR: isize = 0x36;
    pub const OFFSET_SEG_HDR: isize = 0x20;
    pub const NUM_SEG_HDRS: isize = 0x38;

    pub const VADDR_START: isize = 0x10;
    pub const VADDR_END: isize = 0x28;
}

const MAX_ALLOC_ORDER: usize = 10;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod arch_consts {
    pub const UTSPACE_ZONES : [(usize, usize); 2] = [
            (1<<20, 1<<24), //24-bit (ISA) DMA, excluding real mode 
                                    //memory (which is treated as device memory)
            (1<<24, 1<<32), //32-bit DMA
    ];
}

#[cfg(target_arch = "arm")]
pub mod arch_consts {
    pub const UTSPACE_ZONES : [(usize, usize); 2] = [
            (2.pow(0), 2.pow(32)), //32-bit DMA
    ];
}

/// Accessor for resources needed to bootstrap an allocator stack.
pub trait BootstrapResources {
    fn untyped<'a>(&'static self) -> Box<dyn Iterator<Item = (SlotRef, sel4_sys::seL4_UntypedDesc)> + 'a>;

    fn cnode(&self) -> (Window, CNodeInfo);

    fn vspace(&self) -> seL4_CPtr;

    fn existing_mappings(&self, start_vaddr: usize, end_vaddr: usize) -> Option<(ops::Range<seL4_CPtr>, ops::Range<usize>)>;

    fn stack_guard_page(&self) -> Option<usize>;

    fn ipc_buffer(&self) -> Option<usize>;

    fn bootinfo_range(&self) -> Option<(usize, usize)>;
}

impl BootstrapResources for ::sel4_sys::seL4_BootInfo {
    fn untyped<'a>(&'static self) -> Box<dyn Iterator<Item = (SlotRef, sel4_sys::seL4_UntypedDesc)> + 'a> {
        Box::new(
            (self.untyped.start..self.untyped.end)
                .map(|x| SlotRef {
                    root: CNode::from_cap(sel4_sys::seL4_CapInitThreadCNode),
                    cptr: x,
                    depth: consts::BITS,
                }).zip(unsafe { sel4::bootinfo_untyped_descs(self) }.iter().map(|x| *x)),
        )
    }

    fn cnode(&self) -> (Window, CNodeInfo) {
        #[cfg(feature = "debug")]
        println!("root has {} as init cnode size bits", self.initThreadCNodeSizeBits);

        (
            Window {
                cnode: SlotRef {
                    root: CNode::from_cap(0x2),
                    cptr: 2,
                    depth: consts::BITS,
                },
                first_slot_idx: self.empty.start,
                num_slots: self.empty.end - self.empty.start,
            },
            CNodeInfo {
                guard_val: 0,
                radix_bits: self.initThreadCNodeSizeBits as u8,
                guard_bits: consts::BITS - self.initThreadCNodeSizeBits as u8,
                prefix_bits: 0,
            },
        )
    }

    fn vspace(&self) -> seL4_CPtr {
        seL4_CapInitThreadVSpace
    }

    fn existing_mappings(&self, start_vaddr: usize, end_vaddr: usize) -> Option<(ops::Range<seL4_CPtr>, ops::Range<usize>)> {
        if start_vaddr == end_vaddr {
            Some((
                self.userImageFrames.start..self.userImageFrames.end,
                get_vaddr_range_from_elf_hdr(unsafe { &__executable_start }),
            ))
        }else{
            Some((
                self.userImageFrames.start..self.userImageFrames.end,
                start_vaddr..end_vaddr,
            ))
        }
    }

    fn stack_guard_page(&self) -> Option<usize> {
        let mut addr = get_stack_bottom_addr();

        if addr % PAGE_SIZE != 0 {
            addr += PAGE_SIZE - addr % PAGE_SIZE;
        }

        Some(addr)
    }
    fn ipc_buffer(&self) -> Option<usize> {
        Some(self.ipcBuffer as usize)
    }
    fn bootinfo_range(&self) -> Option<(usize, usize)> {
        Some((self as *const ::sel4_sys::seL4_BootInfo as usize, 
            (self.extraLen + (PAGE_SIZE - 1)) & (!(PAGE_SIZE - 1))
        ))
    }
}

/// Bootstrap allocators from initial resources to enable an actual allocator to be able to run.
///
/// # Note
///
/// This requires `alloc` functions to work! The heap module provides a 
/// full-featured slab heap allocator capable of self-bootstrapping from a 
/// static array.
pub fn bootstrap_allocators<B: BootstrapResources>(bi: &'static B, user_start_vaddr: usize, user_end_vaddr: usize) -> BootstrapAllocatorBundle {
    bootstrap_debug_println!("initializing CSpace");
    let cnode = bi.cnode();
    let bitmap = BitmapAllocator::new(cnode.0, cnode.1, cnode.0.cnode.root).expect("cannot initialize CSpace allocator");

    bootstrap_debug_println!("initializing UTSpace");

    let slab = UtSlabAllocator::new(&arch_consts::UTSPACE_ZONES, MAX_ALLOC_ORDER);

    let alloc = (bitmap, slab, DummyAlloc);

    for (slotref, ut) in bi.untyped() {
        alloc.1.add_bucket(&alloc, UtBucket::new(
            slotref,
            ut.sizeBits,
            ut.paddr,
            ut.isDevice == 1,
        )).expect("failed to add bucket to top-level allocator");
    }

    bootstrap_debug_println!("initializing VSpace");

    let hier = Hier::new(&alloc, Some(bi.vspace())).expect("failed to create initial VSpace manager");

    if let Some((cptrs, vaddrs)) = bi.existing_mappings(user_start_vaddr, user_end_vaddr) {
        let rsvp = hier.reserve_at_vaddr(vaddrs.start, vaddrs.end - vaddrs.start, &alloc)
            .expect("failed to reserve range for initial mappings");
        let mut addr = vaddrs.start;

        for cptr in cptrs {
            hier.mock_map_at_vaddr_raw(
                &[cptr],
                addr,
                12,
                &rsvp,
                CapRights::rw(),
                Default::default(),
                &alloc,
            ).expect("failed to create initial mapping record");
            addr += PAGE_SIZE;
        }

        if vaddrs.end % PAGE_SIZE != 0 {
            assert_eq!(addr, vaddrs.end + (PAGE_SIZE - vaddrs.end % PAGE_SIZE));
        } else {
            assert_eq!(addr, vaddrs.end);
        }

        assert_eq!(addr, rsvp.end_vaddr());

        if let Some(addr) = bi.ipc_buffer() {
            if (addr < vaddrs.start) || (addr > vaddrs.end) || (addr + PAGE_SIZE > vaddrs.end) {
                hier.reserve_at_vaddr(addr, PAGE_SIZE, &alloc).expect("failed to reserve IPC buffer page");
            }
        }
        if let Some((addr, len)) = bi.bootinfo_range() {
            if (addr < vaddrs.start) || (addr > vaddrs.end) || (addr + len > vaddrs.end) {
                hier.reserve_at_vaddr(addr, len, &alloc).expect("failed to reserve boot info region");
            }
        }
    }

    if let Some(addr) = bi.stack_guard_page() {
        hier.change_protection(
            addr,
            PAGE_SIZE as usize,
            CapRights::none(),
            Default::default(),
            &alloc,
        ).expect("failed to remove rights from stack guard");
    }

    // Reserve the first 2MB of virtual memory to avoid handing that out to applications
    // Applications that want to map this memory can call unreserve_at_vaddr(0).
    let _ = hier.reserve_at_vaddr(0, 1024 * 1024 * 2, &alloc);
  
    (SwitchingAllocator::new(alloc.0), alloc.1, hier)
}

// Enumerate the elf headers to determine our starting and ending vaddrs
fn get_vaddr_range_from_elf_hdr(header: *const u8) -> ops::Range<usize> {
    unsafe {
        assert_eq!(*(header as *const u32), 0x464c457f);

        let len_seg_hdr = *(header.offset(consts::LEN_SEG_HDR) as *const u16);
        let offset_seg_hdr = *(header.offset(consts::OFFSET_SEG_HDR) as *const isize);
        let num_seg_hdrs = *(header.offset(consts::NUM_SEG_HDRS) as *const u16);

        let mut segment = header.offset(offset_seg_hdr) as *const u8;
        let mut low_vaddr = usize::max_value();
        let mut high_vaddr = 0;

        for _ in 0..num_seg_hdrs {
            let vaddr_start = *(segment.offset(consts::VADDR_START) as *const usize);
            let vaddr_end = vaddr_start + *(segment.offset(consts::VADDR_END) as *const usize);

            if vaddr_start > 0 {
                if vaddr_start < low_vaddr {
                    low_vaddr = vaddr_start;
                }
                if vaddr_end > high_vaddr {
                    high_vaddr = vaddr_end;
                }
            }

            segment = segment.offset(len_seg_hdr as isize) as *const u8;
        }

        low_vaddr..high_vaddr
    }
}
