// Copyright (c) 2018-2022 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright (c) 2015 The Robigalia Project Developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

//TODO: make this optional, since libroot won't use sel4_start, nor will it have access to the bootinfo

#![allow(non_snake_case, non_camel_case_types)]

use crate::PAGE_SIZE;
use sel4_sys;
use core::mem::transmute;
use core::num::NonZeroUsize;
pub use sel4_sys::{
    seL4_BootInfoID,
    seL4_BootInfo,
    seL4_UntypedDesc,
    seL4_VBEInfoBlock,
    seL4_VBEModeInfoBlock,
    seL4_X86_BootInfo_VBE,
    seL4_X86_mb_mmap,
    seL4_X86_BootInfo_mmap,
    seL4_X86_BootInfo_fb_t,
    seL4_BootInfo_mbi2,
};

/// Extra blocks of information passed from the kernel
pub enum BootInfoExtra {
    X86_VBE(&'static seL4_X86_BootInfo_VBE),
    X86_mmap(&'static seL4_X86_BootInfo_mmap),
    X86_framebuffer(&'static seL4_X86_BootInfo_fb_t),
    X86_mbi2_pt(&'static seL4_BootInfo_mbi2),
}

/// Iterator over extra bootinfo blocks
pub struct BootInfoExtraIter {
    first_ptr: *mut sel4_sys::seL4_BootInfoHeader,
    num_bytes: sel4_sys::seL4_Word,
}

impl core::iter::Iterator for BootInfoExtraIter {
    type Item = BootInfoExtra;

    fn next(&mut self) -> Option<BootInfoExtra> {
        while self.num_bytes > 0 {
            let (id, len) = unsafe { ((*self.first_ptr).id, (*self.first_ptr).len) };
            if len <= self.num_bytes {
                self.num_bytes -= len;
            }else{
                println!("bootinfo tag with id {} and length {} extends past the remaining length of {}", id, len, self.num_bytes);
            }
                        let ptr = self.first_ptr;
            self.first_ptr = ((self.first_ptr as usize) + len as usize) as *mut sel4_sys::seL4_BootInfoHeader;
            match id as seL4_BootInfoID {
                sel4_sys::SEL4_BOOTINFO_HEADER_PADDING => {},
                sel4_sys::SEL4_BOOTINFO_HEADER_X86_VBE => {
                    return Some(BootInfoExtra::X86_VBE(unsafe { transmute(ptr) }))
                },
                sel4_sys::SEL4_BOOTINFO_HEADER_X86_MBMMAP => {
                    return Some(BootInfoExtra::X86_mmap(unsafe { transmute(ptr) }))
                },
                sel4_sys::SEL4_BOOTINFO_HEADER_X86_ACPI_RSDP => {/*TODO*/},
                sel4_sys::SEL4_BOOTINFO_HEADER_X86_FRAMEBUFFER => {
                    return Some(BootInfoExtra::X86_framebuffer(unsafe { transmute(ptr) }))
                },
                sel4_sys::SEL4_BOOTINFO_HEADER_X86_TSC_FREQ => {/*TODO*/},
                sel4_sys::SEL4_BOOTINFO_HEADER_MBI2 => {
                    return Some(BootInfoExtra::X86_mbi2_pt(unsafe { transmute(ptr) }))
                },
                _ => debug_assert!(false, "unknown bootinfo header type {}", id),
            }
        }
        None
    }
}

/// This is safe if you don't mutate the `untyped` field and corrupt its length.
pub unsafe fn bootinfo_untyped_descs(bootinfo: &'static sel4_sys::seL4_BootInfo) -> &[seL4_UntypedDesc] {
    let len = bootinfo.untyped.end - bootinfo.untyped.start;
    core::slice::from_raw_parts(&bootinfo.untypedList[0], len)
}

/// This is safe if you don't unmap the extraBIPages
pub unsafe fn bootinfo_extras(bootinfo: &'static sel4_sys::seL4_BootInfo) -> BootInfoExtraIter {
    BootInfoExtraIter {
        first_ptr: (bootinfo as *const _ as usize + PAGE_SIZE) as *mut sel4_sys::seL4_BootInfoHeader,
        num_bytes: (bootinfo.extraLen + (PAGE_SIZE - 1)) & (!(PAGE_SIZE - 1)),
    }
}

pub fn bootinfo() -> &'static sel4_sys::seL4_BootInfo {
    unsafe { &*sel4_start::BOOTINFO }
}

pub fn available_parallelism() -> NonZeroUsize {
    NonZeroUsize::new(bootinfo().numNodes).expect("kernel reported zero cores present")
}
