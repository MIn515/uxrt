// Copyright (c) 2015 The Robigalia Project Developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

use sel4_sys::*;

use ToCap;
#[cfg(feature = "CONFIG_ARM_HYPERVISOR_SUPPORT")]
use Thread;

cap_wrapper!{ ()
    /// Authority to allocate ASID pools
    ASIDControl,
    /// Authority to create page directories
    ASIDPool,

    /// A 4K page of physical memory mapped into a page table
    SmallPage = seL4_ARM_SmallPageObject |_| 1 << seL4_PageBits,
    /// A 64K page of physical memory mapped into a page table
    LargePage = seL4_ARM_LargePageObject |_| 1 << seL4_LargePageBits,
    /// A 1M page of physical memory mapped into a page directory
    Section = seL4_ARM_SectionObject |_| 1 << seL4_SectionBits,
    /// A 16M page of physical memory mapped into a page directory
    SuperSection = seL4_ARM_SuperSectionObject |_| 1 << seL4_SuperSectionBits,
    /// A page table, which can have pages mapped into it
    PageTable = seL4_ARM_PageTableObject |_| 1 << seL4_PageTableBits,
    /// A page directory, which holds page tables or sections and forms the root of the vspace
    PageDirectory = seL4_ARM_PageDirectoryObject |_| 1 << seL4_PageDirBits,
}

#[cfg(feature = "CONFIG_ARM_SMMU")]
cap_wrapper!{ ()
    /// Authority to map IO page tables into a device's address space
    IOSpace,
    /// A page table for the IOMMU
    IOPageTable = seL4_ARM_IOPageTableObject |_| 1 << seL4_IOPageTableBits,
}

#[cfg(feature = "CONFIG_ARM_HYPERVISOR_SUPPORT")]
cap_wrapper!{ ()
    VCPU = seL4_ARM_VCPUObject |_| 1 << seL4_VCPUBits,
}

impl ASIDControl {
    /// Create a new ASID pool, using `untyped` as the storage, and storing the capability in
    /// `dest`.
    ///
    /// `untyped` must be 4KiB.
    #[inline(always)]
    pub fn make_pool(&self, untyped: SmallPage, dest: ::SlotRef) -> ::Result {
        unsafe_as_result!(seL4_ARM_ASIDControl_MakePool(
            self.cptr,
            untyped.to_cap(),
            dest.root.to_cap(),
            dest.cptr,
            dest.depth,
        ))
    }
}

impl ASIDPool {
    /// Assign a page directory to this ASID pool.
    #[inline(always)]
    pub fn assign(&self, vroot: PageDirectory) -> ::Result {
        unsafe_as_result!(seL4_ARM_ASIDPool_Assign(self.cptr, vroot.to_cap()))
    }
}

macro_rules! page_impls {
    ($name:ident) => {
impl $name {
    /// Map this page into an address space.
    #[inline(always)]
    pub fn map(&self, pd: PageDirectory, addr: seL4_Word, rights: seL4_CapRights,
               attr: seL4_ARM_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_ARM_Page_Map(self.cptr, pd.to_cap(), addr, rights, attr))
    }

    /// Map this page into a device's address space.
    #[cfg(feature = "CONFIG_ARM_SMMU")]
    #[inline(always)]
    pub fn map_io(&self, iospace: IOSpace, rights: seL4_CapRights, addr: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_Page_MapIO(self.cptr, iospace.to_cap(), rights, addr))
    }

    /// Remap this page, possibly changing rights or attribute but not address.
    #[inline(always)]
    pub fn remap(&self, pd: PageDirectory, rights: seL4_CapRights,
                 attr: seL4_ARM_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_ARM_Page_Remap(self.cptr, pd.to_cap(), rights, attr))
    }

    /// Unmap this page.
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_ARM_Page_Unmap(self.cptr))
    }

    /// Get the physical address of the underlying frame.
    #[inline(always)]
    pub fn get_address(&self) -> Result<seL4_Word, ::Error> {
        let res = unsafe { seL4_ARM_Page_GetAddress(self.cptr) };
        if res.error == 0 {
            Ok(res.paddr)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }

    #[inline(always)]
    pub fn clean_data(&self, start: seL4_Word, end: seL4_Word) -> :: Result {
        unsafe_as_result!(seL4_ARM_Page_Clean_Data(self.cptr, start, end))
    }

    #[inline(always)]
    pub fn invalidate_data(&self, start: seL4_Word, end: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_Page_Invalidate_Data(self.cptr, start, end))
    }

    #[inline(always)]
    pub fn clean_and_invalidate_data(&self, start: seL4_Word, end: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_Page_CleanInvalidate_Data(self.cptr, start, end))
    }

    #[inline(always)]
    pub fn unify_instruction(&self, start: seL4_Word, end: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_Page_Unify_Instruction(self.cptr, start, end))
    }
}
}}

page_impls!(SmallPage);
page_impls!(LargePage);
page_impls!(Section);
page_impls!(SuperSection);

impl PageDirectory {
    #[inline(always)]
    pub fn clean_data(&self, start: seL4_Word, end: seL4_Word) -> :: Result {
        unsafe_as_result!(seL4_ARM_PageDirectory_Clean_Data(self.cptr, start, end))
    }

    #[inline(always)]
    pub fn invalidate_data(&self, start: seL4_Word, end: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_PageDirectory_Invalidate_Data(self.cptr, start, end))
    }

    #[inline(always)]
    pub fn clean_and_invalidate_data(&self, start: seL4_Word, end: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_PageDirectory_CleanInvalidate_Data(self.cptr, start, end))
    }

    #[inline(always)]
    pub fn unify_instruction(&self, start: seL4_Word, end: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_PageDirectory_Unify_Instruction(self.cptr, start, end))
    }
}

impl PageTable {
    /// Map this page table into an address space.
    #[inline(always)]
    pub fn map(&self, pd: PageDirectory, addr: seL4_Word, attr: seL4_ARM_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_ARM_PageTable_Map(self.cptr, pd.to_cap(), addr, attr))
    }

    /// Unmap this page.
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_ARM_PageTable_Unmap(self.cptr))
    }
}

#[cfg(feature = "CONFIG_ARM_SMMU")]
impl IOPageTable {
    #[inline(always)]
    pub fn map(&self, iospace: IOPageTable, addr: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_ARM_IOPageTable_Map(self.cptr, iospace.to_cap(), addr))
    }

    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_ARM_IOPageTable_Unmap(self.cptr))
    }
}

#[cfg(feature = "CONFIG_ARM_HYPERVISOR_SUPPORT")]
impl VCPU {
    #[inline(always)]
    pub fn set_thread(&self, thread: Thread) -> ::Result {
        unsafe_as_result!(seL4_ARM_VCPU_SetTCB(self.cptr, thread.to_cap()))
    }

    #[inline(always)]
    pub fn inject_irq(&self, virq: u16, priority: u8, group: u8, index: u8) -> ::Result {
        unsafe_as_result!(seL4_ARM_VCPU_InjectIRQ(self.cptr, virq, priority, group, index))
    }

    #[inline(always)]
    pub fn read_regs(&self, field: u32) -> Result<u32, ::Error> {
        let res = unsafe { seL4_ARM_VCPU_ReadRegs(self.cptr, field) };
        if res.error == 0 {
            Ok(res.value)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }

    #[inline(always)]
    pub fn write_regs(&self, field: u32, value: u32) -> ::Result {
        unsafe_as_result!(seL4_ARM_VCPU_WriteRegs(self.cptr, field, value))
    }
}
