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
#[cfg(feature = "CONFIG_VTX")]
use Thread;

cap_wrapper!{ ()
    /// Authority to create ASID pools
    ASIDControl,
    /// Authority to create page directories
    ASIDPool,
    /// Authority to use port-IO
    IOPort,
    /// Authority to map IO page tables into a device's address space
    IOSpace,

    /// A page of physical memory that can be mapped into a vspace
    Page = seL4_X86_4K |_| 1 << seL4_PageBits,
    /// A 'large page' (4MiB) for use with PAE
    LargePage = seL4_X86_LargePageObject |_| 1 << seL4_LargePageBits,
    /// A page table, which can have pages mapped into it
    PageTable = seL4_X86_PageTableObject |_| 1 << seL4_PageTableBits,
    /// A page directory, which holds page tables and forms the root of the vspace
    PageDirectory = seL4_X86_PageDirectoryObject |_| 1 << seL4_PageDirBits,
}

#[cfg(feature = "CONFIG_IOMMU")]
cap_wrapper!{ ()
    /// A page table for the IOMMU
    IOPageTable = seL4_X86_IOPageTableObject |_| 1 << seL4_IOPageTableBits,
}

#[cfg(feature = "CONFIG_VTX")]
cap_wrapper!{ ()
    /// A virtual CPU, for virtualization
    VCPU = seL4_X86_VCPUObject |_| 1 << seL4_VCPUBits,
    /// Extended page table (virt) PML4
    EPTPML4 = seL4_X86_EPTPML4Object |_| 1 << seL4_EPTPML4Bits,
    /// Extended page table (virt) PDPT
    EPTPDPT = seL4_X86_EPTPDPTObject |_| 1 << seL4_EPTPDPTBits,
    /// Extended page table (virt) PageDirectory
    EPTPageDirectory = seL4_X86_EPTPDObject |_| 1 << seL4_EPTPDBits,
    /// Extended page table (virt) PageTable
    EPTPageTable = seL4_X86_EPTPTObject |_| 1 << seL4_EPTPTBits,
}

impl ASIDControl {
    /// Create a new ASID pool, using `untyped` as the storage, and storing the capability in
    /// `dest`.
    ///
    /// `untyped` must be 4KiB.
    #[inline(always)]
    pub fn make_pool(&self, untyped: Page, dest: ::SlotRef) -> ::Result {
        unsafe_as_result!(seL4_X86_ASIDControl_MakePool(
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
        unsafe_as_result!(seL4_X86_ASIDPool_Assign(self.cptr, vroot.to_cap()))
    }
}

impl IOPort {
    /// Read 8 bits from the given port.
    #[inline(always)]
    pub fn read8(&self, port: u16) -> Result<u8, ::Error> {
        let res = unsafe { seL4_X86_IOPort_In8(self.cptr, port) };
        if res.error == 0 {
            Ok(res.result)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error}))
        }
    }

    /// Read 16 bits from the given port.
    #[inline(always)]
    pub fn read16(&self, port: u16) -> Result<u16, ::Error> {
        let res = unsafe { seL4_X86_IOPort_In16(self.cptr, port) };
        if res.error == 0 {
            Ok(res.result)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }

    /// Read 32 bits from the given port.
    #[inline(always)]
    pub fn read32(&self, port: u16) -> Result<u32, ::Error> {
        let res = unsafe { seL4_X86_IOPort_In32(self.cptr, port) };
        if res.error == 0 {
            Ok(res.result)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }

    /// Write 8-bit `value` to the given port.
    #[inline(always)]
    pub fn write8(&self, port: u16, value: u8) -> ::Result {
        unsafe_as_result!(seL4_X86_IOPort_Out8(self.cptr, port as seL4_Word, value as seL4_Word))
    }

    /// Write 16-bit `value` to the given port.
    #[inline(always)]
    pub fn write16(&self, port: u16, value: u16) -> ::Result {
        unsafe_as_result!(seL4_X86_IOPort_Out16(self.cptr, port as seL4_Word, value as seL4_Word))
    }

    /// Write 32-bit `value` to the given port.
    #[inline(always)]
    pub fn write32(&self, port: u16, value: u32) -> ::Result {
        unsafe_as_result!(seL4_X86_IOPort_Out32(self.cptr, port as seL4_Word, value as seL4_Word))
    }
}

#[cfg(feature = "CONFIG_IOMMU")]
impl IOPageTable {
    /// Map this page table into an IOSpace at `addr`
    #[inline(always)]
    pub fn map(&self, iospace: IOSpace, addr: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_X86_IOPageTable_Map(self.cptr, iospace.to_cap(), addr))
    }

    /// Unmap this page table
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_IOPageTable_Unmap(self.cptr))
    }
}

macro_rules! page_impls {
    ($name:ident) => {
impl $name {
    /// Map this page into a VTX EPTPML4
    #[cfg(feature = "CONFIG_VTX")]
    #[inline(always)]
    pub fn map_ept(&self, vroot: EPTPML4, addr: seL4_Word, rights: seL4_CapRights,
                   attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_Page_MapEPT(self.cptr, vroot.to_cap(), addr, rights, attr))
    }

    /// Map this page into an IOSpace with `rights` at `addr`.
    #[inline(always)]
    pub fn map_io(&self, iospace: IOSpace, rights: seL4_CapRights, addr: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_X86_Page_MapIO(self.cptr, iospace.to_cap(), rights, addr))
    }

    /// Map this page into an address space.
    #[inline(always)]
    pub fn map(&self, pd: PageDirectory, addr: seL4_Word, rights: seL4_CapRights,
               attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_Page_Map(self.cptr, pd.to_cap(), addr, rights, attr))
    }

    /// Remap this page, possibly changing rights or attribute but not address.
    #[inline(always)]
    pub fn remap(&self, pd: PageDirectory, rights: seL4_CapRights, attr: seL4_X86_VMAttributes)
                 -> ::Result {
        unsafe_as_result!(seL4_X86_Page_Remap(self.cptr, pd.to_cap(), rights, attr))
    }

    /// Unmap this page.
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_Page_Unmap(self.cptr))
    }

    /// Get the physical address of the underlying frame.
    #[inline(always)]
    pub fn get_address(&self) -> Result<seL4_Word, ::Error> {
        let res = unsafe { seL4_X86_Page_GetAddress(self.cptr) };
        if res.error == 0 {
            Ok(res.paddr)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }
}
}}

page_impls!(Page);
page_impls!(LargePage);

impl PageTable {
    /// Map this page table into an address space.
    #[inline(always)]
    pub fn map(&self, pd: PageDirectory, addr: seL4_Word, attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_PageTable_Map(self.cptr, pd.to_cap(), addr, attr))
    }

    /// Unmap this page.
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_PageTable_Unmap(self.cptr))
    }
}

impl PageDirectory {
    /// Get the status bits for a page mapped into this address space.
    ///
    /// Returns (accessed, dirty).
    #[inline(always)]
    pub fn get_status(&self, vaddr: usize) -> Result<(bool, bool), ::Error> {
        let res = unsafe { seL4_X86_PageDirectory_GetStatusBits(self.cptr, vaddr) };
        if res.error == 0 {
            unsafe {
                let buf = seL4_GetIPCBuffer();
                let accessed = (*buf).msg[0];
                let dirty = (*buf).msg[1];
                Ok((accessed == 1, dirty == 1))
            }
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }
}

impl ::irq::IRQControl {
    /// Create an IRQHandler capability for a message-signalled interrupt (MSI).
    ///
    /// `pci_*` indicate the address of the PCI function that will generate the handled interrupt.
    ///
    /// `handle` is the value programmed into the data portion of the MSI.
    ///
    /// `vector` is the CPU vector the interrupt will be delivered to.
    #[inline(always)]
    pub fn get_msi(&self, slotref: ::SlotRef, pci_bus: seL4_Word, pci_dev: seL4_Word,
                   pci_func: seL4_Word, handle: seL4_Word, vector: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_IRQControl_GetMSI(
            self.to_cap(),
            slotref.root.to_cap(),
            slotref.cptr,
            slotref.depth as seL4_Word,
            pci_bus,
            pci_dev,
            pci_func,
            handle,
            vector,
        ))
    }

    /// Create an IRQHandler capability for an interrupt from an IOAPIC.
    ///
    /// `ioapic` is the zero-based index of the IOAPIC the interrupt will be delivered from, in the
    /// same order as in the ACPI tables.
    ///
    /// `pin` is the IOAPIC pin that generates the interrupt.
    ///
    /// `level_triggered` and `active_low` should be set based on the relevant HW the interrupt is
    /// for.
    ///
    /// `vector` is the CPU vector the interrupt will be delivered on.
    #[inline(always)]
    pub fn get_ioapic(&self, slotref: ::SlotRef, ioapic: seL4_Word, pin: seL4_Word,
                      level_triggered: bool, active_low: bool, vector: seL4_Word)
                      -> ::Result {
        unsafe_as_result!(seL4_IRQControl_GetIOAPIC(
            self.to_cap(),
            slotref.root.to_cap(),
            slotref.cptr,
            slotref.depth as seL4_Word,
            ioapic,
            pin,
            level_triggered as usize,
            active_low as usize,
            vector,
        ))
    }
}
#[cfg(feature = "CONFIG_VTX")]
impl VCPU {
    pub fn set_thread(&self, thread: Thread) -> ::Result {
        unsafe_as_result!(seL4_X86_VCPU_SetTCB(self.cptr, thread.to_cap()))
    }

    pub fn read_vmcs(&self, field: seL4_Word) -> Result<seL4_Word, ::Error> {
        let res = unsafe { seL4_X86_VCPU_ReadVMCS(self.cptr, field) };
        if res.error == 0 {
            Ok(res.value)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }

    pub fn write_vmcs(&self, field: seL4_Word, value: seL4_Word) -> Result<seL4_Word, ::Error> {
        let res = unsafe { seL4_X86_VCPU_WriteVMCS(self.cptr, field, value) };
        if res.error == 0 {
            Ok(res.written)
        } else {
            Err(::Error(::GoOn::CheckIPCBuf { error_code: res.error }))
        }
    }

    pub fn enable_io_port(&self, io_port: IOPort, low: seL4_Word, high: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_X86_VCPU_EnableIOPort(self.cptr, io_port.to_cap(), low, high))
    }

    pub fn disable_io_port(&self, low: seL4_Word, high: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_X86_VCPU_DisableIOPort(self.cptr, low, high))
    }

    // TODO: Why is this &mut?
    pub fn write_registers(&self, regs: &mut seL4_VCPUContext) -> ::Result {
        unsafe_as_result!(seL4_X86_VCPU_WriteRegisters(self.cptr, regs))
    }
}

#[cfg(feature = "CONFIG_VTX")]
impl EPTPDPT {
    /// Map this EPTPDPT into a EPTPML4
    #[inline(always)]
    pub fn map(&self, pml4: EPTPML4, addr: seL4_Word, attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_EPTPDPT_Map(self.cptr, pml4.to_cap(), addr, attr))
    }

    /// Unmap this EPTPDPT from the EPTPML4 it is mapped into
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_EPTPDPT_Unmap(self.cptr))
    }
}

#[cfg(feature = "CONFIG_VTX")]
impl EPTPageDirectory {
    /// Map this EPTPD into a EPTPML4
    #[inline(always)]
    pub fn map(&self, pml4: EPTPML4, addr: seL4_Word, attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_EPTPD_Map(self.cptr, pml4.to_cap(), addr, attr))
    }

    /// Unmap this EPTPD from the EPTPML4 it is mapped into
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_EPTPD_Unmap(self.cptr))
    }
}

#[cfg(feature = "CONFIG_VTX")]
impl EPTPageTable {
    /// Map this EPTPT into a EPTPML4
    #[inline(always)]
    pub fn map(&self, pml4: EPTPML4, addr: seL4_Word, attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_EPTPT_Map(self.cptr, pml4.to_cap(), addr, attr))
    }

    /// Unmap this EPTPT from the EPTPML4 it is mapped into
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_EPTPT_Unmap(self.cptr))
    }
}
