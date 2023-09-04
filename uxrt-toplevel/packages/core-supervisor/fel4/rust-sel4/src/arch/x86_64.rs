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

pub use sel4_sys::{seL4_X86_4K, seL4_X86_LargePageObject, 
    seL4_X86_PageTableObject, seL4_X86_PageDirectoryObject, seL4_X86_PDPTObject,
    seL4_X64_PML4Object, seL4_X64_HugePageObject};

use sel4_sys::*;

pub const MAX_ADDRESS_BITS: usize = 57;

use Allocatable;
use ToCap;
use Mappable;

cap_wrapper!{ ()
    /// Authority to create ASID pools
    ASIDControl,
    /// Authority to create page directories
    ASIDPool,
    /// Authority to use port-IO
    IOPort,
    /// Authority to map IO page tables into a device's address space
    IOSpace,

    /// A page directory pointer table, which holds page directories
    PDPT = seL4_X86_PDPTObject |_| 1 << seL4_PDPTBits,
    /// A page map level 4, which holds PDPTs
    PML4 = seL4_X64_PML4Object |_| 1 << seL4_PML4Bits,
    /// A (4K) page of physical memory that can be mapped into a vspace
    Page = seL4_X86_4K |_| 1 << seL4_PageBits,
    /// A large (2M) page of physical memory that can be mapped into a vspace
    LargePage = seL4_X86_LargePageObject |_| 1 << seL4_LargePageBits,
    /// A page table, which can have pages mapped into it
    PageTable = seL4_X86_PageTableObject |_| 1 << seL4_PageTableBits,
    /// A page directory, which holds page tables
    PageDirectory = seL4_X86_PageDirectoryObject |_| 1 << seL4_PageDirBits,
}

impl Mappable for Page {}
impl Mappable for LargePage {}

#[cfg(KernelHugePage)]
cap_wrapper!{ ()
    /// A huge (1G) page of physical memory that can be mapped into a vspace
    HugePage = seL4_X64_HugePageObject |_| 1 << seL4_HugePageBits,
}

#[cfg(KernelHugePage)]
impl Mappable for HugePage {}

#[cfg(KernelIOMMU)]
cap_wrapper!{ ()
    /// A page table for the IOMMU
    IOPageTable = seL4_X86_IOPageTableObject |_| 1 << seL4_IOPageTableBits,
}

#[cfg(KernelVTX)]
cap_wrapper!{ ()
    /// A virtual CPU, for virtualization
    VCPU = seL4_X86_VCPUObject |_| 1 << seL4_VCPUBits,
    /// Extended page table (virt) PML4
    EPTPML4 = seL4_X86_EPTPML4Object |_| 1 << seL4_X86_EPTPML4Bits,
    /// Extended page table (virt) PDPT
    EPTPDPT = seL4_X86_EPTPDPTObject |_| 1 << seL4_X86_EPTPDPTBits,
    /// Extended page table (virt) PageDirectory
    EPTPageDirectory = seL4_X86_EPTPDObject |_| 1 << seL4_X86_EPTPDBits,
    /// Extended page table (virt) PageTable
    EPTPageTable = seL4_X86_EPTPTObject |_| 1 << seL4_X86_EPTPTBits,
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
    pub fn assign(&self, vroot: PML4) -> ::Result {
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
            Err(::Error::from_ipcbuf(res.error as seL4_Error))
        }
    }

    /// Read 16 bits from the given port.
    #[inline(always)]
    pub fn read16(&self, port: u16) -> Result<u16, ::Error> {
        let res = unsafe { seL4_X86_IOPort_In16(self.cptr, port) };
        if res.error == 0 {
            Ok(res.result)
        } else {
            Err(::Error::from_ipcbuf(res.error as seL4_Error))
        }
    }

    /// Read 32 bits from the given port.
    #[inline(always)]
    pub fn read32(&self, port: u16) -> Result<u32, ::Error> {
        let res = unsafe { seL4_X86_IOPort_In32(self.cptr, port) };
        if res.error == 0 {
            Ok(res.result)
        } else {
            Err(::Error::from_ipcbuf(res.error as seL4_Error))
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

#[cfg(KernelIOMMU)]
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
    #[cfg(KernelVTX)]
    #[inline(always)]
    pub fn map_ept(&self, vroot: EPTPML4, addr: seL4_Word, rights: seL4_CapRights,
                   attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_Page_MapEPT(self.cptr, vroot.to_cap(), addr, rights, attr))
    }

    /// Map this page into an IOSpace with `rights` at `addr`.
    #[cfg(KernelIOMMU)]
    #[inline(always)]
    pub fn map_io(&self, iospace: IOSpace, rights: seL4_CapRights, addr: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_X86_Page_MapIO(self.cptr, iospace.to_cap(), rights, addr))
    }

    /// Map this page into an address space.
    #[inline(always)]
    pub fn map(&self, pml4: PML4, addr: seL4_Word, rights: seL4_CapRights,
               attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_Page_Map(self.cptr, pml4.to_cap(), addr, rights, attr))
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
            Err(::Error::from_ipcbuf(res.error as seL4_Error))
        }
    }
}
}}

page_impls!(Page);
page_impls!(LargePage);
#[cfg(KernelHugePage)]
page_impls!(HugePage);

impl PageTable {
    /// Map this page table into an address space.
    #[inline(always)]
    pub fn map(&self, pml4: PML4, addr: seL4_Word, attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_PageTable_Map(self.cptr, pml4.to_cap(), addr, attr))
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
    //#[inline(always)]
    //TODO: add support for this or an equivalent to the kernel on x86_64 as it 
    //will very likely be necessary for decent performance (trapping accesses
    //just to determine when pages are read/written would add significant
    //overhead in an OS with full paging support)
    //pub fn get_status(&self, vaddr: usize) -> Result<(bool, bool), ::Error> {
    //    let res = unsafe { seL4_X86_PageDirectory_GetStatusBits(self.cptr, vaddr) };
    //    if res.error == 0 {
    //        unsafe {
    //            let buf = seL4_GetIPCBuffer();
    //            let accessed = (*buf).msg[0];
    //            let dirty = (*buf).msg[1];
    //            Ok((accessed == 1, dirty == 1))
    //        }
    //    } else {
    //        Err(::Error::from_ipcbuf(res.error))
    //    }
    //}

    /// Map this page directory into a PML4
    #[inline(always)]
    pub fn map(&self, pml4: PML4, addr: seL4_Word, attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_PageDirectory_Map(self.cptr, pml4.to_cap(), addr, attr))
    }

    /// Unmap this page directory from the PML4 it is mapped into
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_PageDirectory_Unmap(self.cptr))
    }
}

impl PDPT {
    /// Map this PDPT into a PML4
    #[inline(always)]
    pub fn map(&self, pml4: PML4, addr: seL4_Word, attr: seL4_X86_VMAttributes) -> ::Result {
        unsafe_as_result!(seL4_X86_PDPT_Map(self.cptr, pml4.to_cap(), addr, attr))
    }

    /// Unmap this PDPT from the PML4 it is mapped into
    #[inline(always)]
    pub fn unmap(&self) -> ::Result {
        unsafe_as_result!(seL4_X86_PDPT_Unmap(self.cptr))
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
            slotref.depth,
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
            slotref.depth,
            ioapic,
            pin,
            if level_triggered { 0 } else { 1 },
            if active_low { 0 } else { 1 },
            vector,
        ))
    }
}

#[cfg(KernelVTX)]
use Thread;

#[cfg(KernelVTX)]
impl VCPU {
    pub fn set_thread(&self, thread: Thread) -> ::Result {
        unsafe_as_result!(seL4_X86_VCPU_SetTCB(self.cptr, thread.to_cap()))
    }

    pub fn read_vmcs(&self, field: seL4_Word) -> Result<seL4_Word, ::Error> {
        let res = unsafe { seL4_X86_VCPU_ReadVMCS(self.cptr, field) };
        if res.error == 0 {
            Ok(res.value)
        } else {
            Err(::Error::from_ipcbuf(res.error))
        }
    }

    pub fn write_vmcs(&self, field: seL4_Word, value: seL4_Word) -> Result<seL4_Word, ::Error> {
        let res = unsafe { seL4_X86_VCPU_WriteVMCS(self.cptr, field, value) };
        if res.error == 0 {
            Ok(res.written)
        } else {
            Err(::Error::from_ipcbuf(res.error))
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

#[cfg(KernelVTX)]
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

#[cfg(KernelVTX)]
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

#[cfg(KernelVTX)]
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VMFault {
    pub ip: seL4_Word,
    pub addr: seL4_Word,
    pub prefetch_fault: seL4_Word,
    pub fsr: seL4_Word,
}

impl VMFault {
    pub unsafe fn from_ipcbuf(index: usize) -> (VMFault, usize) {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());
        (
            VMFault {
                ip: ipcbuf.msg[index + seL4_VMFault_IP as usize],
                addr: ipcbuf.msg[index + seL4_VMFault_Addr as usize],
                prefetch_fault: ipcbuf.msg[index + seL4_VMFault_PrefetchFault as usize],
                fsr: ipcbuf.msg[index + seL4_VMFault_FSR as usize],
            },
            index + seL4_VMFault_FSR as usize,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownSyscall {
    pub rax: seL4_Word,
    pub rbx: seL4_Word,
    pub rcx: seL4_Word,
    pub rdx: seL4_Word,
    pub rsi: seL4_Word,
    pub rdi: seL4_Word,
    pub rbp: seL4_Word,
    pub r8: seL4_Word,
    pub r9: seL4_Word,
    pub r10: seL4_Word,
    pub r11: seL4_Word,
    pub r12: seL4_Word,
    pub r13: seL4_Word,
    pub r14: seL4_Word,
    pub r15: seL4_Word,
    pub fault_ip: seL4_Word,
    pub sp: seL4_Word,
    pub flags: seL4_Word,
    pub syscall: seL4_Word,
}

impl UnknownSyscall {
    pub unsafe fn from_ipcbuf(index: usize) -> (UnknownSyscall, usize) {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());
        (
            UnknownSyscall {
                rax: ipcbuf.msg[index + seL4_UnknownSyscall_RAX as usize],
                rbx: ipcbuf.msg[index + seL4_UnknownSyscall_RBX as usize],
                rcx: ipcbuf.msg[index + seL4_UnknownSyscall_RCX as usize],
                rdx: ipcbuf.msg[index + seL4_UnknownSyscall_RDX as usize],
                rsi: ipcbuf.msg[index + seL4_UnknownSyscall_RSI as usize],
                rdi: ipcbuf.msg[index + seL4_UnknownSyscall_RDI as usize],
                rbp: ipcbuf.msg[index + seL4_UnknownSyscall_RBP as usize],
                r8: ipcbuf.msg[index + seL4_UnknownSyscall_R8 as usize],
                r9: ipcbuf.msg[index + seL4_UnknownSyscall_R9 as usize],
                r10: ipcbuf.msg[index + seL4_UnknownSyscall_R10 as usize],
                r11: ipcbuf.msg[index + seL4_UnknownSyscall_R11 as usize],
                r12: ipcbuf.msg[index + seL4_UnknownSyscall_R12 as usize],
                r13: ipcbuf.msg[index + seL4_UnknownSyscall_R13 as usize],
                r14: ipcbuf.msg[index + seL4_UnknownSyscall_R14 as usize],
                r15: ipcbuf.msg[index + seL4_UnknownSyscall_R15 as usize],
                fault_ip: ipcbuf.msg[index + seL4_UnknownSyscall_FaultIP as usize],
                sp: ipcbuf.msg[index + seL4_UnknownSyscall_SP as usize],
                flags: ipcbuf.msg[index + seL4_UnknownSyscall_FLAGS as usize],
                syscall: ipcbuf.msg[index + seL4_UnknownSyscall_Syscall as usize],
            },
            index + seL4_UnknownSyscall_Length as usize,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownSyscallReply {
    pub rax: seL4_Word,
    pub rbx: seL4_Word,
    pub rcx: seL4_Word,
    pub rdx: seL4_Word,
    pub rsi: seL4_Word,
    pub rdi: seL4_Word,
    pub rbp: seL4_Word,
    pub r8: seL4_Word,
    pub r9: seL4_Word,
    pub r10: seL4_Word,
    pub r11: seL4_Word,
    pub r12: seL4_Word,
    pub r13: seL4_Word,
    pub r14: seL4_Word,
    pub r15: seL4_Word,
    pub rip: seL4_Word,
    pub rsp: seL4_Word,
    pub rflags: seL4_Word,
}

impl UnknownSyscallReply {
    pub unsafe fn to_ipcbuf(&self, index: usize) -> usize {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());
        ipcbuf.msg[index + seL4_UnknownSyscall_RAX as usize] = self.rax;
        ipcbuf.msg[index + seL4_UnknownSyscall_RBX as usize] = self.rbx;
        ipcbuf.msg[index + seL4_UnknownSyscall_RCX as usize] = self.rcx;
        ipcbuf.msg[index + seL4_UnknownSyscall_RDX as usize] = self.rdx;
        ipcbuf.msg[index + seL4_UnknownSyscall_RSI as usize] = self.rsi;
        ipcbuf.msg[index + seL4_UnknownSyscall_RDI as usize] = self.rdi;
        ipcbuf.msg[index + seL4_UnknownSyscall_RBP as usize] = self.rbp;
        ipcbuf.msg[index + seL4_UnknownSyscall_R8 as usize] = self.r8;
        ipcbuf.msg[index + seL4_UnknownSyscall_R9 as usize] = self.r9;
        ipcbuf.msg[index + seL4_UnknownSyscall_R10 as usize] = self.r10;
        ipcbuf.msg[index + seL4_UnknownSyscall_R11 as usize] = self.r11;
        ipcbuf.msg[index + seL4_UnknownSyscall_R12 as usize] = self.r12;
        ipcbuf.msg[index + seL4_UnknownSyscall_R13 as usize] = self.r13;
        ipcbuf.msg[index + seL4_UnknownSyscall_R14 as usize] = self.r14;
        ipcbuf.msg[index + seL4_UnknownSyscall_R15 as usize] = self.r15;
        ipcbuf.msg[index + seL4_UnknownSyscall_FaultIP as usize] = self.rip;
        ipcbuf.msg[index + seL4_UnknownSyscall_SP as usize] = self.rsp;
        ipcbuf.msg[index + seL4_UnknownSyscall_FLAGS as usize] = self.rflags;
        index + 18
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserException {
    pub fault_ip: seL4_Word,
    pub sp: seL4_Word,
    pub flags: seL4_Word,
    pub number: seL4_Word,
    pub code: seL4_Word,
}

impl UserException {
    pub unsafe fn from_ipcbuf(index: usize) -> (UserException, usize) {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());
        (
            UserException {
                fault_ip: ipcbuf.msg[index + seL4_UserException_FaultIP as usize],
                sp: ipcbuf.msg[index + seL4_UserException_SP as usize],
                flags: ipcbuf.msg[index + seL4_UserException_FLAGS as usize],
                number: ipcbuf.msg[index + seL4_UserException_Number as usize],
                code: ipcbuf.msg[index + seL4_UserException_Code as usize],
            },
            index + seL4_UserException_Length as usize,
        )
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserExceptionReply {
    pub rip: seL4_Word,
    pub rsp: seL4_Word,
    pub rflags: seL4_Word,
}

impl UserExceptionReply {
    pub unsafe fn to_ipcbuf(&self, index: usize) -> usize {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());
        ipcbuf.msg[index + seL4_UserException_FaultIP as usize] = self.rip;
        ipcbuf.msg[index + seL4_UserException_SP as usize] = self.rsp;
        ipcbuf.msg[index + seL4_UserException_FLAGS as usize] = self.rflags;
        index + 3
    }
}

pub mod arch_raw {
    use sel4_sys::*;
    use cspace::CapRights;
    pub type GuardVal = u64;

    pub fn pdpt_map(_service: seL4_CPtr, vspace: seL4_CPtr, vaddr: usize, attr: seL4_X86_VMAttributes) -> seL4_Error {
        unsafe { seL4_X86_PDPT_Map(_service as seL4_X86_PDPT, vspace, vaddr as seL4_Word, attr) as seL4_Error }
    }

    pub fn pdpt_unmap(_service: seL4_CPtr) -> seL4_Error {
        unsafe { seL4_X86_PDPT_Unmap(_service as seL4_X86_PDPT) as seL4_Error }
    }

    pub fn page_directory_map(_service: seL4_CPtr, vspace: seL4_CPtr, vaddr: usize, attr: seL4_X86_VMAttributes) -> seL4_Error {
        unsafe { seL4_X86_PageDirectory_Map(_service as seL4_X86_PageDirectory, vspace, vaddr as seL4_Word, attr) as seL4_Error }
    }

    pub fn page_directory_unmap(_service: seL4_CPtr) -> seL4_Error {
        unsafe { seL4_X86_PageDirectory_Unmap(_service as seL4_X86_PageDirectory) as seL4_Error }
    }

    pub fn page_table_map(_service: seL4_CPtr, vspace: seL4_CPtr, vaddr: usize, attr: seL4_X86_VMAttributes) -> seL4_Error {
        unsafe { seL4_X86_PageTable_Map(_service as seL4_X86_PageTable, vspace, vaddr as seL4_Word, attr) as seL4_Error }
    }

    pub fn page_table_unmap(_service: seL4_CPtr) -> seL4_Error {
        unsafe { seL4_X86_PageTable_Unmap(_service as seL4_X86_PageTable) as seL4_Error }
    }

    pub fn page_map(_service: seL4_CPtr, vspace: seL4_CPtr, vaddr: usize, rights: CapRights, attr: seL4_X86_VMAttributes) -> seL4_Error {
        unsafe { seL4_X86_Page_Map(_service as seL4_X86_Page, vspace, vaddr as seL4_Word, rights.to_raw(), attr) as seL4_Error }
    }

    pub fn page_unmap(_service: seL4_CPtr) -> seL4_Error {
        unsafe { seL4_X86_Page_Unmap(_service as seL4_X86_Page) as seL4_Error }
    }
    pub fn encode_guard_data(value: seL4_Word, size: u8) -> seL4_CNode_CapData_t {
        unsafe { seL4_CNode_CapData_new(value as u64, size.into()) }
    }
}

pub fn arch_get_object_size(objtype: u32, size_bits: usize) -> Option<isize> {
    match objtype {
        sel4_sys::seL4_X86_PDPTObject => { Some(PDPT::object_size(size_bits)) },
        sel4_sys::seL4_X64_PML4Object => { Some(PML4::object_size(size_bits)) },
        sel4_sys::seL4_X86_4K => { Some(Page::object_size(size_bits)) },
        sel4_sys::seL4_X86_LargePageObject => { Some(LargePage::object_size(size_bits)) },

        sel4_sys::seL4_X86_PageTableObject => { Some(PageTable::object_size(size_bits)) },
        sel4_sys::seL4_X86_PageDirectoryObject => { Some(PageDirectory::object_size(size_bits)) },
        #[cfg(KernelHugePage)]
        sel4_sys::seL4_X86_HugePageObject => { Some(HugePage::object_size(size_bits)) },
        #[cfg(KernelIOMMU)]
        sel4_sys::seL4_X86_IOPageTableObject => { Some(IOPageTable::object_size(size_bits)) },
        #[cfg(KernelVTX)]
        sel4_sys::seL4_X86_VCPUObject => { Some(VCPU::object_size(size_bits)) },
        #[cfg(KernelVTX)]
        sel4_sys::seL4_X86_EPTML4Object => { Some(EPTPML4::object_size(size_bits)) },
        #[cfg(KernelVTX)]
        sel4_sys::seL4_X86_EPTPDPTObject => { Some(EPTPDPT::object_size(size_bits)) },
        #[cfg(KernelVTX)]
        sel4_sys::seL4_X86_EPTPDObject => { Some(EPTPageDirectory::object_size(size_bits)) },
        #[cfg(KernelVTX)]
        sel4_sys::seL4_X86_EPTPTObject => { Some(EPTPageTable::object_size(size_bits)) },
        _ => { None }
    }
}
