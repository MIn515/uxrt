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

//! Higher level interfaces to seL4 kernel objects.
//!
//! The intent of this crate is to provide mechanism, not policy, so the general flavour is still
//! very low-level and architecture-specific details are not abstracted over.  However, it should
//! be more convenient than the raw sel4-sys functions and no less performant (once optimized, of
//! course).
//!
//! **Note**: when method documentation says "this", it refers to the receiver of the thread, not
//! any global state.

#![no_std]
#![allow(stable_features, unused_features)]
#![feature(no_std)]

extern crate sel4_sys;
use sel4_sys::{
    seL4_CapNull,
    seL4_GetIPCBuffer, 
    seL4_Yield, 
    seL4_Error,
    seL4_MsgMaxLength,
    seL4_PageBits,
    seL4_WordBits,
};

pub use sel4_sys::{
    seL4_CPtr,
    seL4_UserContext,
    seL4_Word,
};

pub const CAP_NULL: seL4_CPtr = seL4_CapNull;
pub const WORD_BITS: u8 = seL4_WordBits as u8;
pub const PAGE_BITS: u8 = seL4_PageBits as u8;
pub const PAGE_SIZE: usize = 1 << PAGE_BITS;
pub const MSG_MAX_LENGTH: usize = seL4_MsgMaxLength as usize;

///Returns a null SlotRef
#[inline]
pub fn null_slot() -> SlotRef {
	SlotRef::new(CNode::from_cap(CAP_NULL), CAP_NULL, 0)
}

#[cfg(KernelDebugBuild)]
use sel4_sys::{seL4_DebugHalt, seL4_DebugSnapshot};

#[macro_use]
mod macros;

mod alloc;
mod arch;
mod cspace;
mod domain;
mod endpoint;
mod error;
mod irq;
mod notification;
mod thread;
#[cfg(KernelEnableBenchmarks)]
mod benchmark;
mod fault;
mod bootinfo;

pub use alloc::ObjectAllocator;
pub use arch::*;
pub use cspace::{Badge, CNode, CNodeInfo, SlotRef, Window, CapRights, cptr_shl, cptr_shr};
pub use domain::DomainSet;
pub use endpoint::{Endpoint, RecvToken, Reply, reply_then_recv, try_send_then_recv,
                   try_reply_then_recv, try_send_then_recv_refuse_reply, reply_message_then_recv,
                   try_send_message_then_recv, try_reply_message_then_recv,
                   try_send_message_then_recv_refuse_reply};
pub use error::{ErrorDetails, LookupFailureKind};
pub use irq::{IRQControl, IRQHandler};
pub use notification::Notification;
pub use thread::{Breakpoint, BreakpointAccess, SchedContext, SchedControl, Thread,
                 ThreadConfiguration};
#[cfg(KernelEnableBenchmarks)]
pub use benchmark::*;
pub use fault::FaultMsg;
pub use bootinfo::{seL4_BootInfo, BootInfoExtra, BootInfoExtraIter, bootinfo_extras, bootinfo_untyped_descs, available_parallelism};
pub const CONFIG_RETYPE_FAN_OUT_LIMIT: usize = sel4_sys::CONFIG_RETYPE_FAN_OUT_LIMIT as usize;

/// Canonical result type from invoking capabilities.
pub type Result = core::result::Result<(), Error>;

pub trait ToCap {
    /// Unwrap this object into its raw capability pointer.
    fn to_cap(&self) -> seL4_CPtr;
}

pub trait FromCap {
    /// Create an object from a CPtr (intended mostly for use by allocators;
    /// using a CPtr of the wrong type here will create an object that is
    /// completely broken).
    fn from_cap(cptr: seL4_CPtr) -> Self;
}

pub trait FromSlot {
    /// Create an object from a SlotRef; using a SlotRef of the wrong type 
    /// here will create an object that is completely broken).
    fn from_slot(slot: SlotRef) -> Self;
}

pub trait Mappable {
}

pub trait Allocatable {
    /// Allocate an object, using memory from the untyped memory object and storing the capability
    /// into `Window`.
    ///
    /// The number of objects to create is the `num_slots` field on the `Window`.
    fn create(untyped_memory: seL4_CPtr, dest: Window, size_bits: seL4_Word) -> Result;
    fn object_size(size_bits: seL4_Word) -> isize;
    fn object_type() -> usize;
}

impl ToCap for seL4_CPtr {
    #[inline(always)]
    fn to_cap(&self) -> seL4_CPtr {
        *self
    }
}

/// An error occured.
///
/// Since seL4 stores error information in the IPC buffer, and copying that data is not free, to
/// inspect the details of the error you must call `.details()`. The `Debug` implementation will do
/// this automatically, to aid debugging.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Error(pub GoOn);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum GoOn {
    Direct {
        details: Option<ErrorDetails>
    },
    CheckIPCBuf {
        error_code: seL4_Error
    },
}

impl Error {
    #[inline]
    pub fn from_details(details: ErrorDetails) -> Error {
        Error(GoOn::Direct { details: Some(details) })
    }
    #[inline]
    pub fn from_details_opt(details: Option<ErrorDetails>) -> Error {
        Error(GoOn::Direct { details })
    }
    #[inline]
    pub fn from_ipcbuf(error_code: seL4_Error) -> Self{
        Error(GoOn::CheckIPCBuf { error_code })
    }                                                                        
    #[inline]
    pub fn copy_from_ipcbuf(error_code: seL4_Error) -> Self{
        let ipcbuf_err = Self::from_ipcbuf(error_code); 
        Error(GoOn::Direct { details: ipcbuf_err.details() })
    }
    #[inline]
    pub fn copy_from_err(err: Error) -> Self{
        Error(GoOn::Direct { details: err.details() })
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if let Some(deets) = self.details() {
            write!(f, "{:?} ({})", deets, deets)
        }else{
            write!(f, "no error")
        }
    }
}

/// Sets the (thread-local) destination for capability transfer to the given slot.
pub fn set_cap_destination(slot: SlotRef) {
    unsafe {
        let buf = seL4_GetIPCBuffer();
        (*buf).receiveCNode = slot.root.to_cap();
        (*buf).receiveIndex = slot.cptr;
        (*buf).receiveDepth = slot.depth as seL4_Word;
    }
}

/// Gets the current (thread-local) capability transfer destination.
pub fn get_cap_destination() -> SlotRef {
    unsafe {
        let buf = seL4_GetIPCBuffer();
        SlotRef::new(CNode::from_cap(
            (*buf).receiveCNode),
            (*buf).receiveIndex,
            (*buf).receiveDepth as u8,
        )
    }
}

/// Yield the remainder of the current timeslice back to the scheduler.
#[inline(always)]
pub fn yield_now() {
    unsafe {
        seL4_Yield();
    }
}

/// Halt the system. The kernel will stop responding to system calls and switch
/// to the idle thread with interrupts disabled and may switch to a low-power state.
///
/// Only available when KernelDebugBuild is set.
#[cfg(KernelDebugBuild)]
#[inline(always)]
pub fn halt_now() {
    unsafe { seL4_DebugHalt() };
}

/// Output a capDL dump of current kernel state using the kernel serial driver
///
/// Only available when KernelDebugBuild is set.
#[cfg(KernelDebugBuild)]
#[inline(always)]
pub fn debug_snapshot() {
    unsafe { seL4_DebugSnapshot() };
}

/// A handle for using core::fmt with seL4_DebugPutChar
pub struct DebugOutHandle;

impl ::core::fmt::Write for DebugOutHandle {
    fn write_str(&mut self, s: &str) -> ::core::fmt::Result {
        for &b in s.as_bytes() {
            unsafe { sel4_sys::seL4_DebugPutChar(b as i8) };
        }
        Ok(())
    }
}


pub mod raw {
    use sel4_sys::*;
    pub use sel4_sys::seL4_Error;
    pub fn untyped_retype(service: seL4_Untyped, type_: usize, size_bits: usize, root: seL4_CNode, node_index: seL4_CPtr, node_depth: u8, node_offset: usize, num_objects: usize) -> seL4_Error {
        #[cfg(feature = "debug_utspace")]
        println!("untyped_retype: service: {:x} type: {} size_bits: {} root: {:x} node_index: {:x} node_depth: {} node_offset: {:x} num_objects: {}", service, type_, size_bits, root, node_index, node_depth, node_offset, num_objects);
        unsafe { sel4_sys::seL4_Untyped_Retype(service, type_ as seL4_Word, size_bits as seL4_Word, root, node_index as seL4_Word, node_depth as seL4_Word, node_offset as seL4_Word, num_objects as seL4_Word) }
    }
}

pub fn get_object_size(objtype: u32, size_bits: usize) -> Option<isize> {
    match objtype {
        sel4_sys::seL4_UntypedObject => { Some(1 << size_bits) },
        sel4_sys::seL4_TCBObject => { Some(Thread::object_size(size_bits)) },
        sel4_sys::seL4_EndpointObject => { Some(Endpoint::object_size(size_bits)) },
        sel4_sys::seL4_NotificationObject => { Some(Notification::object_size(size_bits)) },
        sel4_sys::seL4_CapTableObject => { Some(CNode::object_size(size_bits)) },
        sel4_sys::seL4_SchedContextObject => { Some(SchedContext::object_size(size_bits)) },
        sel4_sys::seL4_ReplyObject => { Some(Reply::object_size(size_bits)) },
        _ => { arch::arch_get_object_size(objtype, size_bits) }
    }
}
