#![no_std]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![feature(thread_local)]

// Allow std in tests                                                         
#[cfg(test)]                                                                  
#[macro_use]                                                                  
extern crate std;   

extern crate rlibc;

mod compile_time_assertions;

mod lib_base;
pub use lib_base::*;

pub mod tls;

pub const seL4_CapNull: seL4_Word = lib_base::seL4_CapNull as seL4_Word;  
pub const seL4_CapInitThreadTCB: seL4_Word = lib_base::seL4_CapInitThreadTCB as seL4_Word;
pub const seL4_CapInitThreadCNode: seL4_Word = lib_base::seL4_CapInitThreadCNode as seL4_Word;
pub const seL4_CapInitThreadVSpace: seL4_Word = lib_base::seL4_CapInitThreadVSpace as seL4_Word;
pub const seL4_CapIRQControl: seL4_Word = lib_base::seL4_CapIRQControl as seL4_Word;
pub const seL4_CapASIDControl: seL4_Word = lib_base::seL4_CapASIDControl as seL4_Word;
pub const seL4_CapInitThreadASIDPool: seL4_Word = lib_base::seL4_CapInitThreadASIDPool as seL4_Word;
pub const seL4_CapIOPortControl: seL4_Word = lib_base::seL4_CapIOPortControl as seL4_Word;
pub const seL4_CapIOSpace: seL4_Word = lib_base::seL4_CapIOSpace as seL4_Word;
pub const seL4_CapBootInfoFrame: seL4_Word = lib_base::seL4_CapBootInfoFrame as seL4_Word;
pub const seL4_CapInitThreadIPCBuffer: seL4_Word = lib_base::seL4_CapInitThreadIPCBuffer as seL4_Word;
pub const seL4_CapDomain: seL4_Word = lib_base::seL4_CapDomain as seL4_Word;
pub const seL4_CapInitThreadSC: seL4_Word = lib_base::seL4_CapInitThreadSC as seL4_Word;
pub const seL4_NumInitialCaps: seL4_Word = lib_base::seL4_NumInitialCaps as seL4_Word;

pub type seL4_LookupFailureType = usize;
pub const seL4_NoFailure: seL4_LookupFailureType = lib_base::seL4_NoFailure as seL4_LookupFailureType;
pub const seL4_InvalidRoot: seL4_LookupFailureType = lib_base::seL4_InvalidRoot as seL4_LookupFailureType;
pub const seL4_MissingCapability: seL4_LookupFailureType = lib_base::seL4_MissingCapability as seL4_LookupFailureType;
pub const seL4_DepthMismatch: seL4_LookupFailureType = lib_base::seL4_DepthMismatch as seL4_LookupFailureType;
pub const seL4_GuardMismatch: seL4_LookupFailureType = lib_base::seL4_GuardMismatch as seL4_LookupFailureType;

pub type seL4_BreakpointType = usize;
pub const seL4_DataBreakpoint: seL4_BreakpointType = lib_base::seL4_DataBreakpoint as seL4_BreakpointType;
pub const seL4_InstructionBreakpoint: seL4_BreakpointType = lib_base::seL4_InstructionBreakpoint as seL4_BreakpointType;
pub const seL4_SingleStep: seL4_BreakpointType = lib_base::seL4_SingleStep as seL4_BreakpointType;
pub const seL4_SoftwareBreakRequest: seL4_BreakpointType = lib_base::seL4_SoftwareBreakRequest as seL4_BreakpointType;

pub type seL4_BreakpointAccess = usize;
pub const seL4_BreakOnRead: seL4_BreakpointAccess = lib_base::seL4_BreakOnRead as seL4_BreakpointAccess;
pub const seL4_BreakOnWrite: seL4_BreakpointAccess = lib_base::seL4_BreakOnWrite as seL4_BreakpointAccess;
pub const seL4_BreakOnReadWrite: seL4_BreakpointAccess = lib_base::seL4_BreakOnReadWrite as seL4_BreakpointAccess;
pub const seL4_MaxBreakpointAccess: seL4_BreakpointAccess = lib_base::seL4_MaxBreakpointAccess as seL4_BreakpointAccess;

pub const seL4_MsgMaxExtraCaps: c_types::c_ulong = (1<<(lib_base::seL4_MsgExtraCapBits))-1;

pub unsafe fn seL4_MessageInfo_new(label: seL4_Word, capsUnwrapped: seL4_Word, extraCaps: seL4_Word, length: seL4_Word) -> seL4_MessageInfo_t
{
    lib_base::seL4_MessageInfo_new(label as seL4_RawWord, capsUnwrapped as seL4_RawWord, extraCaps as seL4_RawWord, length as seL4_RawWord)
}

pub unsafe fn seL4_CapRights_new(capAllowGrantReply: seL4_Word, capAllowGrant: seL4_Word, capAllowRead: seL4_Word, capAllowWrite: seL4_Word) -> seL4_CapRights_t
{
    lib_base::seL4_CapRights_new(capAllowGrantReply as seL4_RawWord, capAllowGrant as seL4_RawWord, capAllowRead as seL4_RawWord, capAllowWrite as seL4_RawWord)
}

pub unsafe fn seL4_CapRights_set_capAllowGrant(seL4_CapRights: seL4_CapRights_t, allowGrant: seL4_Word) -> seL4_CapRights_t
{
    lib_base::seL4_CapRights_set_capAllowGrant(seL4_CapRights, allowGrant as seL4_RawWord)
}

pub unsafe fn seL4_CapRights_set_capAllowRead(seL4_CapRights: seL4_CapRights_t, allowRead: seL4_Word) -> seL4_CapRights_t
{
    lib_base::seL4_CapRights_set_capAllowRead(seL4_CapRights, allowRead as seL4_RawWord)
}

pub unsafe fn seL4_CapRights_set_capAllowWrite(seL4_CapRights: seL4_CapRights_t, allowWrite: seL4_Word) -> seL4_CapRights_t
{
    lib_base::seL4_CapRights_set_capAllowWrite(seL4_CapRights, allowWrite as seL4_RawWord)
}


pub unsafe fn seL4_CapRights_get_capAllowGrant(seL4_CapRights: seL4_CapRights_t) -> seL4_Word
{
    lib_base::seL4_CapRights_get_capAllowGrant(seL4_CapRights) as seL4_Word
}

pub unsafe fn seL4_CapRights_get_capAllowRead(seL4_CapRights: seL4_CapRights_t) -> seL4_Word
{
    lib_base::seL4_CapRights_get_capAllowRead(seL4_CapRights) as seL4_Word
}

pub unsafe fn seL4_CapRights_get_capAllowWrite(seL4_CapRights: seL4_CapRights_t) -> seL4_Word
{
    lib_base::seL4_CapRights_get_capAllowWrite(seL4_CapRights) as seL4_Word
}

pub unsafe fn seL4_MessageInfo_get_label(message_info: seL4_MessageInfo_t) -> seL4_Word
{
    lib_base::seL4_MessageInfo_get_label(message_info) as seL4_Word
}

pub unsafe fn seL4_MessageInfo_get_capsUnwrapped(message_info: seL4_MessageInfo_t) -> seL4_Word
{
    lib_base::seL4_MessageInfo_get_capsUnwrapped(message_info) as seL4_Word
}

pub unsafe fn seL4_MessageInfo_get_length(message_info: seL4_MessageInfo_t) -> seL4_Word
{
    lib_base::seL4_MessageInfo_get_length(message_info) as seL4_Word
}


