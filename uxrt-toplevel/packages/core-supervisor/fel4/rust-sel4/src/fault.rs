// Copyright (c) 2018-2022 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright (c) 2017 The Robigalia Project Developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

use sel4_sys::{
               seL4_Word, seL4_GetIPCBuffer,  seL4_GuardMismatch, seL4_Fault_NullFault, seL4_Fault_tag, seL4_Fault_CapFault,
               seL4_Fault_VMFault, seL4_Fault_UnknownSyscall, seL4_Fault_UserException, 
               seL4_Fault_DebugException, seL4_CapFault_IP, seL4_CapFault_Addr, 
               seL4_CapFault_InRecvPhase, seL4_CapFault_LookupFailureType, 
               seL4_CapFault_BitsLeft, seL4_DebugException_BreakpointNumber, 
               seL4_DebugException_TriggerAddress,
               seL4_DebugException_ExceptionReason, seL4_DebugException_FaultIP,
               seL4_DebugException_Length
};

use arch::{UnknownSyscall, UnknownSyscallReply, VMFault, UserException, UserExceptionReply};

use {Endpoint, LookupFailureKind, Reply, RecvToken, try_reply_then_recv};

/// Receive, interpret, and reply to fault messages
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FaultMsg {
    UnknownFault,
    CapFault(CapFaultToken),
    VmFault(VmFaultToken),
    UnknownSyscall(UnknownSyscallToken),
    UserException(UserExceptionToken),
    DebugException(DebugExceptionToken),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DebugException {
    pub fault_ip: seL4_Word,
    pub exception_reason: seL4_Word,
    pub trigger_address: seL4_Word,
    pub breakpoint_number: seL4_Word,
}

impl DebugException {
    pub unsafe fn from_ipcbuf(index: usize) -> (DebugException, usize) {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());
        (
            DebugException {
                fault_ip: ipcbuf.msg[seL4_DebugException_FaultIP as usize],
                exception_reason: ipcbuf.msg[seL4_DebugException_ExceptionReason as usize],
                trigger_address: ipcbuf.msg[seL4_DebugException_TriggerAddress as usize],
                breakpoint_number: ipcbuf.msg[seL4_DebugException_BreakpointNumber as usize],
            },
            index + seL4_DebugException_Length as usize,
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DebugExceptionReply {
    pub num_instructions_skip: seL4_Word,
}

impl DebugExceptionReply {
    pub unsafe fn to_ipcbuf(&self, index: usize) -> usize {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());
        ipcbuf.msg[index] = self.num_instructions_skip;
        index + 1
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CapFault {
    pub ip: seL4_Word,
    pub addr: seL4_Word,
    pub in_recv_phase: seL4_Word,
    pub lookup_failure_type: seL4_Word,
}

impl CapFault {
    pub unsafe fn from_ipcbuf(index: usize) -> (CapFault, usize) {
        let ipcbuf = &mut*(seL4_GetIPCBuffer());

        (
            CapFault {

                ip: ipcbuf.msg[index + seL4_CapFault_IP as usize],
                addr: ipcbuf.msg[index + seL4_CapFault_Addr as usize],
                in_recv_phase: ipcbuf.msg[index + seL4_CapFault_InRecvPhase as usize],
                lookup_failure_type: ipcbuf.msg[index + seL4_CapFault_LookupFailureType as usize],

            },
            index + seL4_CapFault_BitsLeft as usize,
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CapFaultToken {
    pub msg: CapFault,
    pub lookup_failure_kind: Option<LookupFailureKind>,
}

impl CapFaultToken {
    fn from_ipcbuf() -> CapFaultToken {
        let ipcbuf = unsafe { &mut*(seL4_GetIPCBuffer()) };
        let (msg, index) = unsafe { CapFault::from_ipcbuf(0) };
        let lookup_failure_kind;
        if msg.lookup_failure_type <= seL4_GuardMismatch {
            lookup_failure_kind = unsafe { LookupFailureKind::from_ipcbuf(ipcbuf,
                                                                 msg.lookup_failure_type as usize,
                                                                 index as usize) };
        } else {
            lookup_failure_kind = None;
        }
        CapFaultToken {
            msg,
            lookup_failure_kind,
        }
    }

    /// Restart the faulted thread by replying to the message. Does not block.
    pub fn resolve_fault(&self, reply: Reply) {
        reply_to_restart(reply);
    }

    /// Restart the faulted thread by repling to the message. Then, block waiting
    /// for another FaultMsg.
    pub fn resolve_fault_then_recv(&self, reply: Reply, ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
        reply_to_restart_then_recv(reply, ep)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct VmFaultToken {
    pub msg: VMFault,
}

impl VmFaultToken {
    fn from_ipcbuf() -> VmFaultToken {
        VmFaultToken {
            msg: unsafe { VMFault::from_ipcbuf(0).0 },
        }
    }

    /// Restart the faulted thread by replying to the message. Does not block.
    pub fn resolve_fault(&self, reply: Reply) {
        reply_to_restart(reply);
    }

    /// Restart the faulted thread by repling to the message. Then, block waiting
    /// for another FaultMsg.
    pub fn resolve_fault_then_recv(&self, reply: Reply, ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
        reply_to_restart_then_recv(reply, ep)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UnknownSyscallToken {
    pub msg: UnknownSyscall,
}

impl UnknownSyscallToken {
    fn from_ipcbuf() -> UnknownSyscallToken {
        UnknownSyscallToken {
            msg: unsafe { UnknownSyscall::from_ipcbuf(0).0 },
        }
    }

    /// Restart the faulted thread by replying to the message. Does not block.
    ///
    /// `message` optionally Sets the faulting thread's registers before restarting.
    pub fn resolve_fault(&self, reply: Reply, message: Option<UnknownSyscallReply>) {
        reply_message_to_restart(reply, message);
    }

    /// Restart the faulted thread by replying to the message. Then, block waiting
    /// for another FaultMsg.
    ///
    /// `message` optionally sets the faulting thread's registers before restarting.
    pub fn resolve_fault_then_recv(&self, reply: Reply, message: Option<UnknownSyscallReply>, ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
        reply_message_to_restart_then_recv(reply, message, ep)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UserExceptionToken {
    pub msg: UserException,
}

impl UserExceptionToken {
    fn from_ipcbuf() -> UserExceptionToken {
        UserExceptionToken {
            msg: unsafe { UserException::from_ipcbuf(0).0 },
        }
    }

    /// Restart the faulted thread by replying to the message. Does not block.
    ///
    /// `message` optionally sets the faulting thread's instruction pointer, stack pointer,
    /// and flags register before restarting.
    pub fn resolve_fault(&self, reply: Reply, message: Option<UserExceptionReply>) {
        reply_message_to_restart(reply, message);
    }

    /// Restart the faulted thread by replying to the message. Then, block waiting
    /// for another FaultMsg.
    ///
    /// `message` optionally sets the faulting thread's instruction pointer, stack pointer,
    /// and flags register before restarting.
    pub fn resolve_fault_then_recv(&self, reply: Reply, message: Option<UserExceptionReply>, ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
        reply_message_to_restart_then_recv(reply, message, ep)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DebugExceptionToken {
    pub msg: DebugException,
}

impl DebugExceptionToken {
    fn from_ipcbuf() -> DebugExceptionToken {
        DebugExceptionToken {
            msg: unsafe { DebugException::from_ipcbuf(0).0 },
        }
    }

    /// Restart the faulted thread by replying to the message. Does not block.
    ///
    /// `message` optionally sets the number of instructions to skip before restarting the
    /// faulting thread. This is only meaningful when single stepping.
    pub fn resolve_fault(&self, reply: Reply, message: Option<DebugExceptionReply>) {
        reply_message_to_restart(reply, message);
    }

    /// Restart the faulted thread by replying to the message. Then, block waiting
    /// for another FaultMsg.
    ///
    /// `message` optionally sets the number of instructions to skip before restarting the
    /// faulting thread. This is only meaningful when single stepping.
    pub fn resolve_fault_then_recv(&self, reply: Reply, message: Option<DebugExceptionReply>, ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
        reply_message_to_restart_then_recv(reply, message, ep)
    }
}

impl FaultMsg {
    /// Process a received message as a fault message
    pub fn from_recv_token(msg: &RecvToken) -> Option<FaultMsg> {
        let label = msg.label as seL4_Fault_tag;
        if label == seL4_Fault_NullFault {
            None 
        }else if label == seL4_Fault_CapFault {
            Some(FaultMsg::CapFault(CapFaultToken::from_ipcbuf()))
        } else if label == seL4_Fault_VMFault {
            Some(FaultMsg::VmFault(VmFaultToken::from_ipcbuf()))
        } else if label == seL4_Fault_UnknownSyscall {
            Some(FaultMsg::UnknownSyscall(UnknownSyscallToken::from_ipcbuf()))
        } else if label == seL4_Fault_UserException {
            Some(FaultMsg::UserException(UserExceptionToken::from_ipcbuf()))
        } else if label == seL4_Fault_DebugException {
            Some(FaultMsg::DebugException(DebugExceptionToken::from_ipcbuf()))
        } else {
            Some(FaultMsg::UnknownFault)
        }
    }

    /// Receive a message on an endpoint and process it as a fault message
    pub fn recv(ep: Endpoint, reply: Reply) -> (Option<FaultMsg>, RecvToken) {
        let recv_token = ep.recv(reply);
        (FaultMsg::from_recv_token(&recv_token), recv_token)
    }
    /// Receive a message on an endpoint and process it as a fault message
    pub fn recv_refuse_reply(ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
        let recv_token = ep.recv_refuse_reply();
        (FaultMsg::from_recv_token(&recv_token), recv_token)
    }
}

trait FaultReply {
    unsafe fn to_ipcbuf(&self) -> usize;
}

impl FaultReply for UnknownSyscallReply {
    unsafe fn to_ipcbuf(&self) -> usize {
        self.to_ipcbuf(0)
    }
}

impl FaultReply for UserExceptionReply {
    unsafe fn to_ipcbuf(&self) -> usize {
        self.to_ipcbuf(0)
    }
}

impl FaultReply for DebugExceptionReply {
    unsafe fn to_ipcbuf(&self) -> usize {
        self.to_ipcbuf(0)
    }
}

fn reply_to_restart(reply: Reply) {
    reply.try_send(0, 0, 0);
}

fn reply_message_to_restart<T: FaultReply>(reply: Reply, message: Option<T>) {
    let mut len = 0;
    if let Some(m) = message {
        len = unsafe { m.to_ipcbuf() as usize };
    }
    reply.try_send(0, len, 0);
}

fn reply_to_restart_then_recv(reply: Reply, ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
    let recv_token = try_reply_then_recv(reply, 0, 0, 0, ep);
    (FaultMsg::from_recv_token(&recv_token), recv_token)
}

fn reply_message_to_restart_then_recv<T: FaultReply>(reply: Reply, message: Option<T>, ep: Endpoint) -> (Option<FaultMsg>, RecvToken) {
    let mut len = 0;
    if let Some(m) = message {
        len = unsafe { m.to_ipcbuf() as usize };
    }
    let recv_token = try_reply_then_recv(reply, 0, len, 0, ep);
    (FaultMsg::from_recv_token(&recv_token), recv_token)
}
