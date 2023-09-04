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

//! Using endpoints for message passing
//!
//! In seL4, message passing is the fundamental primitive upon which the entire system is built.
//! All kernel services are accessed through messages sent to capabilities which the kernel
//! recognizes as belonging to kernel objects. Threads can also use this mechanism to send messages
//! between themselves.
//!
//! Endpoints represent authorization to receive or send messages for a particular queue. These
//! queues do not have a buffer, and act as a rendezvous. That is, senders block until there is a
//! receiver and receivers block until there is a sender - at which point they meet, the message is
//! copied directly from the source to its final destination, and the threads continue execution.
//! Multiple threads can be waiting to send or receive on the same queue. A message is delivered
//! from exactly one sender to exactly one receiver.
//!
//! In addition to being able to send data, capabilities can also be transfered between threads.
//! The endpoint must have the `CanGrant` bit set in its rights. In practice, only one new
//! capability can be transfered at a time - the actual situation is somewhat more complex. Refer
//! to §4.2.2 ("Capability Transfer") of the seL4 Reference Manual. The slot where the received
//! capability will be stored is global state not tied to any particular endpoint.
//!
//! Do note that `Endpoint` does not also attempt to model notification objects, instead leaving
//! that to the `Notification` type.

use sel4_sys::*;

use ToCap;

cap_wrapper!{ ()
    /// An endpoint for message passing
    Endpoint = seL4_EndpointObject |_| 1 << seL4_EndpointBits,
    /// A reply object that holds a reply cap and scheduler context
    Reply = seL4_ReplyObject |_| 1 << seL4_ReplyBits,
}

/// The result of a successful receive.
///
/// Contains "sender information", which is the badge of the endpoint which was invoked to send a
/// message.
///
/// Also contains the decoded message information.
pub struct RecvToken {
    pub badge: seL4_Word,
    pub label: seL4_Word,
    caps_unwrapped: seL4_Word,
    len: seL4_Word,
}

impl RecvToken {
    fn from_raw(sender: seL4_Word, message_info: seL4_MessageInfo) -> RecvToken {
        RecvToken {
            badge: sender,
            label: unsafe { seL4_MessageInfo_get_label(message_info) },
            caps_unwrapped: unsafe { seL4_MessageInfo_get_capsUnwrapped(message_info) },
            len: unsafe { seL4_MessageInfo_get_length(message_info) },
        }
    }

    /// Read out unwrapped capabilities into a slice.
    ///
    /// Returns `Err` if the slice is not at least length `caps_unwrapped`.
    pub fn get_unwrapped_caps(&self, caps: &mut [seL4_Word]) -> Result<(), ()> {
        if caps.len() < seL4_MsgMaxExtraCaps as usize && caps.len() < self.caps_unwrapped{
            return Err(());
        }

        unsafe {
            ::core::intrinsics::copy_nonoverlapping(
                &(*seL4_GetIPCBuffer()).caps_or_badges as *const seL4_Word,
                caps.as_mut_ptr(),
                self.caps_unwrapped,
            )
        }

        Ok(())
    }

    /// Read out message data into a slice.
    ///
    /// Returns `Err` if the slice is not at least length `words_transferred`.
    pub fn get_data(&self, data: &mut [seL4_Word]) -> Result<(), ()> {
        if data.len() < seL4_MsgMaxLength as usize && data.len() < self.len {
            return Err(());
        }

        unsafe {
            ::core::intrinsics::copy_nonoverlapping(
                &(*seL4_GetIPCBuffer()).msg as *const seL4_Word, data.as_mut_ptr(),
                self.len as usize,
            )
        }

        Ok(())

    }

    pub fn caps_unwrapped(&self) -> usize {
        self.caps_unwrapped
    }

    pub fn words_transferred(&self) -> usize {
        self.len
    }
}

macro_rules! send_impls {
    ($name:ident) => {
impl $name {
    /// Send data.
    #[inline(always)]
    pub fn send_data(&self, label: seL4_Word, data: &[seL4_Word]) -> ::Result {
        self.send_message(label, data, &[])
    }

    /// Send a capability.
    #[inline(always)]
    pub fn send_cap<T: ::ToCap>(&self, label: seL4_Word, cap: T) -> ::Result {
        self.send_message(label, &[], &[cap.to_cap()])
    }

    /// Send a message.
    ///
    /// The only failures that can occur are if `data` or `caps` is too long to fit in the IPC
    /// buffer. In this case, `TooMuchData` or `TooManyCaps` will be the error details,
    /// respectively.
    ///
    /// This is `seL4_Send` in its full generality.
    #[inline(always)]
    pub fn send_message(&self, label: seL4_Word, data: &[seL4_Word], caps: &[seL4_CPtr]) -> ::Result {
        if data.len() > seL4_MsgMaxLength as usize {
            return Err(::Error::from_details(::ErrorDetails::TooMuchData));
        }
        if caps.len() > seL4_MsgMaxExtraCaps as usize {
            return Err(::Error::from_details(::ErrorDetails::TooManyCaps));
        }
        unsafe {
            let buf = &mut*(seL4_GetIPCBuffer());
            ::core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buf.msg.as_mut_ptr(),
                data.len(),
            );
            ::core::ptr::copy_nonoverlapping(
                caps.as_ptr(),
                buf.caps_or_badges.as_mut_ptr(),
                caps.len()
            );
            seL4_Send(self.cptr, seL4_MessageInfo_new(label, 0, caps.len(), data.len()));
            Ok(())
        }
    }

    /// Raw send, using data already in the IPC buffer
    #[inline(always)]
    pub fn send(&self, label: seL4_Word, data: seL4_Word, caps: seL4_Word) {
        unsafe {
            seL4_Send(self.cptr, seL4_MessageInfo_new(label, 0, caps, data))
        };
    }

    /// Raw non-blocking send, using data already in the IPC buffer
    #[inline(always)]
    pub fn try_send(&self, label: seL4_Word, data: seL4_Word, caps: seL4_Word) {
        unsafe {
            seL4_NBSend(self.cptr, seL4_MessageInfo_new(label, 0, caps, data))
        };
    }

    /// Try to send a message, returning no indication of failure if the message could not be sent.
    #[inline(always)]
    pub fn try_send_message(&self, label: seL4_Word, data: &[seL4_Word], caps: &[seL4_CPtr]) -> ::Result {
        if data.len() > seL4_MsgMaxLength as usize {
            return Err(::Error::from_details(::ErrorDetails::TooMuchData));
        }
        if caps.len() > seL4_MsgMaxExtraCaps as usize {
            return Err(::Error::from_details(::ErrorDetails::TooManyCaps));
        }
        unsafe {
            let buf = &mut*(seL4_GetIPCBuffer());
            ::core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                buf.msg.as_mut_ptr(),
                data.len(),
            );
            ::core::ptr::copy_nonoverlapping(
                caps.as_ptr(),
                buf.caps_or_badges.as_mut_ptr(),
                caps.len(),
            );
            seL4_NBSend(self.cptr, seL4_MessageInfo_new(label, 0, caps.len(), data.len()));
            Ok(())
        }
    }
}
}}

send_impls!(Endpoint);
send_impls!(Reply);

impl Endpoint {
    /// Block until a message is received. Store reply cap and sched context in reply.
    #[inline(always)]
    pub fn recv(&self, reply: Reply) -> RecvToken {
        let mut sender = 0;
        let msginfo = unsafe { seL4_Recv(self.cptr, &mut sender, reply.to_cap()) };
        RecvToken::from_raw(sender, msginfo)
    }

    /// Block until a message is received. Do not accept a reply cap or sched context.
    #[inline(always)]
    pub fn recv_refuse_reply(&self) -> RecvToken {
        let mut sender = 0;
        let msginfo = unsafe { seL4_Wait(self.cptr, &mut sender) };
        RecvToken::from_raw(sender, msginfo)
    }

    /// Try to receive a message. Store reply cap and sched context in reply.
    ///
    /// If there is no message immediately available in the queue, the badge in `RecvToken` will be
    /// `0`. This is the only way to determine if a message was available.
    #[inline(always)]
    pub fn try_recv(&self, reply: Reply) -> RecvToken {
        let mut sender = 0;
        let msginfo = unsafe { seL4_NBRecv(self.cptr, &mut sender, reply.to_cap()) };
        RecvToken::from_raw(sender, msginfo)
    }

    /// Try to receive a message. Do not accept a reply cap or sched context.
    ///
    /// If there is no message immediately available in the queue, the badge in `RecvToken` will be
    /// `0`. This is the only way to determine if a message was available.
    #[inline(always)]
    pub fn try_recv_refuse_reply(&self) -> RecvToken {
        let mut sender = 0;
        let msginfo = unsafe { seL4_NBWait(self.cptr, &mut sender) };
        RecvToken::from_raw(sender, msginfo)
    }

    /// Raw call, using data already in the IPC buffer
    ///
    /// Returns an error if the reply matches a defined kernel error code.
    ///
    /// CAUTION: There is no way to determine if the error code was sent by the kernel or the ipc
    /// partner.
    #[inline(always)]
    pub fn call(&self, label: seL4_Word, data: seL4_Word, caps: seL4_Word) -> Result<RecvToken, ::Error> {
        let msginfo = unsafe {
            seL4_Call(self.cptr, seL4_MessageInfo_new(label, 0, caps, data))
        };
        let label = unsafe { seL4_MessageInfo_get_label(msginfo) } as seL4_Error;
        if label > 0 && label < seL4_NumErrors {
            Err(::Error::from_ipcbuf(label))
        } else {
            Ok(RecvToken::from_raw(0, msginfo))
        }
    }
}

/// Send a message thru a reply object. If another thread is not waiting for the
/// reply this will block until it gets sent. Then block until a message is received on
/// this endpoint, storing a reply capability and sched context in the same reply
/// object.
///
/// The message must already be in the ipc buffer.
#[inline(always)]
pub fn reply_then_recv(reply: Reply, label: seL4_Word, data: seL4_Word, caps: seL4_Word, recv_on: Endpoint) -> RecvToken {
    let mut sender = 0;
    let msginfo = unsafe { seL4_ReplyRecv(recv_on.to_cap(),
                                 seL4_MessageInfo_new(label, 0, caps, data),
                                 &mut sender,
                                 reply.to_cap()) };
    RecvToken::from_raw(sender, msginfo)
}

/// Try to Send a message thru a reply object. If another thread is not waiting for
/// the reply the message is dropped. Then block until a message is received on
/// an endpoint, storing a reply capability and sched context in the same reply
/// object.
///
/// The message must already be in the ipc buffer.
#[inline(always)]
pub fn try_reply_then_recv(reply: Reply, label: seL4_Word, data: seL4_Word, caps: seL4_Word, recv_on: Endpoint) -> RecvToken {
    raw_try_send_then_recv(reply.to_cap(), label, data, caps, recv_on, reply)
}

/// Try to Send a message thru an endpoint. If another thread is not waiting for
/// the message the message is dropped. Then block until a message is received on
/// an endpoint, storing a reply capability and sched context in reply.
///
/// The message must already be in the ipc buffer.
#[inline(always)]
pub fn try_send_then_recv(send_to: Endpoint, label: seL4_Word, data: seL4_Word, caps: seL4_Word, recv_on: Endpoint, reply: Reply) -> RecvToken {
    raw_try_send_then_recv(send_to.to_cap(), label, data, caps, recv_on, reply)
}

#[inline(always)]
fn raw_try_send_then_recv(send_to: seL4_CPtr, label: seL4_Word, data: seL4_Word, caps: seL4_Word, recv_on: Endpoint, reply: Reply) -> RecvToken {
    let mut sender = 0;
    let msginfo = unsafe { seL4_NBSendRecv(send_to, seL4_MessageInfo_new(label, 0, caps, data),
                                  recv_on.to_cap(), &mut sender, reply.to_cap()) };
    RecvToken::from_raw(sender, msginfo)
}

/// Try to Send a message thru an endpoint. If another thread is not waiting for
/// the message the message is dropped. Then block until a message is received on
/// an endpoint. Do not accept a reply cap or sched context.
///
/// The message must already be in the ipc buffer.
#[inline(always)]
pub fn try_send_then_recv_refuse_reply(send_to: Endpoint, label: seL4_Word, data: seL4_Word, caps: seL4_Word, recv_on: Endpoint) -> RecvToken {
    let mut sender = 0;
    let msginfo = unsafe { seL4_NBSendWait(send_to.to_cap(),
                                  seL4_MessageInfo_new(label, 0, caps, data),
                                  recv_on.to_cap(),
                                  &mut sender) };
    RecvToken::from_raw(sender, msginfo)
}

/// Send a message thru a reply object. If another thread is not waiting for the
/// reply this will block until it gets sent. Then block until a message is received on
/// this endpoint, storing a reply capability and sched context in the same reply
/// object.
#[inline(always)]
pub fn reply_message_then_recv(reply: Reply, label: seL4_Word, data: &[seL4_Word], caps: &[seL4_CPtr], recv_on: Endpoint)
                       -> Result<RecvToken, ::Error> {
    let mut sender = 0;
    let msginfo;
    if data.len() > seL4_MsgMaxLength as usize {
        return Err(::Error::from_details(::ErrorDetails::TooMuchData));
    }
    if caps.len() > seL4_MsgMaxExtraCaps as usize {
        return Err(::Error::from_details(::ErrorDetails::TooManyCaps));
    }
    unsafe {
        let buf = &mut*(seL4_GetIPCBuffer());
        ::core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            buf.msg.as_mut_ptr(),
            data.len(),
        );
        ::core::ptr::copy_nonoverlapping(
            caps.as_ptr(),
            buf.caps_or_badges.as_mut_ptr(),
            caps.len(),
        );

        msginfo = seL4_ReplyRecv(recv_on.to_cap(),
                                 seL4_MessageInfo_new(label, 0, caps.len(), data.len()),
                                 &mut sender,
                                 reply.to_cap());
    }
    Ok(RecvToken::from_raw(sender, msginfo))
}

/// Try to Send a message thru a reply object. If another thread is not waiting for
/// the reply the message is dropped. Then block until a message is received on
/// an endpoint, storing a reply capability and sched context in the same reply
/// object.
#[inline(always)]
pub fn try_reply_message_then_recv(reply_to: Reply, label: seL4_Word, data: &[seL4_Word], caps: &[seL4_CPtr],
                           recv_on: Endpoint)
                           -> Result<RecvToken, ::Error> {
    raw_try_send_message_then_recv(reply_to.to_cap(), label, data, caps, recv_on, reply_to)
}

/// Try to Send a message thru an endpoint. If another thread is not waiting for
/// the message the message is dropped. Then block until a message is received on
/// an endpoint, storing a reply capability and sched context in reply.
#[inline(always)]
pub fn try_send_message_then_recv(send_to: Endpoint, label: seL4_Word, data: &[seL4_Word], caps: &[seL4_CPtr],
                          recv_on: Endpoint, reply: Reply)
                          -> Result<RecvToken, ::Error> {
    raw_try_send_message_then_recv(send_to.to_cap(), label, data, caps, recv_on, reply)
}

#[inline(always)]
fn raw_try_send_message_then_recv(send_to: seL4_CPtr, label: seL4_Word, data: &[seL4_Word], caps: &[seL4_CPtr],
                          recv_on: Endpoint, reply: Reply)  -> Result<RecvToken, ::Error> {
    let mut sender = 0;
    let msginfo;
    if data.len() > seL4_MsgMaxLength as usize {
        return Err(::Error::from_details(::ErrorDetails::TooMuchData));
    }
    if caps.len() > seL4_MsgMaxExtraCaps as usize {
        return Err(::Error::from_details(::ErrorDetails::TooManyCaps));
    }
    unsafe {
        let buf = &mut*(seL4_GetIPCBuffer());
        ::core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            buf.msg.as_mut_ptr(),
            data.len(),
        );
        ::core::ptr::copy_nonoverlapping(
            caps.as_ptr(),
            buf.caps_or_badges.as_mut_ptr(),
            caps.len(),
        );

        msginfo = seL4_NBSendRecv(send_to, seL4_MessageInfo_new(label, 0, caps.len(), data.len()),
                                  recv_on.to_cap(), &mut sender, reply.to_cap());
    }
    Ok(RecvToken::from_raw(sender, msginfo))
}

/// Try to Send a message thru an endpoint. If another thread is not waiting for
/// the message the message is dropped. Then block until a message is received on
/// an endpoint. Do not accept a reply cap or sched context.
#[inline(always)]
pub fn try_send_message_then_recv_refuse_reply(send_to: Endpoint, label: seL4_Word, data: &[seL4_Word], caps: &[seL4_CPtr],
                                       recv_on: Endpoint)  -> Result<RecvToken, ::Error> {
    let mut sender = 0;
    let msginfo;
    if data.len() > seL4_MsgMaxLength as usize {
        return Err(::Error::from_details(::ErrorDetails::TooMuchData));
    }
    if caps.len() > seL4_MsgMaxExtraCaps as usize {
        return Err(::Error::from_details(::ErrorDetails::TooManyCaps));
    }
    unsafe {
        let buf = &mut*(seL4_GetIPCBuffer());
        ::core::ptr::copy_nonoverlapping(
            data.as_ptr(),
            buf.msg.as_mut_ptr(),
            data.len(),
        );
        ::core::ptr::copy_nonoverlapping(
            caps.as_ptr(),
            buf.caps_or_badges.as_mut_ptr(),
            caps.len(),
        );

        msginfo = seL4_NBSendWait(send_to.to_cap(),
                                  seL4_MessageInfo_new(label, 0, caps.len(), data.len()),
                                  recv_on.to_cap(),
                                  &mut sender);
    }
    Ok(RecvToken::from_raw(sender, msginfo))
}
