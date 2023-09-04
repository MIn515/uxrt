// Copyright 2022-2023 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//#![doc(html_root_url = "https://doc.robigalia.org/")]
#![no_std]

#![feature(thread_local)]

#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

#[macro_use]
extern crate enum_primitive_derive;
extern crate num_traits;

extern crate sel4;
extern crate sel4_sys;

extern crate usync;

extern crate intrusive_collections;

extern crate static_assertions;

mod client;
mod notification;
mod server;

use client::{
	BaseClientFileDescriptor,
	ClientClunkFileDescriptor,
};
pub use client::ClientFileDescriptorState;

use notification::BaseNotificationFileDescriptor;

pub use notification::{
	NOTIFICATION_MSG_SIZE,
	NotificationFileDescriptorState,
};

use server::{
	BaseServerFileDescriptor,
	ServerClunkFileDescriptor,
};
pub use server::{
	MsgStatus,
	SECONDARY_BUFFER_ALIGN,
	SecondaryBufferInfo,
	ServerFileDescriptorState,
	set_secondary_buffers,
};

use core::slice;
use core::ops::{Deref, DerefMut, Index, IndexMut};
use core::mem::size_of;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::marker::PhantomData;
use sel4::{
	Endpoint,
	Notification,
	PAGE_SIZE,
	Reply,
	ToCap,
};

use sel4_sys::{
	seL4_GetIPCBuffer,
	seL4_MsgMaxLength,
};

use intrusive_collections::UnsafeRef;

use static_assertions::const_assert;

#[macro_export]
macro_rules! debug_println {
	($($toks:tt)*) => ({
		#[cfg(feature = "debug_msgs")]
		info!($($toks)*);
	})
}


pub type MsgSize = u32;

///The transfer mode of a file descriptor
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TransferMode {
	Synchronous,
	AsyncMPMC,
}

///The permissions (access mode) of a file descriptor
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AccessMode {
	ReadOnly,
	WriteOnly,
	ReadWrite,
}

impl AccessMode {
	///Returns true iff the message is permitted by this access mode
	pub(crate) fn permitted(&self, msgtype: MsgType) -> bool { 
		match msgtype {
			MsgType::Read => match self {
				Self::ReadOnly => true,
				Self::ReadWrite => true,
				Self::WriteOnly => false,
			},
			MsgType::Write => match self {
				Self::ReadOnly => false,
				Self::ReadWrite => true,
				Self::WriteOnly => true,
			},
			MsgType::Clunk => match self {
				Self::ReadOnly => true,
				Self::ReadWrite => true,
				Self::WriteOnly => true,
			},
		}
	}
}

//TODO: add a distinct Poll message type for client-side polling (the server will reply to this with the readable/writable/exceptional status in the buffer instead of data); server-side polling will instead first check if there is a pending reply and poll as writable if so, otherwise it will just do a regular receive and poll as readable when a message is received

//TODO: add polling support using a helper thread for each thread FD and a wakeup notifcation for each thread (which could probably just be the regular park notification for process server threads; user threads will need a notification allocated specifically for this since they won't have a park notificaiton tracked by the process server); if trees or linked lists are used, the memory will have to be caller-provided

///Message type code (returned in the status buffer for server-side FDs)
#[derive(Clone, Copy, Debug, Primitive, PartialEq)]
pub enum MsgType {
	Read = 0,
	Write = 1,
	Clunk = 2,
}

///Offset type code
///
///Which offsets and types are accepted is server-dependent. Some servers only
///accept zero offsets for instance (such as those with RPC/pipe-like APIs).
///
///Start specifies and offset relative to the beginning of the file
///Current specifies an offset relative to the current offset
///End specifies an offset relative to the current end of the file
///Hole specifies the offset of the next hole greater than or equal to the 
///    provided offset (relative to the beginning; if the provided offset is
///    within a hole this is equivalent to Start)
///Data specifies the offset of the next data region greater than or equal to
///    the provided offset (relative to the beginning; if the provided offset 
///    is within a data region this is equivalent to Start)
#[derive(Clone, Copy, Debug, PartialEq, Primitive)]
pub enum OffsetType {
	Start = 0,
	Current = 1,
	End = 2,
	Hole = 3,
	Data = 4,
}

static mut NULL_BUFFER: [u8; 0] = [];

///TODO: specify a lifetime for buffers
///
///Fixed-length IPC buffers associated with a file descriptor, for use with the 
///synchronous API
///
///The primary buffer is always guaranteed to have a non-zero length. The status
///buffer has a non-zero length only for server-side FDs. The secondary buffer
///may or may not have a non-zero length depending on how the FD is configured.
#[derive(Clone, Copy, Debug)]
pub struct IPCBuffers {
	status: BufferArray,
	primary: BufferArray,
	secondary: BufferArray,
}

impl IPCBuffers {
	///Internal function to create a new instance
	pub fn new(status: BufferArray, primary: BufferArray, secondary: BufferArray) -> IPCBuffers {
		IPCBuffers {
			status,
			primary,
			secondary,
		}
	}
	///Internal function to get the size in words of the part of the message
	///in the primary buffer
	#[inline]
	fn get_primary_size(size: usize) -> usize {
		let mut primary_size = size / core::mem::size_of::<usize>() + NUM_RESERVED_REGS;
		if size % core::mem::size_of::<usize>() > 0 {
			primary_size += 1;
		}

		min(primary_size, seL4_MsgMaxLength as usize)
	}
	///Gets the maximum message payload size (excluding the status buffer)
	#[inline]
	pub fn get_max_message_size(&self) -> usize {
		self.primary.len() + self.secondary.len()
	}
	///Gets the status buffer
	#[inline]
	pub fn get_status(&self) -> BufferArray {
		self.status
	}
	///Gets the primary data buffer
	#[inline]
	pub fn get_primary(&self) -> BufferArray {
		self.primary
	}
	///Gets the secondary buffer
	#[inline]
	pub fn get_secondary(&self) -> BufferArray {
		self.secondary
	}
	///Copies the contents of this buffer pair out to a `u8` slice, 
	///starting from `start` and ending at `end` within the concatentation
	///of the primary and secondary buffers (the start in the destination
	///is always 0)
	///
	///Returns the length of the copied data
	pub fn copyout(&self, dest: &mut [u8], start: usize) -> usize {
		debug_println!("copyout");
		let size = dest.len();
		let (primary_size, primary_end, secondary_ext_end, secondary_start, secondary_end) = self.getoffsets(start, size);
		if primary_size > 0 {
			dest[0..primary_size].copy_from_slice(&self.primary[start..primary_end]);
		}
		let secondary_size = secondary_end - secondary_start;
		if secondary_size > 0 {
			dest[primary_size..secondary_ext_end]
					.copy_from_slice(&self.secondary[secondary_start..secondary_end]);
		}
		primary_size + secondary_size
	}
	///Copies a `u8` slice into this buffer pair, starting from `start` 
	///and ending at `end` within the concatentation of the primary and
	///secondary buffers (the start in the source is always 0)
	///
	///Returns the length of the copied data
	pub fn copyin(&mut self, src: &[u8], start: usize) -> usize {
		debug_println!("copyin");
		let size = src.len();
		let (primary_size, primary_end, secondary_ext_end, secondary_start, secondary_end) = self.getoffsets(start, size);
		if primary_size > 0 {
			self.primary[start..primary_end].copy_from_slice(&src[0..primary_size]);
		}
		let secondary_size = secondary_end - secondary_start;
		if secondary_size > 0 {
			self.secondary[secondary_start..secondary_end].copy_from_slice(&src[primary_size..secondary_ext_end]);
		}
		primary_size + secondary_size
	}
	///Internal function to get the offsets to use when copying into and 
	///out of the system buffers
	#[inline]
	fn getoffsets(&self, start: usize, size: usize) -> (usize, usize, usize, usize, usize) {
		debug_println!("{} {}", start, size);
		let end = start + size;
		let mut primary_end = end;
		let primary_size = if start < self.primary.len() {

			if primary_end > self.primary.len() {
				primary_end = self.primary.len();
			}
			let primary_size = primary_end - start;
			primary_size
		}else{
			0
		};

		let (secondary_ext_end, secondary_start, secondary_end) = if end > self.primary.len() {
			let mut secondary_end = end - self.primary.len();
			if secondary_end > self.secondary.len() {
				secondary_end = self.secondary.len()
			}
			let secondary_start = if start > self.primary.len() {
				start - primary_size
			}else{
				0
			};
			let secondary_size = secondary_end - secondary_start;
			let external_end = primary_size + secondary_size;

			(external_end, secondary_start, secondary_end)
		}else{
			(0, 0, 0)
		};
		debug_println!("{} {} {} {} {}", primary_size, primary_end, secondary_ext_end, secondary_start, secondary_end);
		(primary_size, primary_end, secondary_ext_end, secondary_start, secondary_end)
	}
}

///Errors returned by transport layer functions
#[derive(Clone, Copy, Debug, Fail)]
pub enum IOError {
	#[fail(display = "Resource temporarily unavailable")]
	WouldBlock,
	#[fail(display = "Invalid argument")]
	InvalidArgument,
	#[fail(display = "Message too long")]
	MessageTooLong,
	#[fail(display = "Invalid message")]
	InvalidMessage,
	#[fail(display = "Server error")]
	ServerError(usize),
	#[fail(display = "Invalid operation")]
	InvalidOperation,
	#[fail(display = "System call error")]
	SyscallError(sel4::Error),
}

//these are the same as the corresponding Linux errno values
//TODO: take these from errno.h once one is present
pub const SRV_ERR_BADF: usize = 9;
pub const SRV_ERR_INVAL: usize = 22;
pub const SRV_ERR_NOSYS: usize = 38;
pub const SRV_ERR_NOTCONN: usize = 107;

#[cfg(target_pointer_width = "64")]
const SIZE_IDX: usize = 0;
#[cfg(target_pointer_width = "64")]
const OFFSET_IDX: usize = 1;
#[cfg(target_pointer_width = "64")]
const NUM_RESERVED_REGS: usize = 2;

///An individual message buffer
#[derive(Clone, Copy, Debug)]
pub struct BufferArray {
	ptr: *mut u8,
	len: usize,
}

impl BufferArray {
	///Creates a new `BufferArray`
	///
	///This is unsafe because the pointer isn't checked at all.
	pub unsafe fn new(ptr: *mut u8, len: usize) -> BufferArray {
		BufferArray {
			ptr,
			len,
		}
	}
	///Creates a null `BufferArray`
	pub fn null() -> BufferArray {
		unsafe { Self::new(NULL_BUFFER.as_mut_ptr(), 0) }
	}
	///Returns a view of this array that contains `usize` instead of `u8`
	pub fn as_word(&self) -> WordBufferArray {
		unsafe { WordBufferArray::new(self.ptr as *mut usize, self.len) }
	}
}

impl Deref for BufferArray {
	type Target = [u8];

	fn deref(&self) -> &[u8] {
		unsafe { slice::from_raw_parts(self.ptr, self.len) }
	}
}

impl DerefMut for BufferArray {
	fn deref_mut(&mut self) -> &mut [u8] {
		unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
	}
}

///A `usize` view of a `BufferArray`
pub struct WordBufferArray {
	ptr: *mut usize,
	len: usize,
}

impl WordBufferArray {
	///Creates a new `WordBufferArray`
	#[inline]
	pub unsafe fn new(ptr: *mut usize, len: usize) -> WordBufferArray {
		WordBufferArray {
			ptr,
			len,
		}
	}
}

impl Deref for WordBufferArray {
	type Target = [usize];

	fn deref(&self) -> &[usize] {
		unsafe { slice::from_raw_parts(self.ptr, self.len) }
	}
}

impl DerefMut for WordBufferArray {
	fn deref_mut(&mut self) -> &mut [usize] {
		unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
	}
}

//TODO: it might be a good idea to use std::ptr::read_volatile() to read the contents, even though it isn't changed while an FD is open, just to make sure that the compiler doesn't make assumptions about how it is initialized
///A Vec-like array backed by a pre-allocated region
pub struct UnsafeArray<T: Send + Sync> {
	size: AtomicUsize,
	ptr: AtomicUsize,
	align: usize,
	default_addr: usize,
	phantom: PhantomData<T>,
}

impl<T: Send + Sync> UnsafeArray<T> {
	///Creates a new `UnsafeArray`
	pub unsafe fn new(len: usize, ptr: usize, align: usize, default_addr: usize) -> UnsafeArray<T> {
		UnsafeArray {
			size: AtomicUsize::new(len),
			ptr: AtomicUsize::new(ptr),
			align,
			default_addr,
			phantom: Default::default(),
		}
	}
	///Returns the current length of this array
	pub fn len(&self) -> usize {
		self.size.load(Ordering::Relaxed)
	}
	///Sets the current length of this array when the underlying region
	///has been changed
	pub unsafe fn set_len(&self, len: usize) {
		self.size.store(len, Ordering::Relaxed)
	}
	///Sets the start pointer of this array when it has been moved
	pub unsafe fn set_ptr(&self, ptr: usize) {
		self.ptr.store(ptr, Ordering::Relaxed)
	}
}

impl<T: Send + Sync> Index<usize> for UnsafeArray<T> {
	type Output = T;
	fn index(&self, index: usize) -> &Self::Output {
		let ptr = self.ptr.load(Ordering::Relaxed);
		let addr = if index < self.len() && ptr != 0{
			ptr + self.align * index
		}else{
			self.default_addr
		};
		unsafe { &*(addr as *const T) }
	}
}

impl<T: Send + Sync> IndexMut<usize> for UnsafeArray<T> {
	fn index_mut(&mut self, index: usize) -> &mut Self::Output {
		if index > self.len() {
			panic!("UnsafeArray index {} out of range", index);
		}
		let addr = self.ptr.load(Ordering::Relaxed) + self.align * index;
		unsafe { &mut *(addr as *mut T) }
	}
}

impl<T: Send + Sync> Clone for UnsafeArray<T> {
	fn clone(&self) -> Self {
		UnsafeArray {
			size: AtomicUsize::new(self.size.load(Ordering::Relaxed)),
			ptr: AtomicUsize::new(self.ptr.load(Ordering::Relaxed)),
			align: self.align,
			default_addr: self.default_addr,
			phantom: Default::default(),
		}
	}
}

///A reference wrapper to a file descriptor in the calling thread's FDSpace
///
///This looks up the underlying FD by index on every call
#[derive(Copy, Clone)]
pub struct FileDescriptorRef {
	index: i32,
}

impl FileDescriptor for FileDescriptorRef {
	fn get_base_fd(&self) -> UnsafeRef<UnifiedFileDescriptor> {
		debug_println!("get_base_fd: {}", self.index);
		unsafe { FDS.as_ref().expect("thread FDSpace unset").get(self.index) }
	}
}

pub const FD_ALIGN: usize = 128; 
const_assert!(size_of::<UnifiedFileDescriptor>() < FD_ALIGN);
const_assert!(PAGE_SIZE % FD_ALIGN == 0);

const NULL_FD: UnifiedFileDescriptor = UnifiedFileDescriptor {
	base_fd: InnerUnifiedFileDescriptor::Null,
};

///An array of file descriptors for a thread
pub struct FDArray {
	fds: UnsafeArray<Option<UnifiedFileDescriptor>>,
	waiting_endpoint: AtomicUsize,
}

impl FDArray {
	///Creates a new `FDArray`
	pub unsafe fn new(len: usize, ptr: usize) -> FDArray {
		FDArray {
			fds: UnsafeArray::new(len, ptr, FD_ALIGN, &NULL_FD as *const UnifiedFileDescriptor as usize),
			waiting_endpoint: AtomicUsize::new(0),
		}
	}
	///Gets a file descriptor
	pub fn get(&self, index: i32) -> UnsafeRef<UnifiedFileDescriptor> {
		if let Some(ref fd) = self.fds[index as usize] {
			unsafe { UnsafeRef::from_raw(fd as *const UnifiedFileDescriptor) }
		}else{
			unsafe { UnsafeRef::from_raw(&NULL_FD as *const UnifiedFileDescriptor) }
		}
	}
	///Inserts a file descriptor
	pub fn insert(&mut self, index: i32, fd: UnifiedFileDescriptor){
		self.fds[index as usize] = Some(fd);
	}
	///Removes a file descriptor
	pub fn remove(&mut self, index: i32){
		self.fds[index as usize] = None;
	}
	///Updates the length of the array when the underlying region has been
	///changed
	pub unsafe fn set_len(&self, len: usize) {
		self.fds.set_len(len);
	}
	///Sets the start pointer of the array when the underlying region has
	///been changed
	pub unsafe fn set_ptr(&self, ptr: usize) {
		self.fds.set_ptr(ptr);
	}
	///Gets the length of the array
	pub fn len(&self) -> usize {
		self.fds.len()
	}
	///Sets the endpoint on which the calling thread is blocking
	pub(crate) fn set_waiting_endpoint(&self, id: usize) {
		self.waiting_endpoint.store(id, Ordering::Relaxed);
	}
	///Gets the endpoint on which the associated thread is blocking
	pub fn get_waiting_endpoint(&self) -> usize {
		self.waiting_endpoint.load( Ordering::Relaxed)
	}

}

impl Clone for FDArray {
	fn clone(&self) -> FDArray {
		FDArray {
			fds: self.fds.clone(),
			waiting_endpoint: AtomicUsize::new(0),
		}
	}
}

#[thread_local]
static mut FDS: Option<UnsafeRef<FDArray>> = None;

///Sets the calling thread's `FDArray`
pub fn set_fd_array(array: UnsafeRef<FDArray>){
	unsafe { FDS = Some(array) };
}

///Gets a `FileDescriptorRef` from this thread's `FDArray`
pub fn get_fd(index: i32) -> FileDescriptorRef {
	debug_println!("get_fd: {}", index);
	FileDescriptorRef {
		index
	}
}

//TODO: add a non-blocking flag

///A client-server communication channel implementing Unix-like file semantics
///on top of seL4 endpoints and/or notifications
///
///
///This is the internal part that is shared between the client and server code.
///Code using this library should instead use BaseClientFileDescriptor and
///BaseServerFileDescriptor.
///
///In synchronous mode, this uses endpoints to implement what is basically unstructured RPC with two methods.
///
///On the client side, both readbuf() and writebuf() translate into seL4_Call.
///
///On the server side, readbuf() translates into seL4_Recv, and writebuf() into seL4_Send()
///
///In asynchronous mode, this uses a pair of ring buffers - a submission ring for client requests, and a completion ring for server responses. This is not yet implemented
#[derive(Clone)]
pub(crate) struct BaseFileDescriptor {
	id: i32,
	access: AccessMode,
	transfer: TransferMode,
	endpoint: Option<Endpoint>,
}


//TODO: add support for non-blocking mode (which can be done by simply switching blocking for non-blocking calls as necessary)
//TODO: add support for message-oriented files (this will only affect the traditional APIs, and will have the effect of making them preserve message boundaries

///Gets the primary buffer array for the current thread (offset and length are
///in words, rather than bytes)
pub(crate) fn get_primary_array(offset: usize, len: usize) -> BufferArray {
	let buf = unsafe { &mut*(seL4_GetIPCBuffer()) };
	let addr = &buf.msg as *const _ as usize;
	unsafe { BufferArray::new((addr + size_of::<usize>() * offset) as *mut u8, len * size_of::<usize>()) }
}

impl BaseFileDescriptor {
	///Creates a new `BaseFileDescriptor`
	pub fn new(id: i32, access: AccessMode, transfer: TransferMode, endpoint: Endpoint) -> BaseFileDescriptor {
		BaseFileDescriptor {
			id,
			access,
			transfer,
			endpoint: Some(endpoint),
		}
	}
	///Gets the primary buffer for this file descriptor.
	pub fn get_primary(&self) -> BufferArray {
		get_primary_array(NUM_RESERVED_REGS, seL4_MsgMaxLength as usize - NUM_RESERVED_REGS)
	}
	///Gets the ID of this file descriptor
	#[inline]
	pub fn get_id(&self) -> i32 {
		self.id
	}
	///Gets the access mode
	#[inline]
	pub fn get_access(&self) -> AccessMode {
		self.access
	}
	///Gets the transfer mode
	#[inline]
	pub fn get_transfer(&self) -> TransferMode {
		self.transfer
	}
	///Called before a blocking call on this FD
	#[inline]
	pub fn begin_sync_wait(&self) {
		let cap = self.endpoint.expect("no endpoint associated with file descriptor").to_cap();
		let fdspace = unsafe { FDS.as_ref().expect("no FDSpace associated with FD") };
		fdspace.set_waiting_endpoint(cap);
	}
	///Called after a blocking call on this FD returns
	#[inline]
	pub fn end_sync_wait(&self) {
		let fdspace = unsafe { FDS.as_ref().expect("no FDSpace associated with FD") };

		fdspace.set_waiting_endpoint(0);
	}
}

//TODO: add a Thread FD type, which should wrap a TCB object in an RPC-like
//interface that allows setting/getting registers, suspending/resuming, and 
//debugging a thread

//TODO: add an Interrupt FD type, which should wrap an IRQHandler and a 
//Notification, allowing acknowledging the interrupt with writes and blocking 
//on the interrupt notification with reads
///The contents of a `UnifiedFileDescriptor`
#[derive(Clone)]
enum InnerUnifiedFileDescriptor {
	Client(BaseClientFileDescriptor),
	Server(BaseServerFileDescriptor),
	Notification(BaseNotificationFileDescriptor),
	Null,
}

///Wrapper that provides a unified API around client and server FDs
#[derive(Clone)]
pub struct UnifiedFileDescriptor {
	base_fd: InnerUnifiedFileDescriptor,
}

///Converts the result of a seeking server call to that used by 
///`UnifiedFileDescriptor`
#[inline]
fn convert_server_result_seek(res: Result<usize, IOError>) -> Result<(usize, usize), (usize, usize, IOError)>{
	match res {
		Ok(size) => Ok((size, 0)),
		Err(err) => Err((0, 0, err))
	}
}

///Converts the result of a non-seeking server call to that used by 
///`UnifiedFileDescriptor`
#[inline]
fn convert_server_result_noseek(res: Result<usize, IOError>) -> Result<usize, (usize, IOError)>{
	match res {
		Ok(size) => Ok(size),
		Err(err) => Err((0, err))
	}
}

impl UnifiedFileDescriptor {
	///Creates a new client-side file descriptor
	pub fn new_client(id: i32, endpoint: Endpoint, access: AccessMode, transfer: TransferMode, secondary_buffer_addr: usize, secondary_buffer_size: usize, state: UnsafeRef<ClientFileDescriptorState>) -> UnifiedFileDescriptor {
		let base_fd = BaseClientFileDescriptor::new(id, endpoint, access, transfer, secondary_buffer_addr, secondary_buffer_size, state);
		UnifiedFileDescriptor {
			base_fd: InnerUnifiedFileDescriptor::Client(base_fd),
		}
	}
	///Creates a new server-side file descriptor
	pub fn new_server(id: i32, endpoint: Endpoint, reply: Reply, access: AccessMode, transfer: TransferMode, combine_reply: bool, secondary_size: usize, state: UnsafeRef<ServerFileDescriptorState>) -> UnifiedFileDescriptor {
		let base_fd = BaseServerFileDescriptor::new(id, endpoint, reply, access, transfer, combine_reply, secondary_size, state);
		UnifiedFileDescriptor {
			base_fd: InnerUnifiedFileDescriptor::Server(base_fd),
		}
	}
	///Creates a new notification file descriptor
	pub fn new_notification(id: i32, notification: Notification, access: AccessMode, state: UnsafeRef<NotificationFileDescriptorState>) -> UnifiedFileDescriptor {
		let base_fd = BaseNotificationFileDescriptor::new(id, notification, access, state);
		UnifiedFileDescriptor {
			base_fd: InnerUnifiedFileDescriptor::Notification(base_fd),
		}
	}
	///Gets the endpoint associated with this FD (if present). This is
	///only intended for debugging and deallocation purposes (regular code
	///doesn't need to use the endpoint directly)
	pub fn get_endpoint(&self) -> Option<Endpoint> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.get_endpoint(),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.get_endpoint(),
			InnerUnifiedFileDescriptor::Notification(_) => None,
			InnerUnifiedFileDescriptor::Null => None,
		}
	}
	///Gets the reply object associated with this FD (if present). This is
	///only intended for debugging and deallocation purposes (regular code
	///doesn't need to use the reply directly)
	pub fn get_reply(&self) -> Option<Reply> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(_) => None,
			InnerUnifiedFileDescriptor::Server(ref base_fd) => Some(base_fd.get_reply()),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => None,
			InnerUnifiedFileDescriptor::Null => None,
		}
	}
	///Gets the ID
	pub fn get_id(&self) -> i32 {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.get_id(),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.get_id(),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => base_fd.get_id(),
			InnerUnifiedFileDescriptor::Null => i32::MIN,
		}
	}
	///Gets the access mode
	pub fn get_access(&self) -> AccessMode {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.get_access(),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.get_access(),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => base_fd.get_access(),
			InnerUnifiedFileDescriptor::Null => AccessMode::ReadWrite,
		}
	}
	///Gets the transfer mode
	pub fn get_transfer(&self) -> TransferMode {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.get_transfer(),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.get_transfer(),
			InnerUnifiedFileDescriptor::Notification(_) => TransferMode::AsyncMPMC,
			InnerUnifiedFileDescriptor::Null => TransferMode::Synchronous,
		}
	}
	///Gets the IPC buffers associated with this file descriptor.
	///
	///These may change between messages, so this must be called after
	///every message.
	pub fn getbuf(&self) -> Option<IPCBuffers>{
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => Some(base_fd.getbuf()),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.getbuf(),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => Some(base_fd.getbuf()),
			InnerUnifiedFileDescriptor::Null => None,
		}
	}
	///Gets the sizes of the primary and secondary IPC buffers associated
	///with this FD.
	pub fn getbufsize(&self) -> (usize, usize) {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.getbufsize(),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.getbufsize(),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => base_fd.getbufsize(),
			InnerUnifiedFileDescriptor::Null => (0, 0),
		}
	}
	///Gets the size of the last message on this FD
	pub fn getmsgsize(&self) -> usize {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.getmsgsize(),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.getmsgsize(),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => base_fd.getmsgsize(),
			InnerUnifiedFileDescriptor::Null => 0,
		}
	}
	///Gets the offset of the last message on this FD
	pub fn getmsgoffset(&self) -> usize {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.getmsgoffset(),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.getmsgoffset(),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => base_fd.getmsgoffset(),
			InnerUnifiedFileDescriptor::Null => 0,
		}
	}
	///Seeks to the specified offset and reads from the file descriptor,
	///copying into the provided buffer.
	///
	///For server-side FDs, this method is equivalent to read(), since the
	///offset type must be Start and the offset must be 0.
	///
	///Returns the size and offset of the data that was read on success,
	///or the size and offset of the server-specific error status and an
	///IOError on failure.
	///
	pub fn pread(&self, buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.pread(buf, offset, whence),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				if whence as usize == OffsetType::Start as usize && offset == 0 {
					convert_server_result_seek(base_fd.read(buf))
				}else{
					Err((0, 0, IOError::InvalidArgument))
				}
			},
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => {
				if whence as usize == OffsetType::Start as usize && offset == 0 {
					convert_server_result_seek(base_fd.read(buf))
				}else{
					Err((0, 0, IOError::InvalidArgument))
				}
			},
			InnerUnifiedFileDescriptor::Null => Err((0, 0, IOError::InvalidOperation)),
		}
	}
	///Reads a message into a user-provided buffer
	///
	///This must be called twice for each message for server-side FDs.
	///The first call returns the status (blocking if no message is
	///available), and the second always immediately returns the data.
	///
	///This blocks on every call and returns only data for client FDs. Data
	///will be read from the current offset saved by the server (i.e. this
	///is equivalent to pread() with an offset of 0 and an offset type of
	///Current).
	///
	///Returns the size of the data or status that was read on success, or
	///the size of the server-specific error status (always 0 for server
	///FDs) and an IOError on failure.
	pub fn read(&self, buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.read(buf),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_noseek(base_fd.read(buf))
			},
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => convert_server_result_noseek(base_fd.read(buf)),
			InnerUnifiedFileDescriptor::Null => Err((0, IOError::InvalidOperation)),
		}
	}
	///Seeks to the specified offset and reads a message into the IPC
	///buffers
	///
	///Semantics are otherwise the same as pread()
	pub fn preadbuf(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		debug_println!("UnifiedFileDescriptor::preadbuf");
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => {
				debug_println!("UnifiedFileDescriptor::preadbuf: client");
				base_fd.preadbuf(size, offset, whence)
			},
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				debug_println!("UnifiedFileDescriptor::preadbuf: server");
				if whence as usize == OffsetType::Start as usize && offset == 0 {
					convert_server_result_seek(base_fd.readbuf())
				}else{
					Err((0, 0, IOError::InvalidArgument))
				}
			},
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => {
				debug_println!("UnifiedFileDescriptor::preadbuf: notification");
				if whence as usize == OffsetType::Start as usize && offset == 0 {
					convert_server_result_seek(base_fd.readbuf(size))
				}else{
					Err((0, 0, IOError::InvalidArgument))
				}
			},
			InnerUnifiedFileDescriptor::Null => Err((0, 0, IOError::InvalidOperation)),
		}
	}
	///Reads a message into the IPC buffers
	///
	///Semantics are otherwise the same as read()
	pub fn readbuf(&self, size: usize) -> Result<usize, (usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.readbuf(size),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_noseek(base_fd.readbuf())
			},
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => convert_server_result_noseek(base_fd.readbuf(size)),
			InnerUnifiedFileDescriptor::Null => Err((0, IOError::InvalidOperation)),
		}
	}
	///Seeks to the specified offset.
	///
	///Returns the new current offset on success, or the size and offset of
	///the server-specific error status and an IOError on failure.
	///
	///For client-side FDs, this is equivalent to preadbuf with a zero size.
	///
	///For server-side FDs, this updates the stored offset without sending
	///any messages. Only Start (which sets the current offset (which sets
	///the current offset to the given offset) or Current (which adds the
	///given offset to the current offset) offset types are accepted for 
	///server FDs.
	pub fn seek(&self, offset: isize, whence: OffsetType) -> Result<usize, (usize, usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.seek(offset, whence),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => base_fd.seek(offset, whence),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => Err((0, 0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Null => Err((0, 0, IOError::InvalidOperation)),
		}
	}
	///Seeks to the specified offset and writes data to the file descriptor
	///from a user-provided buffer
	///
	///For server-side FDs, the provided offset determines the one that is
	///returned to the client. If the offset type is Start, the offset will
	///be returned to the client as is. If the offset type is Current, the
	///provided offset plus the last stored offset will be returned to the
	///client. In both cases, the saved offset will be set to the offset
	///returned to the client plus the provided size.
	///
	///The other offset types are valid only for client FDs. 
	///
	///For server-side FDs with combine_reply set to True, this must be
	///called twice to actually send a reply. The first call sets the
	///written data size to return to the client (the data is ignored),
	///and the second sets the size of the reply (which the client will
	///read with a read()-family function). The second call may be a
	///writeread()-family call in order to send a reply and wait for a new
	///message in the same call.
	///
	///For server FDs, this returns InvalidOperation if no reply from a
	///previous read()-family call is pending.
	pub fn pwrite(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.pwrite(buf, offset, whence),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => convert_server_result_seek(base_fd.pwrite(buf, offset, whence)),
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => {
				if whence as usize == OffsetType::Start as usize && offset == 0 {
					convert_server_result_seek(base_fd.write(buf))
				}else{
					Err((0, 0, IOError::InvalidArgument))
				}
			},
			InnerUnifiedFileDescriptor::Null => Err((0, 0, IOError::InvalidOperation)),
		}
	}
	///Writes data to the file descriptor from a user-provided buffer
	///
	///For server-side FDs this returns the local saved offset to the
	///client, and for client-side FDs, the server will use its saved
	///offset (i.e. it is equivalent to pwrite with 0 as the offset and
	///Current as the offset type in both cases).
	///
	///The semantics are otherwise similar to pwrite().
	pub fn write(&self, buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.write(buf),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_noseek(base_fd.write(buf))
			},
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => {
				convert_server_result_noseek(base_fd.write(buf))
			},
			InnerUnifiedFileDescriptor::Null => Err((0, IOError::InvalidOperation)),
		}
	}

	///Seeks to the specified offset and writes data to the file descriptor
	///from the IPC buffers
	///
	///Semantics are otherwise identical to pwrite()
	pub fn pwritebuf(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.pwritebuf(size, offset, whence),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				if whence as usize == OffsetType::Start as usize {
					convert_server_result_seek(base_fd.pwritebuf(size, offset, whence))
				}else{
					Err((0, 0, IOError::InvalidArgument))
				}
			},
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => {
				if whence as usize == OffsetType::Start as usize {
					convert_server_result_seek(base_fd.writebuf(size))
				}else{
					Err((0, 0, IOError::InvalidArgument))
				}
			}
			InnerUnifiedFileDescriptor::Null => Err((0, 0, IOError::InvalidOperation)),
		}
	}
	///Writes data to the file descriptor from the IPC buffers
	///
	///Semantics are otherwise identical to write()
	pub fn writebuf(&self, size: usize) -> Result<usize, (usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(ref base_fd) => base_fd.writebuf(size),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_noseek(base_fd.writebuf(size))
			},
			InnerUnifiedFileDescriptor::Notification(ref base_fd) => {
				convert_server_result_noseek(base_fd.writebuf(size))
			},
			InnerUnifiedFileDescriptor::Null => Err((0, IOError::InvalidOperation)),
		}
	}
	///This is equivalent to pwrite() followed by pread() for server FDs.
	///It will always fail on client FDs.
	///
	///The transition from sending the reply to waiting for a new message
	///is atomic unlike separate pwrite() and pread() calls.
	///
	///Only one offset can be provided since pread() on server FDs only
	///accepts a zero offset.
	///
	///If combine_reply is true, this must be preceded by a regular write
	///(any write()-family call will work) with the size of the written
	///data.
	///
	///The error returns are basically a combination of those of pread() and
	///pwrite(). One extra error condition is if this is called when
	///combine_reply is true and a regular write()/writebuf() was not called
	///before this to set the written size (InvalidOperation will be
	///returned)
	pub fn pwriteread(&self, w_buf: &mut [u8], r_buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(_) => Err((0, 0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_seek(base_fd.pwriteread(w_buf, r_buf, offset, whence))
			},
			InnerUnifiedFileDescriptor::Notification(_) => Err((0, 0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Null => Err((0, 0, IOError::InvalidOperation)),
		}
	}
	///This is equivalent to write() followed by read() for server FDs. It
	///will always fail on client FDs.
	///
	///Semantics are otherwise equivalent to pwriteread()
	pub fn writeread(&self, w_buf: &mut [u8], r_buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(_) => Err((0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_noseek(base_fd.writeread(w_buf, r_buf))
			},
			InnerUnifiedFileDescriptor::Notification(_) => Err((0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Null => Err((0, IOError::InvalidOperation)),
		}
	}
	///This is equivalent to pwritebuf() followed by preadbuf() for server
	///FDs. It will always fail on client FDs.
	///
	///Semantics are otherwise equivalent to pwriteread()
	pub fn pwritereadbuf(&self, len: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(_) => Err((0, 0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_seek(base_fd.pwritereadbuf(len, offset, whence))
			},
			InnerUnifiedFileDescriptor::Notification(_) => Err((0, 0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Null => Err((0, 0, IOError::InvalidOperation)),
		}
	}
	///This is equivalent to writebuf() followed by readbuf() for server
	///FDs. It will always fail on client FDs.
	///
	///Semantics are otherwise equivalent to pwriteread()
	pub fn writereadbuf(&self, len: usize) -> Result<usize, (usize, IOError)> {
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(_) => Err((0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				convert_server_result_noseek(base_fd.writereadbuf(len))
			},
			InnerUnifiedFileDescriptor::Notification(_) => Err((0, IOError::InvalidOperation)),
			InnerUnifiedFileDescriptor::Null => Err((0, IOError::InvalidOperation)),
		}
	}
	///For server FDs, this sets the error number that will be sent with the
	///reply. It will always fail for client FDs.
	///
	///Assuming no other errors occur, the client will receive Ok(size) if
	///errno is zero; otherwise it will receive
	///Err(size, offset, ServerError(errno))
	pub fn seterrno(&self, errno: usize) -> Result<(), ()>{
		match self.base_fd {
			InnerUnifiedFileDescriptor::Client(_) => Err(()),
			InnerUnifiedFileDescriptor::Server(ref base_fd) => {
				base_fd.seterrno(errno);
				Ok(())
			},
			InnerUnifiedFileDescriptor::Notification(_) => Err(()),
			InnerUnifiedFileDescriptor::Null => Err(()),
		}
	}
}

///Trait that exposes the methods of `UnifiedFileDescriptor` on a wrapper
pub trait FileDescriptor {
	///Gets the `UnifiedFileDescriptor` instance associated with this
	///FD
	fn get_base_fd(&self) -> UnsafeRef<UnifiedFileDescriptor>;
	///Gets the endpoint associated with this FD (if present). This is
	///only intended for debugging and testing purposes (regular code
	///doesn't need to use the endpoint directly)
	fn get_endpoint(&self) -> Option<Endpoint> {
		self.get_base_fd().get_endpoint()
	}
	///Gets the reply object associated with this FD (if present). This i
	///only intended for debugging and testing purposes (regular code
	///doesn't need to use the reply directly)
	fn get_reply(&self) -> Option<Reply> {
		self.get_base_fd().get_reply()
	}
	///Gets the ID
	fn get_id(&self) -> i32 {
		self.get_base_fd().get_id()
	}
	///Gets the access mode
	fn get_access(&self) -> AccessMode {
		self.get_base_fd().get_access()
	}
	///Gets the transfer mode
	fn get_transfer(&self) -> TransferMode {
		self.get_base_fd().get_transfer()
	}
	///Gets the IPC buffers associated with this file descriptor.
	///
	///These may change between messages, so this must be called after
	///every message.
	///
	fn getbuf(&self) -> Option<IPCBuffers>{
		self.get_base_fd().getbuf()
	}
	///Gets the sizes of the primary and secondary IPC buffers associated
	///with this FD.
	fn getbufsize(&self) -> (usize, usize) {
		self.get_base_fd().getbufsize()
	}
	///Gets the size of the last message on this FD
	fn getmsgsize(&self) -> usize {
		self.get_base_fd().getmsgsize()
	}
	///Gets the offset of the last message on this FD
	fn getmsgoffset(&self) -> usize {
		self.get_base_fd().getmsgoffset()
	}
	///Seeks to the specified offset and reads from the file descriptor,
	///copying into the provided buffer.
	///
	///For server-side FDs, this method is equivalent to read(), since the
	///offset type must be Start and the offset must be 0.
	///
	///Returns the size and offset of the data that was read on success,
	///or the size and offset of the server-specific error status and an
	///IOError on failure.
	///
	fn pread(&self, buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		self.get_base_fd().pread(buf, offset, whence)
	}
	///Reads a message into a user-provided buffer
	///
	///This must be called twice for each message for server-side FDs.
	///The first call returns the status (blocking if no message is
	///available), and the second always immediately returns the data.
	///
	///This blocks on every call and returns only data for client FDs. Data
	///will be read from the current offset saved by the server (i.e. this
	///is equivalent to pread() with an offset of 0 and an offset type of
	///Current).
	///
	///Returns the size of the data or status that was read on success, or
	///the size of the server-specific error status (always 0 for server
	///FDs) and an IOError on failure.
	fn read(&self, buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		self.get_base_fd().read(buf)
	}
	///Seeks to the specified offset and reads a message into the IPC
	///buffers
	///
	///Semantics are otherwise the same as pread()
	fn preadbuf(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		self.get_base_fd().preadbuf(size, offset, whence)
	}
	///Reads a message into the IPC buffers
	///
	///Semantics are otherwise the same as read()
	fn readbuf(&self, size: usize) -> Result<usize, (usize, IOError)> {
		self.get_base_fd().readbuf(size)
	}
	///Seeks to the specified offset.
	///
	///Returns the new current offset on success, or the size and offset of
	///the server-specific error status and an IOError on failure.
	///
	///For client-side FDs, this is equivalent to preadbuf with a zero size.
	///
	///For server-side FDs, this updates the stored offset without sending
	///any messages. Only Start (which sets the current offset (which sets
	///the current offset to the given offset) or Current (which adds the
	///given offset to the current offset) offset types are accepted for 
	///server FDs.
	fn seek(&self, offset: isize, whence: OffsetType) -> Result<usize, (usize, usize, IOError)> {
		self.get_base_fd().seek(offset, whence)
	}
	///Seeks to the specified offset and writes data to the file descriptor
	///from a user-provided buffer
	///
	///For server-side FDs, the provided offset determines the one that is
	///returned to the client. If the offset type is Start, the offset will
	///be returned to the client as is. If the offset type is Current, the
	///provided offset plus the last stored offset will be returned to the
	///client. In both cases, the saved offset will be set to the offset
	///returned to the client plus the provided size.
	///
	///The other offset types are valid only for client FDs. 
	///
	///For server-side FDs with combine_reply set to True, this must be
	///called twice to actually send a reply. The first call sets the
	///written data size to return to the client (the data is ignored),
	///and the second sets the size of the reply (which the client will
	///read with a read()-family function). The second call may be a
	///writeread()-family call in order to send a reply and wait for a new
	///message in the same call.
	///
	///For server FDs, this returns InvalidOperation if no reply from a
	///previous read()-family call is pending.
	fn pwrite(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		self.get_base_fd().pwrite(buf, offset, whence)
	}
	///Writes data to the file descriptor from a user-provided buffer
	///
	///For server-side FDs this returns the local saved offset to the
	///client, and for client-side FDs, the server will use its saved
	///offset (i.e. it is equivalent to pwrite with 0 as the offset and
	///Current as the offset type in both cases).
	///
	///The semantics are otherwise similar to pwrite().
	fn write(&self, buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		self.get_base_fd().write(buf)
	}

	///Seeks to the specified offset and writes data to the file descriptor
	///from the IPC buffers
	///
	///Semantics are otherwise identical to pwrite()
	fn pwritebuf(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		self.get_base_fd().pwritebuf(size, offset, whence)
	}
	///Writes data to the file descriptor from the IPC buffers
	///
	///Semantics are otherwise identical to write()
	fn writebuf(&self, size: usize) -> Result<usize, (usize, IOError)> {
		self.get_base_fd().writebuf(size)
	}
	///This is equivalent to pwrite() followed by pread() for server FDs.
	///It will always fail on client FDs.
	///
	///The transition from sending the reply to waiting for a new message
	///is atomic unlike separate pwrite() and pread() calls.
	///
	///Only one offset can be provided since pread() on server FDs only
	///accepts a zero offset.
	///
	///If combine_reply is true, this must be preceded by a regular write
	///(any write()-family call will work) with the size of the written
	///data.
	///
	///The error returns are basically a combination of those of pread() and
	///pwrite(). One extra error condition is if this is called when
	///combine_reply is true and a regular write()/writebuf() was not called
	///before this to set the written size (InvalidOperation will be
	///returned)
	fn pwriteread(&self, w_buf: &mut [u8], r_buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		self.get_base_fd().pwriteread(w_buf, r_buf, offset, whence)
	}
	///This is equivalent to write() followed by read() for server FDs. It
	///will always fail on client FDs.
	///
	///Semantics are otherwise equivalent to pwriteread()
	fn writeread(&self, w_buf: &mut [u8], r_buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		self.get_base_fd().writeread(w_buf, r_buf)
	}
	///This is equivalent to pwritebuf() followed by preadbuf() for server
	///FDs. It will always fail on client FDs.
	///
	///Semantics are otherwise equivalent to pwriteread()
	fn pwritereadbuf(&self, len: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		self.get_base_fd().pwritereadbuf(len, offset, whence)
	}
	///This is equivalent to writebuf() followed by readbuf() for server
	///FDs. It will always fail on client FDs.
	///
	///Semantics are otherwise equivalent to pwriteread()
	fn writereadbuf(&self, len: usize) -> Result<usize, (usize, IOError)> {
		self.get_base_fd().writereadbuf(len)
	}
	///For server FDs, this sets the error number that will be sent with the
	///reply. It will always fail for client FDs.
	///
	///Assuming no other errors occur, the client will receive Ok(size) if
	///errno is zero; otherwise it will receive
	///Err(size, offset, ServerError(errno))
	fn seterrno(&self, errno: usize) -> Result<(), ()>{
		self.get_base_fd().seterrno(errno)
	}
}

///The contents of a `ClunkFileDescriptor`
enum InnerClunkFileDescriptor {
	Client(ClientClunkFileDescriptor),
	Server(ServerClunkFileDescriptor),
}

///Wrapper providing a unified interface around `ServerClunkFileDescriptor`
///and `ClientClunkFileDescriptor`
pub struct ClunkFileDescriptor {
	base_fd: InnerClunkFileDescriptor,
}

impl ClunkFileDescriptor {
	///Creates a new client `ClunkFileDescriptor`
	pub fn new_client(endpoint: Endpoint, transfer: TransferMode) -> ClunkFileDescriptor {
		ClunkFileDescriptor {
			base_fd: InnerClunkFileDescriptor::Client(ClientClunkFileDescriptor::new(endpoint, transfer)),
		}
	}
	///Creates a new server `ClunkFileDescriptor`
	pub fn new_server(endpoint: Endpoint, reply: Reply, transfer: TransferMode) -> ClunkFileDescriptor {
		ClunkFileDescriptor {
			base_fd: InnerClunkFileDescriptor::Server(ServerClunkFileDescriptor::new(endpoint, reply, transfer)),
		}
	}
	///Gets the endpoint associated with this FD (if present). This is
	///only intended for debugging and deallocation purposes (regular code
	///doesn't need to use the endpoint directly)
	pub fn get_endpoint(&self) -> Option<Endpoint> {
		match self.base_fd {
			InnerClunkFileDescriptor::Client(ref base_fd) => base_fd.get_endpoint(),
			InnerClunkFileDescriptor::Server(ref base_fd) => base_fd.get_endpoint(),
		}
	}
	///Gets the reply object associated with this FD (if present). This is
	///only intended for debugging and deallocation purposes (regular code
	///doesn't need to use the reply directly)
	pub fn get_reply(&self) -> Option<Reply> {
		match self.base_fd {
			InnerClunkFileDescriptor::Client(_) => None,
			InnerClunkFileDescriptor::Server(ref base_fd) => Some(base_fd.get_reply()),
		}
	}
	///Sends a clunk message (blocking if no thread is waiting for a
	///message)
	pub fn clunk(&self) -> Result<(), IOError> {
		match self.base_fd {
			InnerClunkFileDescriptor::Client(ref base_fd) => base_fd.clunk(),
			InnerClunkFileDescriptor::Server(ref base_fd) => base_fd.clunk(),
		}
	}
}
