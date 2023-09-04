// Copyright 2022-2023 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use intrusive_collections::UnsafeRef;

use sel4::Endpoint;

use sel4_sys::{
	seL4_GetIPCBuffer,
	seL4_MsgMaxLength,
	seL4_NumErrors,
	seL4_Word,
	seL4_WordBits,
};

use crate::{
	AccessMode,
	BaseFileDescriptor,
	BufferArray,
	IOError,
	IPCBuffers,
	MsgSize,
	MsgType,
	NUM_RESERVED_REGS,
	OFFSET_IDX,
	OffsetType,
	SIZE_IDX,
	TransferMode,
	debug_println,
};

///Converts a result with an offset into one without
#[inline]
fn convert_offset_result(result: Result<(usize, usize), (usize, usize, IOError)>) -> Result<usize, (usize, IOError)>{
	match result {
		Ok((size, _)) => Ok(size),
		Err((size, _, err)) => Err((size, err)),
	}
}

///Shared state associated with a client file descriptor
pub struct ClientFileDescriptorState {
	waiting_reply_size: AtomicUsize,
	waiting_reply_offset: AtomicUsize,
	last_msg_size: AtomicUsize,
	last_msg_offset: AtomicUsize,
}

impl ClientFileDescriptorState {
	///Creates a new `ClientFileDescriptorState`
	pub fn new() -> ClientFileDescriptorState {
		ClientFileDescriptorState {
			waiting_reply_size: AtomicUsize::new(0),
			waiting_reply_offset: AtomicUsize::new(0),
			last_msg_size: AtomicUsize::new(0),
			last_msg_offset: AtomicUsize::new(0),
		}
	}
}

///A client-side file descriptor.
#[derive(Clone)]
pub struct BaseClientFileDescriptor {
	base_fd: BaseFileDescriptor,
	secondary_buffer_addr: usize,
	secondary_buffer_size: usize,
	state: UnsafeRef<ClientFileDescriptorState>,
}

impl BaseClientFileDescriptor {
	///Creates a new client-side file descriptor.
	pub fn new(id: i32, endpoint: Endpoint, access: AccessMode, transfer: TransferMode, secondary_buffer_addr: usize, secondary_buffer_size: usize, state: UnsafeRef<ClientFileDescriptorState>) -> BaseClientFileDescriptor {
		BaseClientFileDescriptor {
			base_fd: BaseFileDescriptor::new(id, access, transfer, endpoint),
			secondary_buffer_addr,
			secondary_buffer_size,
			state,
		}
	}
	///Gets the endpoint (only intended for debugging and deallocation)
	#[inline]
	pub(crate) fn get_endpoint(&self) -> Option<Endpoint> {
		self.base_fd.endpoint
	}
	///Gets the ID
	#[inline]
	pub fn get_id(&self) -> i32 {
		self.base_fd.get_id()
	}
	///Gets the access mode
	#[inline]
	pub fn get_access(&self) -> AccessMode {
		self.base_fd.get_access()
	}
	///Gets the transfer mode
	#[inline]
	pub fn get_transfer(&self) -> TransferMode {
		self.base_fd.get_transfer()
	}
	///Gets the sizes of the primary and secondary IPC buffers associated
	///with this FD.
	#[inline]
	pub fn getbufsize(&self) -> (usize, usize) {
		(seL4_MsgMaxLength as usize, self.secondary_buffer_size)
	}
	///Gets the size of the last message on this FD
	#[inline]
	pub fn getmsgsize(&self) -> usize {
		self.state.last_msg_size.load(Ordering::Relaxed)
	}
	///Gets the offset of the last message on this FD
	#[inline]
	pub fn getmsgoffset(&self) -> usize {
		self.state.last_msg_offset.load(Ordering::Relaxed)
	}
	///Gets the IPC buffers associated with this file descriptor.
	///
	///These may change between messages, so this must be called after
	///every message.
	///
	pub fn getbuf(&self) -> IPCBuffers {
		let primary = self.base_fd.get_primary();
		IPCBuffers {
			status: BufferArray::null(),
			primary,
			secondary: unsafe { BufferArray::new(self.secondary_buffer_addr as *mut u8, self.secondary_buffer_size) },
		}
	}
	///Internal wrapper around seL4_Call
	fn call_sync(&self, msgtype: MsgType, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		let buf = unsafe { &mut*(seL4_GetIPCBuffer()) };
		buf.msg[SIZE_IDX] = size;
		buf.msg[OFFSET_IDX] = offset as usize;
		let endpoint = self.get_endpoint().expect("no endpoint associated with file descriptor");

		self.base_fd.begin_sync_wait();
		let res = endpoint.call(((whence as usize) << seL4_WordBits / 2) | msgtype as usize, IPCBuffers::get_primary_size(size), 0);
		self.base_fd.end_sync_wait();
		match res {
			Ok(msg) => {
				let error = msg.label - seL4_NumErrors as usize;
				let sizes = buf.msg[SIZE_IDX];
				let offset = buf.msg[OFFSET_IDX];
				let accepted_size = (sizes as MsgSize) as seL4_Word;
				let waiting_size = sizes >> (size_of::<MsgSize>() * 8);
				if error > 0 {
					return Err((accepted_size, offset, IOError::ServerError(error as usize)))
				} else if waiting_size > 0 {
					self.state.waiting_reply_size.store(waiting_size as usize, Ordering::Release);
					self.state.waiting_reply_offset.store(offset, Ordering::Release);
				}
				Ok((accepted_size, offset))
			},
			Err(err) => {
				Err((0, 0, IOError::SyscallError(err)))
			},
		}
	}
	///Seeks to the specified offset and reads from the file descriptor, 
	///copying into the provided buffer.
	///
	///Returns the size and offset of the data that was read on success,
	///or the size and offset of the server-specific error status and an
	///IOError on failure.
	pub fn pread(&self, buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.get_transfer() {
			TransferMode::Synchronous => self.pread_sync(buf, offset, whence),
			TransferMode::AsyncMPMC => self.pread_async(buf, offset, whence),
		}
	}
	///Internal implementation of `pread` for synchronous FDs
	fn pread_sync(&self, buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.preadbuf_sync(buf.len(), offset, whence) {
			Ok(res) => {
				let sys_buf = self.getbuf();
				sys_buf.copyout(&mut buf[..res.0], 0);
				Ok(res)
			}
			Err(err) => {
				Err(err)
			}
		}
	}
	///Internal implementation of `pread` for asynchronous FDs
	fn pread_async(&self, buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		unimplemented!()
	}
	///Reads from the file descriptor, copying into the provided buffer.
	///
	///Returns the size of the data that was read on success, or the size
	///of the server-specific error status and an IOError on failure.
	pub fn read(&self, buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		convert_offset_result(self.pread(buf, 0, OffsetType::Current))
	}
	///Seeks to the specified offset and reads from the file descriptor.
	///The message is in the IPC buffers.
	///
	///Returns the size and offset of the data that was read on success,
	///or the size and offset of the server-specific error status and an
	///IOError on failure.
	pub fn preadbuf(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		match self.get_transfer() {
			TransferMode::Synchronous => self.preadbuf_sync(size, offset, whence),
			TransferMode::AsyncMPMC => self.preadbuf_async(size, offset, whence),
		}
	}
	///Reads from the file descriptor. The message is in the IPC buffers.
	///
	///Returns the size of the data that was read on success, or the size
	///of the server-specific error status and an IOError on failure.
	pub fn readbuf(&self, size: usize) -> Result<usize, (usize, IOError)> {
		convert_offset_result(self.preadbuf(size, 0, OffsetType::Current))
	}
	///Seeks to the specified offset.
	///
	///Returns the new current offset on success, or the size and offset of
	///the server-specific error status and an IOError on failure.
	///
	///This is equivalent to preadbuf with a zero size.
	pub fn seek(&self, offset: isize, whence: OffsetType) -> Result<usize, (usize, usize, IOError)> {
		match self.preadbuf(0, offset, whence) {
			Ok((_, offset)) => Ok(offset),
			Err(err) => Err(err),
		}
	}
	///Internal implementation of readbuf for synchronous FDs.
	fn preadbuf_sync(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)>{
		let waiting_reply_size = self.state.waiting_reply_size.load(Ordering::Acquire);
		let waiting_reply_offset = self.state.waiting_reply_offset.load(Ordering::Acquire);
		let (ret, mut ret_size, ret_offset) = if waiting_reply_size > 0 {
			debug_println!("reply waiting, size: {}", waiting_reply_size);
			let ret = (waiting_reply_size, waiting_reply_offset);
			self.state.waiting_reply_size.store(0, Ordering::Release);
			self.state.waiting_reply_offset.store(0, Ordering::Release);
			(Ok(ret), waiting_reply_size, waiting_reply_offset)
		}else{
			match self.call_sync(MsgType::Read, size, offset, whence) {
				Ok((size, offset)) => (Ok((size, offset)), size, offset),
				Err((size, offset, err)) => (Err((size, offset, err)), size, offset),

			}
		};
		let max_size = self.getbuf().get_max_message_size();
		if ret_size > max_size {
			ret_size = max_size;
		}
		self.state.last_msg_size.store(ret_size, Ordering::Relaxed);
		self.state.last_msg_offset.store(ret_offset, Ordering::Relaxed);
		ret
	}
	///Internal implementation of readbuf for asynchronous FDs.
	fn preadbuf_async(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)>{
		unimplemented!()
	}
	///Seeks to the specified offset and writes data to the file descriptor
	///from the provided buffer.
	///
	///Returns the size and offset of the data that was written on 
	///success, or the size and offset of the server-specific error status
	///and an IOError on failure.
	pub fn pwrite(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)>{
		match self.get_transfer() {
			TransferMode::Synchronous => self.pwrite_sync(buf, offset, whence),
			TransferMode::AsyncMPMC => self.pwrite_async(buf, offset, whence),
		}
	}
	///Internal implementation of `pwrite` for synchronous FDs
	fn pwrite_sync(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		if buf.len() > self.base_fd.get_primary().len() + self.secondary_buffer_size {
			return Err((0, 0, IOError::InvalidArgument));
		}
		let mut sys_buf = self.getbuf();
		sys_buf.copyin(&buf[..], 0);
		self.pwritebuf_sync(buf.len(), offset, whence)
	}
	///Internal implementation of `pwrite` for asynchronous FDs
	fn pwrite_async(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)> {
		unimplemented!()
	}
	///Writes data to the file descriptor from the provided buffer.
	///
	///Returns the size of the data that was written on success, or the size
	///of the server-specific error status and an IOError on failure.
	pub fn write(&self, buf: &mut [u8]) -> Result<usize, (usize, IOError)> {
		convert_offset_result(self.pwrite(buf, 0, OffsetType::Current))
	}

	///Seeks to the specified offset and writes to the file descriptor. The
	///message is in the IPC buffers.
	///
	///Returns the size and offset of the data that was written on success,
	///or the size and offset of the server-specific error status and an
	///IOError on failure.
	pub fn pwritebuf(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)>{
		match self.get_transfer() {
			TransferMode::Synchronous => self.pwritebuf_sync(size, offset, whence),
			TransferMode::AsyncMPMC => self.pwritebuf_async(size, offset, whence),
		}
	}
	///Writes to the file descriptor. The message is in the IPC buffers.
	///
	///Returns the size of the data that was written on success, or the size
	///of the server-specific error status and an IOError on failure.
	pub fn writebuf(&self, size: usize) -> Result<usize, (usize, IOError)> {
		convert_offset_result(self.pwritebuf(size, 0, OffsetType::Current))
	}

	///Internal implementation of writebuf for synchronous FDs.
	fn pwritebuf_sync(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)>{
		if self.state.waiting_reply_size.load(Ordering::Acquire) > 0 {
			return Err((0, 0, IOError::InvalidOperation));
		}
		self.call_sync(MsgType::Write, size, offset, whence)
	}
	///Internal implementation of writebuf for asynchronous FDs.
	fn pwritebuf_async(&self, size: usize, offset: isize, whence: OffsetType) -> Result<(usize, usize), (usize, usize, IOError)>{
		unimplemented!()
	}
}

///Sends client-side clunk messages to servers
pub struct ClientClunkFileDescriptor {
	base_fd: BaseFileDescriptor,
}

impl ClientClunkFileDescriptor {
	///Creates a new client-side clunk file descriptor.
	pub fn new(endpoint: Endpoint, transfer: TransferMode) -> ClientClunkFileDescriptor {
		ClientClunkFileDescriptor {
			base_fd: BaseFileDescriptor::new(0, AccessMode::ReadWrite, transfer, endpoint),
		}
	}
	///Gets the endpoint (only intended for debugging and deallocation)
	#[inline]
	pub(crate) fn get_endpoint(&self) -> Option<Endpoint> {
		self.base_fd.endpoint
	}
	///Gets the transfer mode
	#[inline]
	pub fn get_transfer(&self) -> TransferMode {
		self.base_fd.get_transfer()
	}
	///Sends a Clunk message, which indicates that the FD has been closed
	///by the client.
	pub fn clunk(&self) -> Result<(), IOError> {
		match self.get_transfer() {
			TransferMode::Synchronous => self.clunk_sync(),
			TransferMode::AsyncMPMC => self.clunk_async(),
		}
	}
	///Internal implementation of `clunk` for synchronous FDs
	fn clunk_sync(&self) -> Result<(), IOError> {
		let buf = unsafe { &mut*(seL4_GetIPCBuffer()) };
		buf.msg[SIZE_IDX] = 0;
		buf.msg[OFFSET_IDX] = 0;
		let endpoint = self.get_endpoint().expect("no endpoint associated with file descriptor");

		endpoint.send(MsgType::Clunk as usize, NUM_RESERVED_REGS, 0);
		Ok(())
	}
	///Internal implementation of `clunk` for asynchronous FDs
	fn clunk_async(&self) -> Result<(), IOError> {
		unimplemented!()
	}
}
