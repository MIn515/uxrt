// Copyright 2022-2023 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem::size_of;
use core::sync::atomic::{
	AtomicBool,
	AtomicI32,
	AtomicUsize, 
	Ordering
};

use static_assertions::const_assert;
use num_traits::FromPrimitive;

use sel4::{
	Endpoint,
	PAGE_SIZE,
	RecvToken,
	Reply,
	seL4_Word,
	reply_then_recv,
};

use sel4_sys::{
	seL4_GetIPCBuffer,
	seL4_MsgMaxLength,
	seL4_NumErrors,
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
	SRV_ERR_BADF,
	SRV_ERR_INVAL,
	SRV_ERR_NOSYS,
	SRV_ERR_NOTCONN,
	SIZE_IDX,
	TransferMode,
	UnsafeArray,
	debug_println,
	get_primary_array,
};

use intrusive_collections::UnsafeRef;

#[cfg(target_pointer_width = "64")]
type RawMsgType = u32;
#[cfg(target_pointer_width = "64")]
type RawOffsetType = u32;
type RawOffset = u64;

///The structure returned in the status buffer
///
///Includes the message type, as well as the offset and its type.
#[repr(C)]
pub struct MsgStatus {
	pub msgtype: RawMsgType,
	pub whence: RawOffsetType,
	pub offset: RawOffset,
}

impl MsgStatus {
	///Creates a `MsgStatus` from an `IPCBuffers` instance
	pub fn from_buf(buf: &IPCBuffers) -> &mut MsgStatus {
		let raw = buf.status.as_ptr();
		let s = raw as *mut MsgStatus;
		unsafe {
			let ref mut ret = *s;
			ret
		}
	}
	///Returns the message type as a `MsgType`
	pub fn msgtype_enum(&self) -> Option<MsgType> {
		MsgType::from_u64(self.msgtype as u64)
	}
	///Returns the offset type as an `OffsetType`
	pub fn whence_enum(&self) -> Option<OffsetType> {
		OffsetType::from_u64(self.whence as u64)
	}
}

pub const SECONDARY_BUFFER_ALIGN: usize = size_of::<SecondaryBufferInfo>(); 
const_assert!(size_of::<SecondaryBufferInfo>() <= SECONDARY_BUFFER_ALIGN);
const_assert!(PAGE_SIZE % SECONDARY_BUFFER_ALIGN == 0);

///An entry in the secondary buffer list for a thread
pub struct SecondaryBufferInfo {
	addr: usize,
}

impl SecondaryBufferInfo {
	///Creates a new `SecondaryBufferInfo` with a given address
	pub fn new(addr: usize) -> SecondaryBufferInfo {
		SecondaryBufferInfo {
			addr
		}
	}
	///Creates a new null `SecondaryBufferInfo`
	pub fn null() -> SecondaryBufferInfo {
		SecondaryBufferInfo::new(0)
	}
	///Gets the underlying buffer
	fn get_buffer(&self, size: usize) -> BufferArray {
		unsafe { BufferArray::new(self.addr as *mut u8, size) }
	}
}

static mut SECONDARY_BUFFERS: Option<UnsafeRef<UnsafeArray<SecondaryBufferInfo>>> = None;

///Sets the secondary buffer array of the calling thread
pub fn set_secondary_buffers(array: UnsafeRef<UnsafeArray<SecondaryBufferInfo>>){
	unsafe { SECONDARY_BUFFERS = Some(array) };
}

///Gets a secondary buffer from the calling thread's array
pub fn get_secondary_buffer(index: usize, size: usize) -> BufferArray {
	unsafe { SECONDARY_BUFFERS.as_ref().expect("secondary buffers not initialized")[index].get_buffer(size) }
}

const STATUS_SIZE: usize = NUM_RESERVED_REGS * size_of::<usize>();

///Internal shared state for a `ServerFileDescriptor`
pub struct ServerFileDescriptorState {
	written_size_set: AtomicBool,
	reply_pending: AtomicBool,
	last_secondary_offset: AtomicUsize,
	errno: AtomicUsize,
	current_offset: AtomicUsize,
	clunk_received: AtomicBool,
	last_msg_size: AtomicI32,
	last_msg_offset: AtomicUsize,
}

impl ServerFileDescriptorState {
	///Creates a new `BaseServerFileDescriptor`
	pub fn new() -> ServerFileDescriptorState {
		ServerFileDescriptorState {
			written_size_set: AtomicBool::new(false),
			reply_pending: AtomicBool::new(false),
			last_secondary_offset: AtomicUsize::new(0),
			errno: AtomicUsize::new(0),
			current_offset: AtomicUsize::new(0),
			clunk_received: AtomicBool::new(false),
			last_msg_size: AtomicI32::new(0),
			last_msg_offset: AtomicUsize::new(0),
		}
	}
}

///A server-side file descriptor
#[derive(Clone)]
pub(crate) struct BaseServerFileDescriptor {
	base_fd: BaseFileDescriptor,
	reply: Reply,
	combine_reply: bool,
	secondary_size: usize,
	state: UnsafeRef<ServerFileDescriptorState>,
}

impl BaseServerFileDescriptor {
	///Creates a new server file descriptor
	///
	///The access mode specifies what kind of accesses will be accepted
	///from a client, not what kinds of calls the server itself will be
	///allowed to make, since servers must always use both reads
	///(to accept messages) and writes (to reply to them).
	///
	///The combine_reply flag allows sending data with the reply to a
	///write message; the client can read the data by calling a
	///read()-family function, which will return immediately (this is
	///meant for servers with RPC-like semantics). It also causes reads
	///from the client that are not preceded by a write to automatically
	///fail (the server-side read will return InvalidOperation as for other
	///client-side protocol errors)
	pub fn new(id: i32, endpoint: Endpoint, reply: Reply, access: AccessMode, transfer: TransferMode, combine_reply: bool, mut secondary_size: usize, state: UnsafeRef<ServerFileDescriptorState>) -> BaseServerFileDescriptor {
		let base_fd = BaseFileDescriptor::new(id, access, transfer, endpoint);
		let max_secondary_size = (i32::MAX - base_fd.get_primary().len() as i32) as usize;
		if secondary_size > max_secondary_size {
			secondary_size = max_secondary_size;
		}
		BaseServerFileDescriptor {
			base_fd,
			reply,
			combine_reply,
			secondary_size,
			state,
		}
	}

	///Gets the endpoint (only intended for debugging and deallocation)
	#[inline]
	pub fn get_endpoint(&self) -> Option<Endpoint> {
		self.base_fd.endpoint
	}
	///Gets the reply (only intended for debugging and deallocation)
	#[inline]
	pub fn get_reply(&self) -> Reply {
		self.reply
	}
	///Gets the ID
	#[inline]
	pub fn get_id(&self) -> i32 {
		self.base_fd.get_id()
	}
	///Gets the transfer mode of the FD
	#[inline]
	pub fn get_transfer(&self) -> TransferMode {
		self.base_fd.get_transfer()
	}
	///Gets the access mode of the FD
	#[inline]
	pub fn get_access(&self) -> AccessMode {
		self.base_fd.get_access()
	}
	///Internal method to acquire the secondary buffer of the client thread
	fn acquire_secondary(&self, offset: usize){
		if self.secondary_size == 0 {
			return;
		}
		self.state.last_secondary_offset.store(offset, Ordering::Release);
	}
	///Internal method to release the secondary buffer of the client thread
	fn release_secondary(&self){
		if self.secondary_size == 0 {
			return;
		}
		self.state.last_secondary_offset.store(0, Ordering::Release);
	}
	///Sets the error number that will be sent with the reply
	///
	///Assuming no other errors occur, the client will receive Ok(size) if
	///errno is zero; otherwise it will receive
	///Err(size, offset, ServerError(errno))
	pub fn seterrno(&self, errno: usize){
		self.state.errno.store(errno, Ordering::Relaxed)
	}
	///Writes a reply to the file descriptor from the provided buffer.
	///
	///The semantics are otherwise the same as pwritebuf()
	pub fn pwrite(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<usize, IOError>{
		match self.get_transfer() {
			TransferMode::Synchronous => self.pwrite_sync(buf, offset, whence),
			TransferMode::AsyncMPMC => self.pwrite_async(buf, offset, whence),
		}
	}
	///Internal implementation of common functionality for `pwrite` and
	///`pwriteread` for synchronous FDs
	fn pwrite_sync_common(&self, buf: &[u8]) -> Result<usize, IOError>{
		let mut sys_buf = if let Some(b) = self.getbuf() {
			b
		}else{
			return Err(IOError::InvalidOperation);
		};
		sys_buf.copyin(&buf[..], 0);
		Ok(0) //the value is ignored by pwrite()/pwriteread(); they 
		      //only care that the call to this function succeeded
	}
	///Internal implementation of `pwrite` for synchronous FDs
	fn pwrite_sync(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<usize, IOError>{
		self.pwrite_sync_common(buf)?;
		self.pwritebuf_sync(buf.len(), offset, whence)
	}
	///Internal implementation of `pwrite` for asynchronous FDs
	fn pwrite_async(&self, buf: &[u8], offset: isize, whence: OffsetType) -> Result<usize, IOError>{
		unimplemented!()
	}
	///Writes a reply to the file descriptor from a user-provided buffer
	///
	///This returns the local saved offset to the client, (i.e. it is 
	///equivalent to pwrite with 0 as the offset and Current as the offset
	///type in both cases).
	///
	///The semantics are otherwise similar to pwrite().
	pub fn write(&self, buf: &[u8]) -> Result<usize, IOError> {
		self.pwrite(buf, self.state.current_offset.load(Ordering::Acquire) as isize, OffsetType::Start)
	}
	///Writes a reply to the file descriptor from the IPC buffers
	///
	///If combine_reply is true, this must be called twice for each message
	///to actually send a reply. The first call sets the written data size
	///to return to the client (the data is ignored), and the second sets
	///the size of the reply (which the client will read with a
	///read()-family function). The second call may be a
	///writeread()-family call in order to send a reply and wait for a new
	///message in the same call
	///
	///This returns InvalidOperation if no reply from a previous
	///read()-family call is pending
	pub fn pwritebuf(&self, size: usize, offset: isize, whence: OffsetType) -> Result<usize, IOError> {
		match self.get_transfer() {
			TransferMode::Synchronous => self.pwritebuf_sync(size, offset, whence),
			TransferMode::AsyncMPMC => self.pwritebuf_async(size, offset, whence),
		}
	}
	///Writes a reply to the file descriptor from the IPC buffers, returning
	///the saved offset to the client. This is equivalent to pwritebuf with
	///an offset of 0 and an offset type of Current
	pub fn writebuf(&self, size: usize) -> Result<usize, IOError> {
		self.pwritebuf(size, 0, OffsetType::Current)
	}
	///Internal implementation of writebuf for synchronous FDs
	fn pwritebuf_sync(&self, mut len: usize, offset: isize, whence: OffsetType) -> Result<usize, IOError> {
		debug_println!("pwritebuf_sync");
		if !self.state.reply_pending.load(Ordering::Acquire) {
			debug_println!("no reply pending");
			return Err(IOError::InvalidOperation);
		}
		match whence {
			OffsetType::Start => {},
			OffsetType::Current => {},
			_ => return Err(IOError::InvalidOperation),
		}
		
		if len > self.getmsgsize() {
			debug_println!("truncating message: {} {}", len, self.getmsgsize());
			len = self.getmsgsize();
		}
		
		if let Some(errno) = self.pwritebuf_sync_common(len, offset, whence){
			self.state.last_msg_size.store(0, Ordering::Relaxed);
			debug_println!("sending reply: {:?} {} {} {}", self.get_reply(), len, offset, errno);
			self.get_reply().send(errno + seL4_NumErrors as usize, IPCBuffers::get_primary_size(len), 0);
			debug_println!("reply sent");
			self.state.reply_pending.store(false, Ordering::Release);
		}
		Ok(len)
	}
	///Internal implementation of writebuf for asynchronous FDs
	fn pwritebuf_async(&self, size: usize, offset: isize, whence: OffsetType) -> Result<usize, IOError> {
		unimplemented!();
	}
	///Gets the IPC buffers associated with this file descriptor.
	///
	///The buffers are only valid between a call to readbuf() and the call
	///to writebuf() that replies to the message, and may be specific to
	///one thread.
	///
	pub fn getbuf(&self) -> Option<IPCBuffers>{
		if !self.state.reply_pending.load(Ordering::Acquire) {
			return None;
		}
		let secondary = if self.secondary_size > 0 && !self.state.clunk_received.load(Ordering::Relaxed) {
			let secondary_offset = self.state.last_secondary_offset.load(Ordering::Acquire);
			if secondary_offset == 0 {
				return None
			}else{
				get_secondary_buffer(secondary_offset, self.secondary_size)
			}
		}else{
			BufferArray::null()
		};
		Some(IPCBuffers::new(get_primary_array(0, NUM_RESERVED_REGS), self.base_fd.get_primary(), secondary))
	}
	///Gets the underlying primary and secondary buffer sizes
	pub fn getbufsize(&self) -> (usize, usize) {
		(seL4_MsgMaxLength as usize, self.secondary_size)
	}
	///Gets the size of the last message read from this FD
	pub fn getmsgsize(&self) -> usize {
		let size = self.state.last_msg_size.load(Ordering::Relaxed);
		if size < 0 {
			(-size) as usize
		}else{
			size as usize
		}
	}
	///Gets the offset of the last message read from this FD
	pub fn getmsgoffset(&self) -> usize {
		self.state.last_msg_offset.load(Ordering::Relaxed)
	}
	///Waits for an incoming message on a server-side FD. Returns the
	///message type and size on success or IOError on failure.
	///
	///If the message was a read, a reply should be sent with write()
	///
	///If the message was a write, the data should be read with read(),
	///processed, and then a reply sent with write() on success
	///
	///Failure conditions:
	///
	///A reply was pending from a previous message (InvalidOperation)
	///The received message size was bigger than the buffer size (MessageTooLong)
	///The received message was not permitted by the access mode (InvalidOperation)
	///No secondary buffer was present for an FD that requires one (InvalidOperation)
	///The received message had an invalid type (InvalidMessage)
	///
	/// This wraps seL4_Recv()
	pub fn readbuf(&self) -> Result<usize, IOError>{
		debug_println!("BaseServerFileDescriptor::readbuf");
		match self.get_transfer() {
			TransferMode::Synchronous => self.readbuf_sync(),
			TransferMode::AsyncMPMC => self.readbuf_async(),
		}
	}
	///Internal function to send an error reply on readbuf() failures
	fn readbuf_error_reply(&self, errno: usize, ret: IOError) -> Result<usize, IOError>{
		self.seterrno(errno);
		if self.combine_reply {
			if let Err(err) = self.pwritebuf(0, 0, OffsetType::Current){
				return Err(err)
			}
		}
		if let Err(err) = self.pwritebuf(0, 0, OffsetType::Current){
			Err(err)
		}else{
			Err(ret)
		}
	}
	///Inner internal implementation of readbuf()/writereadbuf()
	fn readbuf_sync_common(&self, msg: RecvToken) -> Result<usize, IOError> {
		//self.dump_primary_buffer();
		if self.state.reply_pending.load(Ordering::Acquire) {
			debug_println!("BaseServerFileDescriptor::readbuf_sync: reply still pending");
			return Err(IOError::InvalidOperation);
		}
		self.state.reply_pending.store(true, Ordering::Release);

		if let Some(msgtype) = MsgType::from_usize(msg.label & ((1<<seL4_WordBits/2) - 1)) {
			if msgtype == MsgType::Clunk {
				debug_println!("clunk received");
				self.state.clunk_received.store(true, Ordering::Relaxed);
			}
			let whence_opt = OffsetType::from_usize(msg.label >> (seL4_WordBits/2));
			if whence_opt.is_none() {
				debug_println!("BaseServerFileDescriptor::readbuf_sync: invalid offset type");
				return self.readbuf_error_reply(SRV_ERR_INVAL, IOError::InvalidMessage);
			}

			if !self.get_access().permitted(msgtype) {
				debug_println!("BaseServerFileDescriptor::readbuf_sync: operation not permitted");
				return self.readbuf_error_reply(SRV_ERR_BADF, IOError::InvalidMessage);
			}

			if self.combine_reply && msgtype as usize == MsgType::Read as usize {
				debug_println!("BaseServerFileDescriptor::readbuf_sync: read received on combined reply FD");
				return self.readbuf_error_reply(SRV_ERR_BADF, IOError::InvalidMessage);
			}
			debug_println!("secondary buffer offset: {}", msg.badge);
			self.acquire_secondary(msg.badge);
			let base_buf = unsafe { &mut*(seL4_GetIPCBuffer()) };
			let size = base_buf.msg[SIZE_IDX];
			if let Some(buf) = self.getbuf(){
				if size > buf.get_max_message_size() {
					return self.readbuf_error_reply(SRV_ERR_INVAL, IOError::MessageTooLong);
				}
				let mut last_msg_size = size as i32;
				if msgtype != MsgType::Write {
					last_msg_size = -last_msg_size;
				}
				self.state.last_msg_size.store(last_msg_size, Ordering::Relaxed);
				let status = MsgStatus::from_buf(&buf);
				//the offset doesn't have to be initialized
				//here since it the client already set it
				//FIXME: the types here depend on word size
				status.msgtype = msgtype as u32;
				status.whence = whence_opt.unwrap() as u32;
				Ok(size)
			}else{
				debug_println!("BaseServerFileDescriptor::readbuf_sync: buffer not set");
				self.readbuf_error_reply(SRV_ERR_BADF, IOError::InvalidOperation)
			}
		}else{
			self.readbuf_error_reply(SRV_ERR_NOSYS, IOError::InvalidMessage)
		}
	}
	///Internal implementation of readbuf() for synchronous FDs
	fn readbuf_sync(&self) -> Result<usize, IOError>{
		debug_println!("readbuf_sync");
		if self.state.reply_pending.load(Ordering::Acquire) {
			return Err(IOError::InvalidOperation);
		}
		let endpoint = self.get_endpoint().expect("file descriptor not associated with an endpoint");
		debug_println!("endpoint: {:x}", endpoint.to_cap());

		self.base_fd.begin_sync_wait();
		let msg = endpoint.recv(self.get_reply());
		self.base_fd.end_sync_wait();

		debug_println!("readbuf_sync done");
		self.readbuf_sync_common(msg)
	}
	///Internal implementation of readbuf() for asynchronous FDs
	fn readbuf_async(&self) -> Result<usize, IOError>{
		unimplemented!()
	}
	///Reads a message into a user-provided buffer
	///
	///This must be called twice for each message. The first call returns
	///the status (blocking if no message is available), and the second
	///immediately returns the data if the received message was a write.
	pub fn read(&self, buf: &mut [u8]) -> Result<usize, IOError> {
		match self.get_transfer() {
			TransferMode::Synchronous => self.read_sync(buf),
			TransferMode::AsyncMPMC => self.read_async(buf),
		}
	}
	///Internal implementation of `read` for synchronous FDs
	fn read_sync(&self, buf: &mut [u8]) -> Result<usize, IOError> {
		//last_msg_size is set by readbuf_sync
		let last_msg_size = self.state.last_msg_size.load(Ordering::Relaxed);
		let is_status = if last_msg_size > 0 {
			if buf.len() < self.base_fd.get_primary().len() + self.secondary_size {
				return Err(IOError::InvalidArgument);
			}
			false
		}else{
			if buf.len() < STATUS_SIZE {
				return Err(IOError::InvalidArgument);
			}
			match self.readbuf_sync() {
				Ok(_) => {	
					true
				},
				Err(err) => { return Err(err) },
			}
		};
		let sys_buf = if let Some(b) = self.getbuf() {
			b
		}else{
			return Err(IOError::InvalidOperation);
		};
		if is_status {
			buf[0..STATUS_SIZE].copy_from_slice(&sys_buf.status[0..STATUS_SIZE]);
			Ok(STATUS_SIZE)
		}else{
			let copied_size = sys_buf.copyout(&mut buf[..last_msg_size as usize], 0);
			Ok(copied_size)
		}
	}
	///Internal implementation of `read` for asynchronous FDs
	fn read_async(&self, buf: &mut [u8]) -> Result<usize, IOError> {
		unimplemented!()
	}
	///This is equivalent to pwrite() followed by pread(); the semantics are
	///the same as pwritereadbuf() except that it uses caller-provided
	///buffers (copying into and out of them from the system-level 
	///buffers).
	pub fn pwriteread(&self, w_buf: &mut [u8], r_buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<usize, IOError> {
		match self.get_transfer() {
			TransferMode::Synchronous => self.pwriteread_sync(w_buf, r_buf, offset, whence),
			TransferMode::AsyncMPMC => self.pwriteread_async(w_buf, r_buf, offset, whence),
		}
	}
	///Internal implementation of `pwriteread` for synchronous FDs
	fn pwriteread_sync(&self, w_buf: &mut [u8], r_buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<usize, IOError> {
		if r_buf.len() < STATUS_SIZE {
			return Err(IOError::InvalidArgument);
		}
		self.pwrite_sync_common(w_buf)?;
		let size = self.pwritereadbuf_sync(w_buf.len(), offset, whence)?;
		let sys_buf = if let Some(b) = self.getbuf(){
			b
		}else{
			return Err(IOError::InvalidOperation);
		};
		r_buf[0..STATUS_SIZE].copy_from_slice(&sys_buf.status[0..STATUS_SIZE]);
		Ok(STATUS_SIZE)			
	}
	///Internal implementation of `pwriteread` for asynchronous FDs
	fn pwriteread_async(&self, w_buf: &mut [u8], r_buf: &mut [u8], offset: isize, whence: OffsetType) -> Result<usize, IOError> {
		unimplemented!()
	}
	///This is equivalent to write() followed by read(); the semantics are
	///the same as pwritereadbuf() except that it uses caller-provided
	///buffers.
	pub fn writeread(&self, w_buf: &mut [u8], r_buf: &mut [u8]) -> Result<usize, IOError> {
		self.pwriteread(w_buf, r_buf, self.state.current_offset.load(Ordering::Acquire) as isize, OffsetType::Start)
	}

	///This is equivalent to pwritebuf() followed by preadbuf(); it wraps
	///seL4_ReplyRecv(). The transition from sending the reply to waiting
	///for a new message is atomic unlike separate pwritebuf() and
	///preadbuf() calls.
	///
	///If combine_reply is true, this must be preceded by a regular write
	///(any write()-family call will work) with the size of the written
	///data.
	///
	///The error returns are basically a combination of those of preadbuf()
	///and pwritebuf(). One extra error condition is if this is called
	///when combine_reply is true and a regular write()/writebuf() was not
	///called before this to set the written size (InvalidOperation will
	///be returned)
	pub fn pwritereadbuf(&self, len: usize, offset: isize, whence: OffsetType) -> Result<usize, IOError>{
		match self.get_transfer() {
			TransferMode::Synchronous => self.pwritereadbuf_sync(len, offset, whence),
			TransferMode::AsyncMPMC => self.pwritereadbuf_async(len, offset, whence),
		}
	}
	///This is equivalent to pwritebuf() followed by preadbuf(); semantics
	///are similar to pwritereadbuf(), but it returns the last saved offset
	///to the client rather than taking the offset as an argument
	pub fn writereadbuf(&self, size: usize) -> Result<usize, IOError> {
		self.pwritereadbuf(size, self.state.current_offset.load(Ordering::Acquire) as isize, OffsetType::Start)
	}

	///Internal implementation of writereadbuf() for asynchronous FDs
	fn pwritereadbuf_async(&self, len: usize, offset: isize, whence: OffsetType) -> Result<usize, IOError>{
		unimplemented!()
	}
	///Internal implementation of writereadbuf() for synchronous FDs
	fn pwritereadbuf_sync(&self, len: usize, offset: isize, whence: OffsetType) -> Result<usize, IOError>{
		if self.combine_reply && !(self.state.written_size_set.load(Ordering::Acquire)) {
			return Err(IOError::InvalidOperation);
		}
		if !self.state.reply_pending.load(Ordering::Acquire) {
			return Err(IOError::InvalidOperation);
		}

		match whence {
			OffsetType::Start => {},
			OffsetType::Current => {},
			_ => return Err(IOError::InvalidOperation),
		}


		let endpoint = self.get_endpoint().expect("file descriptor not associated with an endpoint");


		let errno = self.pwritebuf_sync_common(len, offset, whence).unwrap();
		debug_println!("replying and receiving: {:?} {:?} {} {}", self.reply, endpoint, len, offset);
		self.base_fd.begin_sync_wait();
		let msg = reply_then_recv(self.reply, errno + seL4_NumErrors as usize, IPCBuffers::get_primary_size(len), 0, endpoint);
		self.base_fd.end_sync_wait();

		debug_println!("reply/receive done");
		self.state.reply_pending.store(false, Ordering::Release);
		let ret = self.readbuf_sync_common(msg);
		ret
	}

	///Inner internal implementation of readbuf() for asynchronous FDs
	fn pwritebuf_sync_common(&self, size: usize, mut offset: isize, whence: OffsetType) -> Option<usize> {
		let mut ret = Some(self.state.errno.load(Ordering::Acquire));
		let buf = unsafe { &mut*(seL4_GetIPCBuffer()) };

		if self.combine_reply {
			debug_println!("pwritebuf_sync_common: combining reply");
			if self.state.written_size_set.load(Ordering::Acquire) {
				debug_println!("written size set");
				self.state.written_size_set.store(false, Ordering::Release);
				buf.msg[SIZE_IDX] = (size << (size_of::<MsgSize>()) * 8) as seL4_Word | buf.msg[SIZE_IDX];
				self.state.errno.store(0, Ordering::Relaxed);
				self.release_secondary();
				return ret;
			}else{
				debug_println!("written size not set");
				self.state.written_size_set.store(true, Ordering::Release);
				ret = None;
			}
		}

		let buf = unsafe { &mut*(seL4_GetIPCBuffer()) };
		buf.msg[SIZE_IDX] = size;
		if whence as usize == OffsetType::Current as usize {
			let prev_offset = self.state.current_offset.load(Ordering::Acquire);
			offset += prev_offset as isize;
		}
		buf.msg[OFFSET_IDX] = offset as usize;
		self.state.current_offset.store(offset as usize + size, Ordering::Release);
		if ret.is_some(){
			self.release_secondary();
			self.state.errno.store(0, Ordering::Relaxed);
		}

		ret
	}
	///Updates the stored offset.
	///
	///The offset type may be either Start (which sets the current offset
	///to the given offset) or Current (which adds the given offset to the
	///current offset). All other offset types return failure.
	///
	///Unlike for client-side FDs, this does not send messages at all.
	pub fn seek(&self, offset: isize, whence: OffsetType) -> Result<usize, (usize, usize, IOError)> {
		match whence {
			OffsetType::Start => {
				self.state.current_offset.store(offset as usize, Ordering::Release);
				Ok(offset as usize)
			}
			OffsetType::Current => {
				let prev_offset = self.state.current_offset.load(Ordering::Acquire);
				let cur_offset = prev_offset + offset as usize;
				self.state.current_offset.store(cur_offset, Ordering::Release);
				Ok(cur_offset)
			},
			_ => Err((0, 0, IOError::InvalidOperation)),
		}
	}
}

///A server-side clunk file descriptor, which sends clunk messages to clients
pub struct ServerClunkFileDescriptor {
	base_fd: BaseFileDescriptor,
	reply: Reply,
}

impl ServerClunkFileDescriptor {
	///Creates a new client-side file descriptor.
	pub fn new(endpoint: Endpoint, reply: Reply, transfer: TransferMode) -> ServerClunkFileDescriptor {
		ServerClunkFileDescriptor {
			base_fd: BaseFileDescriptor::new(0, AccessMode::ReadWrite, transfer, endpoint),
			reply
		}
	}
	///Gets the endpoint (only intended for debugging and deallocation)
	#[inline]
	pub(crate) fn get_endpoint(&self) -> Option<Endpoint> {
		self.base_fd.endpoint
	}
	///Gets the reply (only intended for debugging and deallocation)
	#[inline]
	pub(crate) fn get_reply(&self) -> Reply {
		self.reply
	}
	///Sends an error message indicating that the FD has been closed by the
	///server.
	///
	///This is only intended for use by the VFS layer, and not actual server
	///code.
	pub fn clunk(&self) -> Result<(), IOError>{
		match self.base_fd.get_transfer() {
			TransferMode::Synchronous => self.clunk_sync(),
			TransferMode::AsyncMPMC => self.clunk_async(),
		}
	}
	///Internal implementation of `clunk` for synchronous FDs
	fn clunk_sync(&self) -> Result<(), IOError>{
		let _ = self.get_endpoint().expect("no endpoint associated with clunk FD").recv(self.get_reply());
		let base_buf = unsafe { &mut*(seL4_GetIPCBuffer()) };
		base_buf.msg[SIZE_IDX] = 0;
		base_buf.msg[OFFSET_IDX] = 0;
		self.get_reply().send(SRV_ERR_NOTCONN + seL4_NumErrors as usize, NUM_RESERVED_REGS, 0);
		Ok(())
	}
	///Internal implementation of `clunk` for asynchronous FDs
	fn clunk_async(&self) -> Result<(), IOError>{
		unimplemented!()
	}
}
