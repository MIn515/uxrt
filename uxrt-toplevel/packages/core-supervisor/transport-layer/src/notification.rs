// Copyright 2023 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use intrusive_collections::UnsafeRef;

use sel4::Notification;

use crate::{
	AccessMode,
	BufferArray,
	IOError,
	IPCBuffers,
};

pub const NOTIFICATION_MSG_SIZE: usize = size_of::<usize>();

#[thread_local]
static mut RES_BUFFER: [usize; 1] = [0];

///The internal state of a notification FD
pub struct NotificationFileDescriptorState {
	errno: AtomicUsize,
}

impl NotificationFileDescriptorState {
	///Creates a new NotificationFileDescriptorState
	pub fn new() -> NotificationFileDescriptorState {
		NotificationFileDescriptorState {
			errno: AtomicUsize::new(0),
		}
	}
	///Puts this FD into an EOF condition
	pub fn seteof(&self){
		self.seterrno(usize::MAX);
	}
	///Puts this FD into an error condition with the specified error number
	pub fn seterrno(&self, errno: usize){
		self.errno.store(errno, Ordering::Relaxed);
	}
}

impl Clone for NotificationFileDescriptorState {
	fn clone(&self) -> NotificationFileDescriptorState {
		NotificationFileDescriptorState {
			errno: AtomicUsize::new(self.errno.load(Ordering::Relaxed)),
		}
	}
}

///A notification file descriptor.
#[derive(Clone)]
pub struct BaseNotificationFileDescriptor {
	id: i32,
	access: AccessMode,
	notification: Notification,
	state: UnsafeRef<NotificationFileDescriptorState>,
}

impl BaseNotificationFileDescriptor {
	///Creates a new notification file descriptor.
	pub fn new(id: i32, notification: Notification, access: AccessMode, state: UnsafeRef<NotificationFileDescriptorState>) -> BaseNotificationFileDescriptor {
		BaseNotificationFileDescriptor {
			id,
			access,
			notification,
			state,
		}
	}
	///Gets the ID
	#[inline]
	pub fn get_id(&self) -> i32 {
		self.id
	}
	///Gets the access mode
	#[inline]
	pub fn get_access(&self) -> AccessMode {
		self.access
	}
	///Gets the sizes of the primary and secondary IPC buffers associated
	///with this FD.
	#[inline]
	pub fn getbufsize(&self) -> (usize, usize) {
		(NOTIFICATION_MSG_SIZE, 0)
	}
	///Gets the size of the last message on this FD
	#[inline]
	pub fn getmsgsize(&self) -> usize {
		NOTIFICATION_MSG_SIZE
	}
	///Gets the offset of the last message on this FD
	#[inline]
	pub fn getmsgoffset(&self) -> usize {
		0
	}
	///Gets the IPC buffers associated with this file descriptor.
	///
	///These may change between messages, so this must be called after
	///every message.
	pub fn getbuf(&self) -> IPCBuffers {
		IPCBuffers {
			status: BufferArray::null(),
			primary: unsafe { BufferArray::new(RES_BUFFER.as_mut_ptr() as *mut u8, RES_BUFFER.len()) },
			secondary: BufferArray::null(),
		}
	}
	///Waits for the notification to be signalled. Copies the notification
	///word into the provided buffer.
	pub fn read(&self, buf: &mut [u8]) -> Result<usize, IOError> {
		let buf_size = buf.len(); 
		match self.readbuf(buf_size) {
			Ok(res) => {
				let sys_buf = self.getbuf();
				sys_buf.copyout(&mut buf[..buf_size], 0);
				Ok(res)
			},
			Err(err) => Err(err),
		}
	}
	///Waits for the notification to be signalled. Copies the notification
	///word into the system buffer.
	pub fn readbuf(&self, size: usize) -> Result<usize, IOError> {
		let res = self.notification.wait();
		unsafe { RES_BUFFER[0] = res };
		let errno = self.state.errno.load(Ordering::Relaxed);
		if errno == 0 {
			if size < NOTIFICATION_MSG_SIZE {
				Ok(size)
			}else{
				Ok(NOTIFICATION_MSG_SIZE)
			}
		}else if errno == usize::MAX {
			Ok(0)
		}else{
			Err(IOError::ServerError(errno))
		}
	}
	///Signals the notification. The buffer contents aren't used, although
	///the length affects the return value. 
	pub fn write(&self, buf: &[u8]) -> Result<usize, IOError>{
		self.writebuf(buf.len())
	}
	///Signals the notification.
	///
	///Returns the notification word size or the size argument (whichever 
	///is smaller) on success, 0 if the FD was closed, or an error on 
	///failure.
	pub fn writebuf(&self, size: usize) -> Result<usize, IOError>{
		let errno = self.state.errno.load(Ordering::Relaxed);
		if errno == 0 {
			self.notification.signal();
			unsafe { RES_BUFFER[0] = 0; }
			if size < NOTIFICATION_MSG_SIZE {
				Ok(size)
			}else{
				Ok(NOTIFICATION_MSG_SIZE)
			}
		}else if errno == usize::MAX {
			return Ok(0);
		}else{
			return Err(IOError::ServerError(errno));
		}
		
	}
}
