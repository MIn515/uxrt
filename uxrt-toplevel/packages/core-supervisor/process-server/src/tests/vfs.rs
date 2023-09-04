/*
 * Copyright (c) 2022-2023 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This module includes core code for testing the VFS and transport layer.
 */

use alloc::sync::Arc;
use core::str;

use crate::job::thread::SysThread;

use usync::RwLock;

use uxrt_transport_layer::{
	AccessMode,
	BufferArray,
	FileDescriptor,
	FileDescriptorRef,
	IOError,
	MsgStatus,
	MsgType,
	NOTIFICATION_MSG_SIZE,
	OffsetType,
	SRV_ERR_BADF,
	SRV_ERR_NOSYS,
	SRV_ERR_INVAL,
	TransferMode,
};

use crate::vfs::transport::{
	FDFactory,
	FDType,
	FactoryCSpace,
	ThreadFD,
	get_root_fdspace,
	get_fd,
};

use crate::{
	dump_heap,
	dump_utspace,
};

use alloc::vec::Vec;

use sel4_sys::seL4_NumErrors;

const SECONDARY_BUFFER_SIZE: usize = 4096;

///Wrapper around preadbuf() that parses the message tyoe, size, 
///offset type, and offset received from a client
pub fn awaitmsg_copy(fd: &mut ThreadFD) -> Result<(usize, MsgType, usize, OffsetType), IOError> {
	//info!("awaitmsg");
	let (primary_size, _) = fd.getbufsize();
	let mut buf = vec![0u8; primary_size];
	//info!("awaitmsg: {} {}", primary_size, secondary_size);
	let res = fd.pread(&mut buf[..], 0, OffsetType::Start);
	awaitmsg_copy_common(&mut buf[..], res)
}

///Combines pwritebuf() and awaitmsg()
pub fn pwrite_awaitmsg(fd: &mut ThreadFD, buf: &mut [u8], offset: isize) -> Result<(usize, MsgType, usize, OffsetType), IOError> {
	let (primary_size, _) = fd.getbufsize();
	let mut status_buf = vec![0u8; primary_size];

	let res = fd.pwriteread(buf, &mut status_buf[..], offset, OffsetType::Start);
	awaitmsg_copy_common(&mut status_buf, res)
}

///Internal implementation of awaitmsg()
pub fn awaitmsg_copy_common(buf: &mut [u8], res: Result<(usize, usize), (usize, usize, IOError)>) -> Result<(usize, MsgType, usize, OffsetType), IOError> {
	match res {
		Ok((size, _)) => {
			let s = buf.as_ptr() as *mut MsgStatus;
			let status = unsafe {
                        	let ref mut st = *s;
				st
                  	};

			if let Some(msgtype) = status.msgtype_enum() && let Some(whence) = status.whence_enum() {
				Ok((size, msgtype, status.offset as usize, whence))
			}else{
				Err(IOError::InvalidMessage)
			}
		},
		Err((_, _, err)) => Err(err),
	}
}


fn test_server_basic_read(fd: &ThreadFD, mut primary: BufferArray, _secondary: BufferArray, size: usize, offset: usize, whence: OffsetType) -> (usize, usize) {
	info!("test server: received read of size {} offset {} whence {:?}", size, offset, whence);
	if whence as usize != OffsetType::Start as usize {
		info!("returning failure");
		fd.seterrno(SRV_ERR_INVAL).expect("failed to set errno");
		return (0, 0);
	}
	let test_string = "hello world".as_bytes();
	if offset < test_string.len(){
		primary[0..test_string.len() - offset].clone_from_slice(&test_string[offset..test_string.len()]);
	}
	(test_string.len() - offset, offset)
}

fn test_server_basic_write(fd: &ThreadFD, primary: BufferArray, secondary: BufferArray, mut size: usize, offset: usize, whence: OffsetType) -> (usize, usize) {
	info!("test server: received write of size {} offset {} whence {:?}", size, offset, whence);

	let mut primary_size = size;
	if size > primary.len(){
		primary_size = primary.len();
	}

	let primary_string = str::from_utf8(&primary[0..primary_size]).expect("received write with invalid UTF-8 characters");
	info!("primary contents: {}", primary_string);
	if size > primary_size{
		let secondary_string = str::from_utf8(&secondary[0..size - primary_size]).expect("received write with invalid UTF-8 characters");
		info!("secondary contents: {}", secondary_string);
	}
	if primary_string == "foobar" {
		info!("returning failure");
		size = 0;
		fd.seterrno(SRV_ERR_BADF).expect("failed to set errno");
	}
	(size, 0)
}

fn test_server_basic_inner(fd: &ThreadFD, size: usize, msgtype: MsgType, offset: usize, whence: OffsetType) -> Option<(usize, usize)> {
	let buf = fd.getbuf().expect("failed to get IPC buffers for server");
	let primary = buf.get_primary();
	let secondary = buf.get_secondary();
	match msgtype {
		MsgType::Read => {
			Some(test_server_basic_read(fd, primary, secondary, size, offset, whence))
		},
		MsgType::Write => {
			Some(test_server_basic_write(fd, primary, secondary, size, offset, whence))
		},
		MsgType::Clunk => {
			info!("clunk received");
			None
		},
	}
}

fn test_server_basic(fid: i32) {
	info!("test_server_basic");
	let mut fd = get_fd(fid);
	info!("test_server_basic got FD");	
	loop {
		let (size, msgtype, offset, whence) = fd.awaitmsg().expect("test server failed to get message");
		info!("test_server_basic: got message: {} {:?} {} {:?}", size, msgtype, offset, whence);
		if let Some((accepted_size, accepted_offset)) = test_server_basic_inner(&mut fd, size, msgtype, offset, whence) {
			fd.pwritebuf(accepted_size, accepted_offset as isize, OffsetType::Start).expect("failed to reply to message");
		}else{
			return;
		}
	}
}

fn test_server_basic_copy_read(fd: &ThreadFD, size: usize, offset: usize, whence: OffsetType) -> (Vec<u8>, usize) {
	info!("test server: received read of size {} offset {} whence {:?}", size, offset, whence);
	let sys_buf = fd.getbuf().expect("test_server_basic_copy_read: failed to get IPC buffers");
	let mut buf = vec![0u8; sys_buf.get_max_message_size()];

	if whence as usize != OffsetType::Start as usize {
		info!("returning failure");
		fd.seterrno(SRV_ERR_INVAL).expect("failed to set errno");
		buf.truncate(0);
		return (buf, 0);
	}
	let test_string = "hello world".as_bytes();
	let test_len = test_string.len() - offset;
	if offset < test_string.len(){
		buf[0..test_len].clone_from_slice(&test_string[offset..test_string.len()]);
	}
	buf.truncate(test_len);
	(buf, offset)
}

fn test_server_basic_copy_write(fd: &ThreadFD, mut size: usize, offset: usize, whence: OffsetType) -> (Vec<u8>, usize) {
	info!("test server: received write of size {} offset {} whence {:?}", size, offset, whence);

	let sys_buf = fd.getbuf().expect("test_server_basic_copy_write: failed to get IPC buffers");
	let mut buf = vec![0u8; sys_buf.get_max_message_size()];

	(size, _) = fd.pread(&mut buf[..], 0, OffsetType::Start).expect("failed to read message");

	let string = str::from_utf8(&buf[..size]).expect("received write with invalid UTF-8 characters");
	info!("buffer contents: {}", string);
	if string == "foobar" {
		info!("returning failure");
		size = 0;
		fd.seterrno(SRV_ERR_BADF).expect("failed to set errno");
	}
	buf.truncate(size);
	(buf, 0)
}

fn test_server_basic_copy_inner(fd: &ThreadFD, size: usize, msgtype: MsgType, offset: usize, whence: OffsetType) -> Option<(Vec<u8>, usize)> {
	match msgtype {
		MsgType::Read => {
			Some(test_server_basic_copy_read(fd, size, offset, whence))
		},
		MsgType::Write => {
			Some(test_server_basic_copy_write(fd, size, offset, whence))
		},
		MsgType::Clunk => {
			info!("clunk received");
			None
		},
	}
}

fn test_server_basic_copy(fid: i32) {
	info!("test_server_basic_copy");
	let mut fd = get_fd(fid);
	info!("test_server_basic_copy got FD");	
	loop {
		let (size, msgtype, offset, whence) = awaitmsg_copy(&mut fd).expect("test server failed to get message");
		info!("test_server_basic_copy: got message: {} {:?} {} {:?}", size, msgtype, offset, whence);
		if let Some((mut buf, accepted_offset)) = test_server_basic_copy_inner(&mut fd, size, msgtype, offset, whence) {
			fd.pwrite(&mut buf[..], accepted_offset as isize, OffsetType::Start).expect("failed to reply to message");
		}else{
			return;
		}
	}
}

fn test_server_basic_seek(fid: i32) {
	let mut fd = get_fd(fid);
	loop {
		info!("test_server_basic_seek: waiting for message");
		let (size, msgtype, offset, whence) = fd.awaitmsg().expect("test server failed to get message");
		if let Some((accepted_size, accepted_offset)) = test_server_basic_inner(&mut fd, size, msgtype, offset, whence) {
			fd.seek(accepted_offset as isize, OffsetType::Start).expect("failed to seek server FD");
			info!("test_server_basic_seek: sending reply");
			fd.writebuf(accepted_size).expect("failed to reply to message");
			assert!(
				fd.seek(0, OffsetType::Current).expect("could not check offset of server FD after write") == accepted_offset + accepted_size, 
				"seek on server FD returned incorrect offset"
			);

		}else{
			return;
		}

	}
}

fn test_server_basic_writereadbuf(fid: i32) {
	let mut fd = get_fd(fid);

	let (mut size, mut msgtype, mut offset, mut whence) = fd.awaitmsg().expect("test server failed to get message");
	loop {
		if let Some((received_size, received_offset)) = test_server_basic_inner(&mut fd, size, msgtype, offset, whence) {
			(size, msgtype, offset, whence) = fd.pwritebuf_awaitmsg(received_size, received_offset as isize).expect("test server failed to get message");
		}else{
			return;
		}
	}
}

fn test_server_basic_writeread(fid: i32) {
	let mut fd = get_fd(fid);

	let (mut size, mut msgtype, mut offset, mut whence) = awaitmsg_copy(&mut fd).expect("test server failed to get message");
	loop {
		if let Some((mut buf, received_offset)) = test_server_basic_copy_inner(&mut fd, size, msgtype, offset, whence) {
			(size, msgtype, offset, whence) = pwrite_awaitmsg(&mut fd, &mut buf[..], received_offset as isize).expect("test server failed to get message");
		}else{
			return;
		}
	}
}

fn check_bufs(buf1: &[u8], buf2: &[u8]) -> Result<(), ()> {
	info!("{} {}", buf1.len(), buf2.len());
	for i in 0..buf1.len(){
		if buf1[i] != buf2[i] {
			return Err(());
		}
	}
	Ok(())
}


fn test_client_basic_copy(fid: i32) {
	info!("test_client_basic_copy");
	let fd = get_fd(fid);
	info!("test_client_basic_copy got FD");

	let mut sys_buf = fd.getbuf().expect("no buffers for client FD");
	let test_string = "foo".as_bytes();
	let (mut size, mut offset) = fd.pwrite(test_string, 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {} to {}", size, offset);

	let mut buf = vec![0u8; sys_buf.get_max_message_size()];

	let mut c = 'a' as u8;
	for i in 0..buf.len(){
		if c > 'z' as u8 {
			c = 'a' as u8;
		}
		buf[i] = c;
		c += 1;
	}

	let mut copy_buf0 = vec![0u8; sys_buf.get_max_message_size()];
	sys_buf.copyin(&buf[..], 0);	
	sys_buf.copyout(&mut copy_buf0[..], 0);	
	check_bufs(&buf[..], &copy_buf0[..]).expect("copyin()/copyout() failed to copy entire buffer properly");

	let primary_size = sys_buf.get_primary().len();
	let secondary_size = sys_buf.get_secondary().len();

	let mut copy_buf1 = vec![0u8; primary_size];
	sys_buf.copyout(&mut copy_buf1[..], 0);
	check_bufs(&buf[..primary_size], &copy_buf1[..]).expect("copyin()/copyout() failed to copy primary buffer properly");

	let mut copy_buf2 = vec![0u8; secondary_size];
	sys_buf.copyout(&mut copy_buf2[..], primary_size);
	check_bufs(&buf[primary_size..], &copy_buf2[..]).expect("copyin()/copyout() failed to copy secondary buffer properly");

	let mut copy_buf3 = vec![0u8; secondary_size + primary_size / 2];
	sys_buf.copyout(&mut copy_buf3[..], primary_size / 2);
	check_bufs(&buf[primary_size / 2..], &copy_buf3[..]).expect("copyin()/copyout() failed to copy across buffers properly");

	let mut copy_buf4 = vec![0u8; secondary_size / 2 + primary_size / 2];
	sys_buf.copyout(&mut copy_buf4[..], primary_size / 2);
	check_bufs(&buf[primary_size / 2..secondary_size / 2], &copy_buf4[..]).expect("copyin()/copyout() failed to copy across buffers properly");

	let mut copy_buf5 = vec![0u8; secondary_size + primary_size];
	sys_buf.copyout(&mut copy_buf5[..], primary_size);
	check_bufs(&buf[primary_size..], &copy_buf5[..secondary_size]).expect("copyin()/copyout() failed to copy secondary buffer properly");

	let mut copy_buf6 = vec![0u8; secondary_size + primary_size];
	sys_buf.copyout(&mut copy_buf6[..], primary_size / 2);
	check_bufs(&buf[primary_size / 2..], &copy_buf6[..secondary_size + primary_size / 2]).expect("copyin()/copyout() failed to copy secondary buffer properly");

	let mut copy_buf7 = vec![0u8; sys_buf.get_max_message_size() + primary_size];
	sys_buf.copyin(&buf[..], 0);	
	sys_buf.copyout(&mut copy_buf7[..], 0);	
	check_bufs(&buf[..], &copy_buf7[..sys_buf.get_max_message_size()]).expect("copyin()/copyout() failed to copy entire buffer properly");


	(size, offset) = fd.pwrite(&buf[..], 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {} to {}", size, offset);

	const READ_SIZE: usize = 16;
	(size, offset) = fd.pread(&mut buf[0..READ_SIZE], 0, OffsetType::Start).expect("failed to read message");
	info!("read {} from {}", size, offset);
	let string = str::from_utf8(&buf[0..size]).expect("read message with invalid UTF-8 characters");
	info!("contents: {}", string);
	assert!(string == "hello world", "invalid response {} received from read", string);
	assert!(offset == 0, "invalid offset {} received from read", offset);

	const READ_OFFSET: isize = 5;
	(size, offset) = fd.pread(&mut buf[0..READ_SIZE], READ_OFFSET, OffsetType::Start).expect("failed to read message");
	info!("read {} from {}", size, offset);
	let string = str::from_utf8(&buf[0..size]).expect("read message with invalid UTF-8 characters");
	info!("contents: {}", string);
	assert!(string == " world", "invalid response received from read");
	assert!(offset as isize == READ_OFFSET, "invalid offset received from read");
	
	let test_string = "foobar".as_bytes();
	buf[..test_string.len()].clone_from_slice(test_string);
	let (size, offset, err) = fd.pwrite(&mut buf[0..test_string.len()], 0, OffsetType::Start).expect_err("server falsely returned success");
	match err {
		IOError::ServerError(SRV_ERR_BADF) => {},
		_ => panic!("unexpected error received"),
	}
	assert!(size == 0, "invalid size received from read error");
	assert!(offset == 0, "invalid offset received from read error");


	let (size, offset, err) = fd.pread(&mut buf[0..test_string.len()], 5, OffsetType::End).expect_err("server falsely returned success");
	match err {
		IOError::ServerError(SRV_ERR_INVAL) => {},
		_ => panic!("unexpected error received"),
	}
	assert!(size == 0, "invalid size received from read error");
	assert!(offset == 0, "invalid offset received from read error");
}


fn test_client_basic(fid: i32) {
	info!("test_client_basic");
	let fd = get_fd(fid);
	info!("test_client_basic got FD");

	let buf = fd.getbuf().expect("no buffers for client FD");
	let test_string = "foo".as_bytes();
	buf.get_primary()[..test_string.len()].clone_from_slice(test_string);
	let (mut size, mut offset) = fd.pwritebuf(test_string.len(), 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {} to {}", size, offset);


	let primary_len = buf.get_primary().len();
	for i in 0..buf.get_primary().len(){
		buf.get_primary()[i] = 'a' as u8;
	}
	let secondary_len = buf.get_secondary().len();
	for i in 0..buf.get_secondary().len(){
		buf.get_secondary()[i] = 'b' as u8;
	}
	(size, offset) = fd.pwritebuf(primary_len + secondary_len, 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {} to {}", size, offset);

	const READ_SIZE: usize = 16;
	(size, offset) = fd.preadbuf(READ_SIZE, 0, OffsetType::Start).expect("failed to read message");
	info!("read {} from {}", size, offset);
	let primary = buf.get_primary();
	let string = str::from_utf8(&primary[0..size]).expect("read message with invalid UTF-8 characters");
	info!("contents: {}", string);
	assert!(string == "hello world", "invalid response received from read");
	assert!(offset == 0, "invalid offset received from read");

	const READ_OFFSET: isize = 5;
	(size, offset) = fd.preadbuf(16, READ_OFFSET, OffsetType::Start).expect("failed to read message");
	info!("read {} from {}", size, offset);
	let primary = buf.get_primary();
	let string = str::from_utf8(&primary[0..size]).expect("read message with invalid UTF-8 characters");
	info!("contents: {}", string);
	assert!(string == " world", "invalid response received from read");
	assert!(offset as isize == READ_OFFSET, "invalid offset received from read");
	
	let buf = fd.getbuf().expect("no buffers for client FD");
	let test_string = "foobar".as_bytes();
	buf.get_primary()[..test_string.len()].clone_from_slice(test_string);
	let (size, offset, err) = fd.pwritebuf(test_string.len(), 0, OffsetType::Start).expect_err("server falsely returned success");
	match err {
		IOError::ServerError(SRV_ERR_BADF) => {},
		_ => panic!("unexpected error received"),
	}
	assert!(size == 0, "invalid size received from read error");
	assert!(offset == 0, "invalid offset received from read error");


	let (size, offset, err) = fd.preadbuf(test_string.len(), 5, OffsetType::End).expect_err("server falsely returned success");
	match err {
		IOError::ServerError(SRV_ERR_INVAL) => {},
		_ => panic!("unexpected error received"),
	}
	assert!(size == 0, "invalid size received from read error");
	assert!(offset == 0, "invalid offset received from read error");
}


fn test_server_combined_inner(fd: &ThreadFD, size: usize, msgtype: MsgType) -> Option<usize> {
	let buf = fd.getbuf().expect("failed to get IPC buffers for server");
	match msgtype {
		MsgType::Read => {
			panic!("read received on FD with combined reply enabled");
		},
		MsgType::Write => {
			let mut primary = buf.get_primary();
			info!("test server: received write of {}", size);
			let string = str::from_utf8_mut(&mut primary[0..size]).expect("received write with invalid UTF-8 characters");
			string.make_ascii_uppercase();
			info!("contents: {}", string);
			fd.pwritebuf(size, 0, OffsetType::Start).expect("failed to set accepted size of write message");
			Some(size)
		},
		MsgType::Clunk => {
			None
		},
	}
}

fn test_server_combined(fid: i32) {
	let mut fd = get_fd(fid);
	loop {
		let (size, msgtype, _, _) = match fd.awaitmsg() {
			Ok(res) => res,
			Err(err) => match err {
				IOError::InvalidMessage => continue,
				_ => panic!("unexpected error when trying to get message: {}", err),
			},
		};
		if let Some(received_size) = test_server_combined_inner(&mut fd, size, msgtype) {
			fd.pwritebuf(received_size, 0, OffsetType::Start).expect("failed to reply to message");
		}else{
			return;
		}

	}
}

fn test_server_combined_writereadbuf(fid: i32) {
	let mut fd = get_fd(fid);
	let mut res = fd.awaitmsg();	
	loop {
		let (size, msgtype, _, _) = match res {
			Ok(res) => res,
			Err(err) => match err {
				IOError::InvalidMessage => {
					res = fd.awaitmsg();
					continue;
				},
				_ => panic!("unexpected error when trying to get message: {}", err),
			},
		};

		if let Some(received_size) = test_server_combined_inner(&mut fd, size, msgtype){
			res = fd.pwritebuf_awaitmsg(received_size, 0);
		}else{
			return;
		}
	}
}


fn test_server_combined_copy_inner(fd: &ThreadFD, size: usize, msgtype: MsgType) -> Option<Vec<u8>> {
	let sys_buf = fd.getbuf().expect("failed to get IPC buffers for server");
	match msgtype {
		MsgType::Read => {
			panic!("read received on FD with combined reply enabled");
		},
		MsgType::Write => {
			let mut buf = vec![0u8; sys_buf.get_max_message_size()];

			let (read_size, _) = fd.pread(&mut buf[..], 0, OffsetType::Start).expect("could not read message from client");
			info!("test server: received write of {}", size);
			let string = str::from_utf8_mut(&mut buf[..read_size]).expect("received write with invalid UTF-8 characters");
			string.make_ascii_uppercase();
			info!("contents: {}", string);
			fd.pwrite(&buf[..read_size], 0, OffsetType::Start).expect("failed to set accepted size of write message");
			buf.truncate(read_size);
			Some(buf)
		},
		MsgType::Clunk => {
			None
		},
	}
}

fn test_server_combined_copy(fid: i32) {
	let mut fd = get_fd(fid);
	loop {
		let (size, msgtype, _, _) = match fd.awaitmsg() {
			Ok(res) => res,
			Err(err) => match err {
				IOError::InvalidMessage => continue,
				_ => panic!("unexpected error when trying to get message: {}", err),
			},
		};
		if let Some(buf) = test_server_combined_copy_inner(&mut fd, size, msgtype) {
			fd.pwrite(&buf[..], 0, OffsetType::Start).expect("failed to reply to message");
		}else{
			return;
		}

	}
}

fn test_client_combined(fid: i32) {
	let fd = get_fd(fid);
	info!("attempting to read");
	let (size, offset, err) = fd.preadbuf(16, 0, OffsetType::Start).expect_err("server falsely returned success");
	match err {
		IOError::ServerError(SRV_ERR_BADF) => {},
		_ => panic!("unexpected error received"),
	}
	assert!(size == 0, "invalid size received from read error");
	assert!(offset == 0, "invalid offset received from read error");

	info!("writing test message");
	let buf = fd.getbuf().expect("failed to get IPC buffers for client");

	let test_string = "foo".as_bytes();
	buf.get_primary()[..test_string.len()].clone_from_slice(test_string);
	let (mut size, mut offset) = fd.pwritebuf(test_string.len(), 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {} at {}", size, offset);
	assert!(offset == 0, "invalid offset received from write");

	(size, offset) = fd.preadbuf(test_string.len(), 0, OffsetType::Start).expect("failed to read message");
	info!("read {}", size);
	let primary = buf.get_primary();
	let uc_string = str::from_utf8(&primary[0..test_string.len()]).expect("read message with invalid UTF-8 characters");
	assert!(uc_string == "FOO", "server returned invalid result {}", uc_string);
	assert!(offset == 0, "invalid offset received from read");
}

fn test_client_combined_copy(fid: i32) {
	const BUF_SIZE: usize = 16;
	let fd = get_fd(fid);
	info!("attempting to read");
	let mut buf = vec![0u8; BUF_SIZE];
	let (size, offset, err) = fd.pread(&mut buf[..], 0, OffsetType::Start).expect_err("server falsely returned success");
	match err {
		IOError::ServerError(SRV_ERR_BADF) => {},
		_ => panic!("unexpected error received"),
	}
	assert!(size == 0, "invalid size received from read error");
	assert!(offset == 0, "invalid offset received from read error");

	let test_string = "foo".as_bytes();
	let (mut size, mut offset) = fd.pwrite(&test_string, 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {} at {}", size, offset);
	assert!(offset == 0, "invalid offset received from write");

	(size, offset) = fd.pread(&mut buf[..], 0, OffsetType::Start).expect("failed to read message");
	info!("read {}", size);
	let uc_string = str::from_utf8(&buf[..size]).expect("read message with invalid UTF-8 characters");
	assert!(uc_string == "FOO", "server returned invalid result {}", uc_string);
	assert!(offset == 0, "invalid offset received from read");
}

fn test_client_readonly(fid: i32) {
	let fd = get_fd(fid);
	let buf = fd.getbuf().expect("failed to get IPC buffers for client");
	let test_string = "foo".as_bytes();
	buf.get_primary()[..test_string.len()].clone_from_slice(test_string);
	let (mut size, mut offset, err) = fd.pwritebuf(test_string.len(), 0, OffsetType::Start).expect_err("server accepted a write on a read-only FD");
	match err {
		IOError::ServerError(SRV_ERR_BADF) => {},
		_ => { panic!("unexpected error {:?} received from invalid write", err); },
	}
	assert!(offset == 0, "invalid offset received from write error");
	assert!(size == 0, "invalid size received from write error");

	info!("wrote {}", size);

	(size, offset) = fd.preadbuf(16, 0, OffsetType::Start).expect("failed to read message");
	info!("read {}", size);
	let primary = buf.get_primary();
	let string = str::from_utf8(&primary[0..size]).expect("read message with invalid UTF-8 characters");
	info!("contents: {}", string);
	assert!(offset == 0, "invalid offset received from read");
}

fn test_server_readonly_inner(fd: &ThreadFD, size: usize, msgtype: MsgType, offset: usize, whence: OffsetType) -> Option<(usize, usize)> {
	let buf = fd.getbuf().expect("failed to get IPC buffers for server");
	let primary = buf.get_primary();
	let secondary = buf.get_secondary();
	match msgtype {
		MsgType::Read => {
			Some(test_server_basic_read(fd, primary, secondary, size, offset, whence))
			
		},
		MsgType::Write => {
			panic!("write received on read-only FD");
		},
		MsgType::Clunk => {
			None
		},
	}
}

fn test_server_readonly(fid: i32) {
	let mut fd = get_fd(fid);
	loop {
		let res = fd.awaitmsg();
		if res.is_err(){
			continue;
		}
		let (size, msgtype, offset, whence) = res.unwrap();
		if let Some((received_size, received_offset)) = test_server_readonly_inner(&mut fd, size, msgtype, offset, whence) {
			fd.pwritebuf(received_size, received_offset as isize, OffsetType::Start).expect("failed to reply to message");
		}else{
			return
		}
	}
}

fn test_server_readonly_writereadbuf(fid: i32) {
	let mut fd = get_fd(fid);
	let mut res = Err(IOError::InvalidOperation);
	loop {
		if let Ok((size, msgtype, offset, whence)) = res {
			if let Some((received_size, received_offset)) = test_server_readonly_inner(&mut fd, size, msgtype, offset, whence) {
				res = fd.pwritebuf_awaitmsg(received_size, received_offset as isize);
			}else{
				return;
			}
		}else{
			res = fd.awaitmsg();
		}
		
	}
}

fn test_server_writeonly_inner(fd: &ThreadFD, size: usize, msgtype: MsgType, offset: usize, whence: OffsetType) -> Option<(usize, usize)> {
		let buf = fd.getbuf().expect("failed to get IPC buffers for server");
		let primary = buf.get_primary();
		let secondary = buf.get_primary();

		match msgtype {
			MsgType::Read => {
				panic!("read received on write-only FD");
			},
			MsgType::Write => {
				Some(test_server_basic_write(fd, primary, secondary, size, offset, whence))
			},
			MsgType::Clunk => {
				None
			},
		}
}

fn test_client_writeonly(fid: i32) {
	let fd = get_fd(fid);
	let (mut size, mut offset, err) = fd.preadbuf(16, 0, OffsetType::Start).expect_err("server accepted a read on a write-only FD");
	match err {
		IOError::ServerError(SRV_ERR_BADF) => {},
		_ => { panic!("unexpected error {:?} received from invalid read", err); },
	}
	info!("read {}", size);

	assert!(offset == 0, "invalid offset received from read error");

	let buf = fd.getbuf().expect("failed to get IPC buffers for client");
	let test_string = "foo".as_bytes();
	buf.get_primary()[..test_string.len()].clone_from_slice(test_string);
	(size, offset) = fd.pwritebuf(test_string.len(), 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {}", size);
	assert!(offset == 0, "invalid offset received from write");
}


fn test_server_writeonly_writereadbuf(fid: i32) {
	let mut fd = get_fd(fid);
	let mut res = Err(IOError::InvalidOperation);
	loop {
		if let Ok((size, msgtype, offset, whence)) = res {
			if let Some((received_size, received_offset)) = test_server_writeonly_inner(&mut fd, size, msgtype, offset, whence) {
				res = fd.pwritebuf_awaitmsg(received_size, received_offset as isize);
			}else{
				return;
			}
			
		}else{
			res = fd.awaitmsg();
		}
		
	}
}

fn test_server_writeonly(fid: i32) {
	let mut fd = get_fd(fid);
	loop {
		let res = fd.awaitmsg();
		if res.is_err(){
			continue;
		}
		let (size, msgtype, offset, whence) = res.unwrap();
		if let Some((received_size, received_offset)) = test_server_writeonly_inner(&mut fd, size, msgtype, offset, whence) {
			fd.pwritebuf(received_size, received_offset as isize, OffsetType::Start).expect("failed to reply to message");
		}else{
			return;
		}
		
	}
}

fn test_server_error_sequence(fid: i32) {
	let mut fd = get_fd(fid);
	info!("attempting write without pending reply");
	let mut res = fd.pwritebuf(1, 0, OffsetType::Start).expect_err("write succeeded without pending reply");
	match res.2 {
		IOError::InvalidOperation => {},
		_ => { panic!("unexpected error received from invalid write"); },
	}

	info!("attempting combined write/read without pending reply");
	res = fd.pwritereadbuf(1, 0, OffsetType::Start).expect_err("write succeeded without pending reply");
	match res.2 {
		IOError::InvalidOperation => {},
		_ => { panic!("unexpected error received from invalid combined write/read"); },
	}

	info!("reading message from client");
	fd.awaitmsg().expect("could not read message");
	let err = fd.awaitmsg().expect_err("reading new message with pending reply succeeded");
	match err {
		IOError::InvalidOperation => {},
		_ => { panic!("unexpected error received from invalid read"); },
	}

	info!("attempting combined write/read without writing accepted size");
	res = fd.pwritereadbuf(1, 0, OffsetType::Start).expect_err("combined write/read succeeded before accepted size was written");
	match res.2 {
		IOError::InvalidOperation => {},
		_ => { panic!("unexpected error received from invalid combined write/read"); },
	}

	info!("writing accepted size");
	fd.pwritebuf(1, 0, OffsetType::Start).expect("writing accepted size failed");
	info!("writing reply size");
	fd.pwritebuf(1, 0, OffsetType::Start).expect("writing reply size failed");
}

fn test_server_error_oversized(fid: i32) {
	let mut fd = get_fd(fid);

	info!("attempting to read oversized message");
	let res = fd.awaitmsg().expect_err("reading oversized message succeeded");
	match res {
		IOError::MessageTooLong => {},
		_ => { panic!("unexpected error received from invalid read"); },
	}
}
fn test_server_error_invalid(fid: i32) {
	let mut fd = get_fd(fid);

	info!("attempting to read message with invalid type");
	let res = fd.awaitmsg().expect_err("reading message with invalid type succeeded");
	match res {
		IOError::InvalidMessage => {},
		_ => { panic!("unexpected error received from invalid read"); },
	}
	info!("end of error test server");
}

fn test_client_error_sequence(fid: i32) {
	let fd = get_fd(fid);
	info!("sending test message");

	let (mut size, mut offset) = fd.pwritebuf(1, 0, OffsetType::Start).expect("failed to write message");
	info!("wrote {}", size);
	let (_, _, err) = fd.pwritebuf(1, 0, OffsetType::Start).expect_err("write with a pending reply succeeded");
	match err {
		IOError::InvalidOperation => {},
		_ => { panic!("unexpected error received from invalid read"); },
	}
	assert!(offset == 0, "invalid offset received from invalid read");

	info!("reading result of test message");
	(size, offset) = fd.preadbuf(1, 0, OffsetType::Start).expect("failed to read message");
	info!("read {}", size);
	assert!(offset == 0, "invalid offset received from read");
}

fn test_client_error_oversized(fid: i32) {
	let fd = get_fd(fid);
	let buf = fd.getbuf().expect("failed to get IPC buffers for client FD");
	let max_size = buf.get_max_message_size();
	let size = max_size * 2;
	info!("sending oversized message (size: {}, max: {})", size, max_size);
	let (_, _, err) = fd.pwritebuf(size, 0, OffsetType::Start).expect_err("server accepted oversized message");
	match err {
		IOError::ServerError(SRV_ERR_INVAL) => {},
		_ => { panic!("unexpected error {:?} received from oversized message", err); },
	}
	info!("wrote {}", size);
}

fn test_client_error_invalid(fid: i32) {
	info!("sending invalid message");
	let fd = get_fd(fid);
	let endpoint = fd.get_endpoint().expect("could not get endpoint for FD");
	//XXX: this makes assumptions about transport layer internals (maybe
	//it would be a good idea to write a dedicated test driver and move
	//these tests to the transport layer crate)
	match endpoint.call(0xdeadbeef, 2, 0){
		Ok(msg) => {
			if msg.label != SRV_ERR_NOSYS + seL4_NumErrors as usize {
				panic!("unexpected error code received from invalid message");
			}
		},
		Err(err) => {
			panic!("unexpected system call error {:?} received from invalid message", err);
		},
	}
	info!("end of error test client");
}

pub fn run_transport_layer_channel_test(server_fn: fn(i32), client_fn: fn(i32), threads: &mut Vec<Arc<RwLock<SysThread>>>, access: AccessMode, combine_reply: bool, share_state: bool) {
	let (server_factory, client_factory) = FDFactory::new(FDType::IPCChannel, access, TransferMode::Synchronous, combine_reply, SECONDARY_BUFFER_SIZE, FactoryCSpace::Root, FactoryCSpace::Root, share_state, share_state).expect("could not allocate file descriptors for test");

	info!("getting FDSpace");
	let tmp = get_root_fdspace();
	let mut fdspace = tmp.write();
	info!("done");
	info!("adding server factory");
	let server_id = fdspace.insert(server_factory, None).expect("could not add server FD to FDSpace");
	info!("adding client factory");
	let client_id = fdspace.insert(client_factory, None).expect("could not add client FD to FDSpace");
	info!("done");
	drop(fdspace);

	info!("Heap status after FD allocation:");
	dump_heap();	
	info!("UTSpace status after FD allocation:");
	dump_utspace();

	info!("getting threads");
	let mut server = threads[0].write();
	let mut client = threads[1].write();

	info!("starting server");
	server.run(move ||{
		server_fn(server_id);
		None
	}).expect("could not start server thread");

	info!("starting client");
	client.run(move ||{
		client_fn(client_id);
		None
	}).expect("could not start client thread");
	client.get_exit_endpoint().unwrap().recv_refuse_reply();

	let tmp = get_root_fdspace();
	let mut fdspace = tmp.write();
	fdspace.remove(client_id).expect("could not deallocate client FD");
	info!("waiting for server to exit");
	server.get_exit_endpoint().unwrap().recv_refuse_reply();
	fdspace.remove(server_id).expect("could not deallocate server FD");
	info!("Heap status after FD deallocation:");
	dump_heap();
	info!("UTSpace status after FD deallocation:");
	dump_utspace();
}

pub fn run_transport_layer_notification_tests(threads: &mut Vec<Arc<RwLock<SysThread>>>, share_state: bool){
	let (server_factory, client_factory) = FDFactory::new(FDType::Notification, AccessMode::ReadWrite, TransferMode::AsyncMPMC, false, 0, FactoryCSpace::Root, FactoryCSpace::Root, share_state, share_state).expect("could not allocate file descriptors for test");

	info!("getting FDSpace");
	let tmp = get_root_fdspace();
	let mut fdspace = tmp.write();
	info!("done");
	info!("adding server factory");
	let server_id = fdspace.insert(server_factory, None).expect("could not add server FD to FDSpace");
	info!("adding client factory");
	let client_id = fdspace.insert(client_factory, None).expect("could not add client FD to FDSpace");
	info!("done");
	drop(fdspace);

	info!("server: {} client: {}", server_id, client_id);

	info!("getting threads");
	let mut client = threads[0].write();

	info!("starting client");
	client.run(move ||{
		let client_fd = get_fd(client_id);
		info!("trying to read from notification FD");
		let mut size = client_fd.readbuf(NOTIFICATION_MSG_SIZE).expect("could not read from notification FD");
		if size != NOTIFICATION_MSG_SIZE {
			panic!("incorrect message size {} returned from notification FD", size);
		}
		info!("waiting for notification FD to be closed");
		size = client_fd.readbuf(1).expect("could not read from notification FD");
		if size != 0 {
			panic!("incorrect message size {} returned from notification FD", size);
		}
		None
	}).expect("could not start client thread");
	sel4::yield_now();

	info!("getting server FD");
	let server_fd = get_fd(server_id);
	info!("signalling notification");
	server_fd.writebuf(NOTIFICATION_MSG_SIZE).expect("could not write message to notification FD");
	info!("done");
	sel4::yield_now();

	let tmp = get_root_fdspace();
	let mut fdspace = tmp.write();
	info!("deallocating server FD: {}", server_id);
	fdspace.remove(server_id).expect("could not deallocate server FD");
	info!("done");
	sel4::yield_now();

	info!("waiting for client to exit");
	client.get_exit_endpoint().unwrap().recv_refuse_reply();
	info!("deallocating client FD");
	fdspace.remove(client_id).expect("could not deallocate client FD");
	info!("Heap status after FD deallocation:");
	dump_heap();
	info!("UTSpace status after FD deallocation:");
	dump_utspace();
}

pub fn test_vfs_inner(threads: &mut Vec<Arc<RwLock<SysThread>>>, share_state: bool){
	info!("testing transport layer");

	info!("running basic test");
	run_transport_layer_channel_test(test_server_basic, test_client_basic, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with copy on both sides");
	run_transport_layer_channel_test(test_server_basic_copy, test_client_basic_copy, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with copy on server only");
	run_transport_layer_channel_test(test_server_basic_copy, test_client_basic, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with copy on client only");
	run_transport_layer_channel_test(test_server_basic, test_client_basic_copy, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with seek");
	run_transport_layer_channel_test(test_server_basic_seek, test_client_basic, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with combined write/read");
	run_transport_layer_channel_test(test_server_basic_writereadbuf, test_client_basic, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with combined write/read and copy on both sides");
	run_transport_layer_channel_test(test_server_basic_writeread, test_client_basic_copy, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with combined write/read and copy on server only");
	run_transport_layer_channel_test(test_server_basic_writeread, test_client_basic, threads, AccessMode::ReadWrite, false, share_state);
	info!("running basic test with combined write/read and copy on client only");
	run_transport_layer_channel_test(test_server_basic_writereadbuf, test_client_basic_copy, threads, AccessMode::ReadWrite, false, share_state);

	info!("running combined reply test");
	run_transport_layer_channel_test(test_server_combined, test_client_combined, threads, AccessMode::ReadWrite, true, share_state);
	info!("running combined reply test with combined write/read");
	run_transport_layer_channel_test(test_server_combined_writereadbuf, test_client_combined, threads, AccessMode::ReadWrite, true, share_state);
	info!("running combined reply test with copy on both sides");
	run_transport_layer_channel_test(test_server_combined_copy, test_client_combined_copy, threads, AccessMode::ReadWrite, true, share_state);
	info!("running combined reply test with copy on server only");
	run_transport_layer_channel_test(test_server_combined_copy, test_client_combined, threads, AccessMode::ReadWrite, true, share_state);
	info!("running combined reply test with copy on client only");
	run_transport_layer_channel_test(test_server_combined, test_client_combined_copy, threads, AccessMode::ReadWrite, true, share_state);
	info!("running read-only FD test");
	run_transport_layer_channel_test(test_server_readonly, test_client_readonly, threads, AccessMode::ReadOnly, false, share_state);
	info!("running read-only FD test with combined write/read");
	run_transport_layer_channel_test(test_server_readonly_writereadbuf, test_client_readonly, threads, AccessMode::ReadOnly, false, share_state);
	info!("running write-only FD test");
	run_transport_layer_channel_test(test_server_writeonly, test_client_writeonly, threads, AccessMode::WriteOnly, false, share_state);
	info!("running write-only FD test with combined write/read");
	run_transport_layer_channel_test(test_server_writeonly_writereadbuf, test_client_writeonly, threads, AccessMode::WriteOnly, false, share_state);

	info!("running protocol sequence error FD test");
	run_transport_layer_channel_test(test_server_error_sequence, test_client_error_sequence, threads, AccessMode::ReadWrite, true, share_state);

	info!("running oversized message FD test");
	run_transport_layer_channel_test(test_server_error_oversized, test_client_error_oversized, threads, AccessMode::ReadWrite, false, share_state);

	info!("running invalid message FD test");
	run_transport_layer_channel_test(test_server_error_invalid, test_client_error_invalid, threads, AccessMode::ReadWrite, false, share_state);

	run_transport_layer_notification_tests(threads, share_state);

	info!("transport layer tests finished");
}

//const NUM_VFS_TESTS: usize = usize::MAX;
const NUM_VFS_TESTS: usize = 50;
//const NUM_VFS_TESTS: usize = 1;

pub fn test_vfs(threads: &mut Vec<Arc<RwLock<SysThread>>>){
	for i in 0..NUM_VFS_TESTS {
		info!("running VFS tests: {}", i);
		test_vfs_inner(threads, true);
		test_vfs_inner(threads, false);
	}
}
/* vim: set softtabstop=8 tabstop=8 shiftwidth=8 noexpandtab */
