/*
 * Copyright (c) 2018-2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This module includes the VFS along with glue code for the IPC transport 
 * layer.
 */

use sel4_alloc::{cspace, vspace};
use crate::job::thread::SysThread;
pub mod transport;

use transport::{
	ThreadFDSpace,
	fdspace_root_thread_init,
	init_clunk_threads,
	init_fdspace_list,
	init_secondary_allocator,
};

use alloc::sync::Arc;

#[derive(Clone, Copy, Debug, Fail)]
pub enum VFSError {
	#[fail(display = "I/O error")]
	IOError(uxrt_transport_layer::IOError),
	#[fail(display = "CSpace error")]
	CSpaceError(cspace::CSpaceError),
	#[fail(display = "VSpace error")]
	VSpaceError(vspace::VSpaceError),
	#[fail(display = "Too many open files")]
	TooManyFiles,
	#[fail(display = "InternalError")]
	InternalError,
}

pub fn init_spaces() {
	init_secondary_allocator();
	init_fdspace_list();
}

pub fn init() {
	init_clunk_threads();
}

pub fn vfs_root_thread_init(fdspace: Arc<ThreadFDSpace>) {
	fdspace_root_thread_init(fdspace);
}
pub fn add_custom_slabs() {
	transport::add_custom_slabs();
}
