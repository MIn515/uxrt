/*
 * Copyright (c) 2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This module includes core code for managing threads, processes, and
 * cgroups.
 */

use core::fmt;
use core::sync::atomic::{
	AtomicBool,
	Ordering
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use sel4_sys::CONFIG_SELFE_ROOT_STACK;

use sel4::{
	Endpoint,
	FromCap,
	Thread,
	ToCap,
	seL4_Word,
};

use sel4_alloc::{
	AllocatorBundle,
	cspace::CSpaceManager,
};

use sel4_thread::{
	BaseThread,
	CommonThreadConfig,
	LocalThread,
	LocalThreadConfig,
	SchedParams,
	ThreadError,
	WrappedThread,
};

use crate::global_heap_alloc::get_kobj_alloc;
use crate::job::thread::{
	SysThread,
	SysThreadError,
};

use crate::vfs::{
	VFSError,
	vfs_root_thread_init,
};
use crate::vfs::transport::{
	FactoryFDSpace,
	ThreadFDSpace,
};

pub struct ThreadPoolHandle {
}

impl ThreadPoolHandle {
	pub fn get_result(&self) -> Result<Option<Vec<seL4_Word>>, SysThreadError>{
		unimplemented!()
	}
	pub fn stop(&self) {
		unimplemented!()
	}
}

pub struct ThreadPool {
}

impl ThreadPool {
	pub fn run<F>(&self, mut f: F) -> Result<ThreadPoolHandle, SysThreadError>
			where F: FnMut() -> Option<Vec<seL4_Word>> + Send + 'static {
		unimplemented!()
	}
}

pub fn get_main_pool() -> Arc<ThreadPool> {
	unimplemented!()
}

pub fn get_helper_pool() -> Arc<ThreadPool> {
	unimplemented!()
}
/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
