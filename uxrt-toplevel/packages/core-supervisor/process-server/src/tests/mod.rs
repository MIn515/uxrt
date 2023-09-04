/*
 * Copyright (c) 2018-2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 */

#[cfg(feature = "test_alloc")]
pub mod alloc;

#[cfg(feature = "test_job")]
pub mod job;

#[cfg(feature = "test_vfs")]
pub mod vfs;

use ::alloc::sync::Arc;
use ::alloc::vec::Vec;
use usync::RwLock;
use crate::job::{
	get_job_tree,
	thread::SysThread,
};

#[cfg(any(feature = "test_job", feature = "test_vfs"))]
pub fn create_local_test_threads() -> Vec<Arc<RwLock<SysThread>>>{
	info!("creating local test threads");
	let job_tree = get_job_tree();
	info!("creating test thread 0");
	let local_thread_0 = job_tree.new_root_thread().expect("could not allocate local thread");
	info!("creating test thread 1");
   	let local_thread_1 = job_tree.new_root_thread().expect("could not allocate local thread");

	local_thread_1.write().set_core(1).expect("couldn't change core of test thread 1");

	let mut ret = Vec::new();
	ret.push(local_thread_0);
	ret.push(local_thread_1);
	ret
}

#[cfg(any(feature = "test_job", feature = "test_vfs"))]
pub fn deallocate_local_threads(threads: &mut Vec<Arc<RwLock<SysThread>>>){
	while threads.len() > 0 {
		let thread = threads.pop().unwrap();
		let id = thread.read().tid;
		info!("deallocating test thread {}", id);
		get_job_tree().delete_root_thread(id).expect("cannot delete root server thread");
	}
}

/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
