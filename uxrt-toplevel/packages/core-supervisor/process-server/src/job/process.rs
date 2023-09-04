/*
 * Copyright (c) 2022-2023 Andrew Warkentin
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
	AtomicI32,
	Ordering
};
use alloc::{
	collections::BTreeMap,
	string::String,
	sync::Arc,
};

use sel4_thread::{
	SchedParams,
	ThreadError,
};

use sel4_sys::{
	CONFIG_BOOT_THREAD_TIME_SLICE,
	seL4_CapInitThreadTCB
};

use sel4::{
	FromCap,
	Thread,
};

use usync::RwLock;

use super::{
	CGroup,
	Job,
	Team,
	get_job_tree,

};
use super::thread::{
	SysThread,
	SysThreadError,
};
use crate::vfs::transport::FactoryFDSpace;
use crate::vm::get_root_common_config;
use crate::utils::GlobalIDAllocator;
use crate::add_arc_slab;

pub const KERNEL_PID: i32 = -1;
pub const ROOT_PID: i32 = 0;

///Gets the scheduler parameters for the root thread
pub fn get_root_sched_params() -> SchedParams {
	SchedParams {
		priority: 255,
		mcp: 255,
		core: 0,
		context_bits: 8,
		sched_ctrl: get_job_tree().get_sched_control(),
		period: CONFIG_BOOT_THREAD_TIME_SLICE as u64 * 1000,
		budget: CONFIG_BOOT_THREAD_TIME_SLICE as u64 * 1000,
		extra_refills: 0,
		flags: 0,
		badge: 0,
	}
}

///A process
pub struct Process {
	id: i32,
	orig_cmdline: String, //TODO: there should also be a separate argv that is shared with the process, as on conventional Unix; both shoould be accessible from /proc
	exec: String,
	all_threads: BTreeMap<i32, Arc<RwLock<SysThread>>>,
	next_tid: AtomicI32,
}

impl Process {
	///Creates a new process
	pub fn new(id: i32, exec: String, cmdline: String) -> Result<Process, ()> {
		Ok(Process {
			id,
			orig_cmdline: cmdline,
			exec,
			all_threads: Default::default(),
			next_tid: AtomicI32::new(-1),
		})
	}
	///Creates a new thread in this process
	pub fn new_thread(&mut self, fdspace: Option<Arc<RwLock<FactoryFDSpace>>>) -> Result<Arc<RwLock<SysThread>>, SysThreadError>{
		let id = self.allocate_id();

		if id.is_err(){
			//TODO: return something better here to indicate too many threads
			return Err(SysThreadError::Base(ThreadError::InternalError));
		}
		//info!("Process::new_thread: {} {}", self.id, id.unwrap());
		let res = if self.id == KERNEL_PID {
			SysThread::new_kernel(self.id, id.unwrap())
		}else if self.id == ROOT_PID {
			if id.unwrap() == 0 {
				SysThread::new_root_init(get_root_common_config(), Thread::from_cap(sel4_sys::seL4_CapInitThreadTCB), self.id, id.unwrap(), fdspace.expect("no FDSpace provided for root thread"))
			}else{
				SysThread::new_root(get_root_common_config(), get_root_sched_params(), self.id, id.unwrap(), fdspace)
			}
		}else{
			panic!("TODO: implement creation of user threads");
		};
		match res {
			Ok(thread) => {
				let rc = Arc::new(RwLock::new(thread));
				self.all_threads.insert(id.unwrap(), rc.clone());
				Ok(rc)
			},
			Err(err) => { Err(err) },
		}
	}
	///Gets a thread within this process
	pub fn get_thread(&self, pid: i32) -> Option<Arc<RwLock<SysThread>>>{
		if let Some(thread) = self.all_threads.get(&pid) {
			Some(thread.clone())
		}else{
			None
		}
	}
	///Deletes a thread from this process
	pub fn delete_thread(&mut self, id: i32) -> Result<(), ()>{
		if self.all_threads.remove(&id).is_some() {
			Ok(())
		}else{
			Err(())
		}
	}
	///Dumps all threads in this process to the log
	pub fn dump_threads(&self){
		info!("{:?}, threads:", self);
		for thread in self.all_threads.values(){
			info!(" {:?}", thread.read());
		}
	}
}

impl GlobalIDAllocator for Process {
	fn has_id(&self, id: i32) -> bool {
		self.all_threads.contains_key(&id)
	}
	fn get_next_id(&self) -> i32 {
		self.next_tid.load(Ordering::SeqCst)
	}
	fn increment_id(&self) -> i32 {
		self.next_tid.fetch_add(1, Ordering::SeqCst)
	}
}

impl Drop for Process {
	fn drop(&mut self) {
	}
}

impl Team for Process {
}

impl Job for Process {
}

impl fmt::Debug for Process {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "[Process: id: {}, exec: {}]", self.id, self.exec)
	}
}

///Adds process-related custom slabs
pub fn add_custom_slabs(){
	add_arc_slab!(RwLock<SysThread>, 512, 4, 4, 2).expect("could not add custom slab for thread");
}
/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
