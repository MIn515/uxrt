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

use core::sync::atomic::{
	AtomicI32,
	Ordering,
};
use core::mem;

use alloc::{
	collections::BTreeMap,
	string::String,
	sync::Arc,
};

use crate::global_heap_alloc::get_kobj_alloc;
use crate::add_arc_slab;

use sel4_sys::{
	seL4_CPtr,
	seL4_SlotRegion
};

use sel4::{
	FromCap,
	SchedControl,
	available_parallelism,
};

use custom_slab_allocator::CustomSlabAllocator;

use sel4_thread::{
	ThreadError,
	WrappedThread,
};
use usync::RwLock;

use crate::bootinfo::MBIHandler;

use crate::utils::GlobalIDAllocator;

use crate::vfs::transport::get_root_fdspace;

pub mod process;
pub mod thread;
pub mod thread_pool;

use process::{
	KERNEL_PID,
	ROOT_PID,
	Process,
};

use thread::{
	SysThread,
	SysThreadError,
};

static mut JOB_TREE: JobTree = JobTree::new();

///Gets the job tree
pub fn get_job_tree() -> &'static JobTree {
	unsafe { &JOB_TREE }
}

///Initializes the job tree
pub fn init_job_tree(bootinfo: &'static sel4_sys::seL4_BootInfo, mbi_handler: MBIHandler) {
	unsafe { JOB_TREE.init(bootinfo, mbi_handler) }
}

///A group of threads (either a process or CGroup)
pub trait Team: Job {
}

///A CGroup
pub trait CGroup: Team {
	fn num_leaves(&self);
	fn num_branches(&self);
}

///A thread or team
pub trait Job {
}

///The tree of all teams and threads in the system
pub struct JobTree {
	all_processes: RwLock<BTreeMap<i32, Arc<RwLock<Process>>>>,
	next_pid: AtomicI32,
	sched_control_caps: Option<seL4_SlotRegion>,
}

impl JobTree {
	///Creates a new `JobTree`
	const fn new() -> JobTree {
		JobTree{
			all_processes: RwLock::new(BTreeMap::new()),
			next_pid: AtomicI32::new(0),
			sched_control_caps: None,
		}
	}
	///Gets the SchedControl object
	pub fn get_sched_control(&self) -> SchedControl {
		let caps = self.sched_control_caps.expect("sched_control_caps unset");
		SchedControl::from_cap(caps.start as seL4_CPtr)
	}
	///Creates the kernel and root server processes
	fn init(&mut self, bootinfo: &'static sel4_sys::seL4_BootInfo, mbi_handler: MBIHandler) {
		info!("initializing command line for kernel process");
		self.sched_control_caps = Some(bootinfo.schedcontrol);
		let mut kernel_cmdline = String::new();
		let mut kernel_exec = String::new();
		for arg in mbi_handler.kernel_cmdline.split_whitespace() {
			if kernel_exec.len() == 0 {
				kernel_exec.push_str(arg);
			}
			kernel_cmdline.push_str(arg);
			kernel_cmdline.push('\0');
		}

		info!("initializing command line for root server process");
		let mut root_exec = String::new();
		for arg in mbi_handler.proc_cmdline.split_whitespace() {
			if root_exec.len() != 0 {
				panic!("arguments passed to process server (they should be passed to the kernel instead)");
			}
			root_exec.push_str(arg);
		}
		let mut root_cmdline = root_exec.clone();
		root_cmdline.push('\0');


		info!("creating process table entry for kernel process");
		let mut kernel_process = Process::new(KERNEL_PID, kernel_exec, kernel_cmdline).expect("could not create kernel process info");
		for _ in 0..available_parallelism().get(){
			let thread = kernel_process.new_thread(None).expect("could not create thread info for idle thread");
			thread.write().set_name("idle_thread");
		}

		let mut all_processes = self.all_processes.write();
		all_processes.insert(KERNEL_PID, Arc::new(RwLock::new(kernel_process)));

		info!("creating process table entry for root server process");
		let mut root_process = Process::new(ROOT_PID, root_exec, root_cmdline).expect("could not create root server process info");
		let init_thread = root_process.new_thread(Some(get_root_fdspace())).expect("could not create thread info for initial thread");
		init_thread.write().set_name("init_thread");
		all_processes.insert(ROOT_PID, Arc::new(RwLock::new(root_process)));
	}
	///Creates a new root server thread with an FDSpace
	pub fn new_root_thread(&self) -> Result<Arc<RwLock<SysThread>>, SysThreadError>{
		let mut processes = self.all_processes.write();
		let root_process = processes.get_mut(&ROOT_PID).expect("root process not initialized");
		let thread = root_process.write().new_thread(Some(get_root_fdspace()));
		thread
	}
	///Creates a new root server thread without an FDSpace
	pub fn new_root_helper_thread(&self) -> Result<Arc<RwLock<SysThread>>, SysThreadError>{
		let mut processes = self.all_processes.write();
		let root_process = processes.get_mut(&ROOT_PID).expect("root process not initialized");
		let thread = root_process.write().new_thread(None);
		thread
	}
	///Deletes a root server thread
	pub fn delete_root_thread(&self, id: i32) -> Result<(), ()> {
		self.all_processes.write().get(&ROOT_PID).expect("attempted to delete root thread but no root process present (this should never happen)").write().delete_thread(id)
	}
	///Gets a process
	pub fn get_process(&self, pid: i32) -> Option<Arc<RwLock<Process>>>{
		if let Some(process) = self.all_processes.read().get(&pid) {
			Some(process.clone())
		}else{
			None
		}
	}
	///Dumps a list of all processes to the log
	pub fn dump_processes(&self){
		for process in self.all_processes.read().values(){
			process.read().dump_threads();
		}
	}
}

impl GlobalIDAllocator for JobTree {
	fn has_id(&self, id: i32) -> bool {
		self.all_processes.read().contains_key(&id)
	}
	fn get_next_id(&self) -> i32 {
		self.next_pid.load(Ordering::SeqCst)
	}
	fn increment_id(&self) -> i32 {
		self.next_pid.fetch_add(1, Ordering::SeqCst)
	}
}

///Adds job-related custom slabs
pub fn add_custom_slabs() {
	process::add_custom_slabs();
	thread::add_custom_slabs();
	add_arc_slab!(RwLock<Process>, 512, 4, 4, 2).expect("could not add custom slab for thread");
}
/* vim: set softtabstop=8 tabstop=8 noexpandtab:: */
