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
	AtomicBool,
	Ordering
};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use intrusive_collections::UnsafeRef;

use sel4_sys::CONFIG_SELFE_ROOT_STACK;

use sel4::{
	Endpoint,
	FromCap,
	Thread,
	ToCap,
	seL4_CPtr,
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

use uxrt_transport_layer::FDArray;

use crate::global_heap_alloc::get_kobj_alloc;
use crate::job::{
	Job,
	ROOT_PID,
};

use crate::vfs::{
	VFSError,
	vfs_root_thread_init,
};
use crate::vfs::transport::{
	FactoryFDSpace,
	ThreadFDSpace,
};
use crate::vm::get_root_alloc;
use crate::vm::vspace::{
	get_root_vspace,
	VSpaceContainer,
};
use crate::add_arc_slab;

use usync::RwLock;

static DEFAULT_LOCAL_CONFIG: LocalThreadConfig = LocalThreadConfig {
	stack_size: CONFIG_SELFE_ROOT_STACK as usize,
	allocate_ipc_buffer: true,
	create_reply: false,
	exit_endpoint: None,
};

///A thread-related error
#[derive(Clone, Copy, Debug, Fail)]
pub enum SysThreadError {
	#[fail(display = "Thread error")]
	Base(ThreadError),
	#[fail(display = "VFS error")]
	VFSError(VFSError),
}

///Converts ThreadError to SysThreadError
fn base_to_sys(res: Result<(), ThreadError>) -> Result<(), SysThreadError> {
	if let Err(err) = res {
		return Err(SysThreadError::Base(err));
	}
	Ok(())
}

///Gets the global ID for a thread given the PID and TID
fn get_gtid(pid: i32, tid: i32) -> u64 {
	(pid as u64) << 32 | (tid as u64)
}

///A handle to a thread, used where acquiring a lock to the full thread is
///undesirable
#[derive(Clone)]
pub struct ThreadHandle {
	tcb: Thread,
	runnable: Arc<AtomicBool>,
	fds: Option<UnsafeRef<FDArray>>,
	vspace: Arc<VSpaceContainer>,
	pid: i32,
	tid: i32,
}

impl ThreadHandle {
	///Creates a new `ThreadHandle` 
	fn new(tcb: Thread, runnable: Arc<AtomicBool>, fds: Option<UnsafeRef<FDArray>>, vspace: Arc<VSpaceContainer>, pid: i32, tid: i32) -> ThreadHandle {
		ThreadHandle {
			tcb,
			runnable,
			fds,
			vspace,
			pid,
			tid,
		}
	}
	///Gets the process ID of this thread
	pub fn get_pid(&self) -> i32 {
		self.pid
	}
	///Gets the ID of this thread
	pub fn get_tid(&self) -> i32 {
		self.tid
	}
	///Gets the global ID of this thread
	pub fn get_gtid(&self) -> u64 {
		get_gtid(self.pid, self.tid)
	}
	///Returns true if this thread is runnable
	pub fn is_runnable(&self) -> bool {
		let ret = self.runnable.load(Ordering::Relaxed);
		//info!("{}: is_runnable: {}", self.get_gtid(), ret);
		ret
	}
	///Gets the FD endpoint this thread is currently blocking on (if any)
	pub fn get_waiting_endpoint(&self) -> Option<seL4_CPtr> {
		if self.is_runnable() && self.is_other() {
			None
		}else{
			let fds = self.fds.clone().expect("no user FD array set for thread handle (this shouldn't happen)");
			Some(fds.get_waiting_endpoint())
		}
	}
	///Suspends this thread if it is runnable.
	///
	///Returns true if it was runnable, false if it was already suspended.
	pub fn suspend(&self) -> bool {
		//XXX: there is a race if the thread is suspended because of a fault, since the runnable flag may not have been set (this would presumably result in the same fault being received twice by the fault handler); ideally, there should be some way to tell at the kernel level if the thread has been suspended (maybe the suspend method could be patched to fail if the thread isn't running)
		let runnable = self.is_runnable();
		if runnable {
			//info!("suspending thread {}", self.tid);
			self.tcb.suspend().expect("ThreadFDSpace: could not suspend thread");
			self.runnable.store(false, Ordering::Relaxed);
		}
		runnable
	}
	///Resumes this thread if it was previously runnable.
	pub fn resume(&self, orig_runnable: bool) {
		if orig_runnable {
			//info!("resuming thread {}", self.tid);
			self.tcb.resume().expect("ThreadFDSpace: could not resume thread");
			self.runnable.store(true, Ordering::Relaxed);
		}
	}
	///Returns true if this thread is not the calling thread
	pub fn is_other(&self) -> bool {
		let res = self.pid != ROOT_PID || self.tid != get_current_tid();
		//info!("is_other: {} {} {} {}", self.pid, self.tid, get_current_tid(), res);
		res
	}
	///Suspends this thread if it is not the calling thread. Returns true
	///if it was runnable, and false if it was already suspended
	pub fn suspend_if_other(&self) -> bool {
		if self.is_other(){
			self.suspend()
		}else{
			false
		}
	}
	///Resumes the thread if it was originally runnable and not the 
	///calling thread.
	pub fn resume_if_other(&self, orig_runnable: bool) {
		if self.is_other(){
			self.resume(orig_runnable);
		}
	}
	///Gets the VSpace of this thread
	pub fn get_vspace(&self) -> Arc<VSpaceContainer> {
		self.vspace.clone()
	}
}

///The base thread object of a `SysThread`.
enum InnerThread {
	Kernel(BaseThread),
	RootInit(BaseThread),
	Root(LocalThread),
	User(BaseThread),
}

///The system-level wrapper for threads.
pub struct SysThread {
	inner: InnerThread,
	pub(crate) pid: i32,
	pub(crate) tid: i32,
	fdspace: Option<(Arc<ThreadFDSpace>, Arc<RwLock<FactoryFDSpace>>)>,
	vspace: Option<Arc<VSpaceContainer>>,
	runnable: Arc<AtomicBool>,
}

impl WrappedThread for SysThread {
	fn get_base_thread(&self) -> &BaseThread {
		match self.inner {
			InnerThread::Kernel(ref inner) => &inner,
			InnerThread::RootInit(ref inner) => &inner,
			InnerThread::Root(ref inner) => inner.get_base_thread(),
			InnerThread::User(ref inner) => &inner,
		}
	}
	fn get_base_thread_mut(&mut self) -> &mut BaseThread {
		match self.inner {
			InnerThread::Kernel(ref mut inner) => inner,
			InnerThread::RootInit(ref mut inner) => inner,
			InnerThread::Root(ref mut inner) => inner.get_base_thread_mut(),
			InnerThread::User(ref mut inner) => inner,
		}
	}
	fn get_tcb(&self) -> Thread {
		self.get_base_thread().get_tcb()
	}
	fn suspend(&self) -> sel4::Result {
		self.runnable.store(false, Ordering::Relaxed);
		self.get_base_thread().suspend()
	}
}

impl SysThread {
	///Creates a new dummy kernel idle thread object
	pub fn new_kernel(pid: i32, tid: i32) -> Result<SysThread, SysThreadError> {
		Ok(SysThread {
			inner: InnerThread::Kernel(BaseThread::new_from_tcb(Thread::from_cap(0))),
			pid,
			tid,
			fdspace: None,
			vspace: None,
			runnable: Arc::new(AtomicBool::new(true)),
		})
	}
	///Creates the thread object for the initial root server thread.
	pub fn new_root_init(mut common_config: CommonThreadConfig, tcb: Thread, pid: i32, base_tid: i32, fdspace: Arc<RwLock<FactoryFDSpace>>) -> Result<SysThread, SysThreadError> {
		let kobj_alloc = get_kobj_alloc();
		let fault_endpoint = get_root_alloc().allocate_fault_endpoint(pid, base_tid, &kobj_alloc);
		if let Err(err) = fault_endpoint {
			return Err(SysThreadError::Base(ThreadError::CSpaceAllocationError { details: err }));
		}
		common_config.fault_endpoint = fault_endpoint.unwrap();

		let mut base_thread = BaseThread::new_from_tcb(tcb);

		if let Err(err) = base_thread.set_space(common_config){
			return Err(SysThreadError::Base(err))
		}

		let runnable = Arc::new(AtomicBool::new(true));

		//safety: this is temporary, and gets set once the underlying 
		//region is allocated; any access before it is set will return
		//None
		let fds_user = unsafe { UnsafeRef::from_box(Box::new(FDArray::new(0, 0))) };
		let vspace = get_root_vspace();
		let suspend_handle = ThreadHandle::new(base_thread.get_tcb().clone(), runnable.clone(), Some(fds_user.clone()), vspace.clone(), pid, base_tid);

		let thread_fdspace = match fdspace.write().new_thread_root(suspend_handle, fds_user) {
			Ok(fdspace) => fdspace,
			Err(err) => return Err(SysThreadError::VFSError(err)),
		};
		
		assert!(get_current_tid() == 0, "Thread::new_root_init called from thread other than the initial thread");
	
		vfs_root_thread_init(thread_fdspace.clone());

		Ok(SysThread {
			inner: InnerThread::RootInit(base_thread),
			pid,
			tid: base_tid,
			fdspace: Some((thread_fdspace, fdspace.clone())),
			vspace: Some(vspace),
			runnable,
		})
	}
	///Creates a new root server thread
	pub fn new_root(mut common_config: CommonThreadConfig, sched_params: SchedParams, pid: i32, base_tid: i32, fdspace: Option<Arc<RwLock<FactoryFDSpace>>>) -> Result<SysThread, SysThreadError> {
		let kobj_alloc = get_kobj_alloc();
		let fault_endpoint = get_root_alloc().allocate_fault_endpoint(pid, base_tid, &kobj_alloc);
		if let Err(err) = fault_endpoint {
			return Err(SysThreadError::Base(ThreadError::CSpaceAllocationError { details: err }));
		}
		common_config.fault_endpoint = fault_endpoint.unwrap();

		let mut local_config = DEFAULT_LOCAL_CONFIG.clone();
		let exit_endpoint = kobj_alloc.cspace().allocate_slot_with_object_fixed::<Endpoint, _>(&kobj_alloc);
		if let Err(err) = exit_endpoint {
			return Err(SysThreadError::Base(ThreadError::CSpaceAllocationError { details: err }));
		}
		local_config.exit_endpoint = Some(exit_endpoint.unwrap());

		let inner = match LocalThread::new(common_config, local_config, sched_params, &kobj_alloc) {
			Ok(thread) => thread,
			Err(err) => return Err(SysThreadError::Base(err)),
		};

		let runnable = Arc::new(AtomicBool::new(false));
		let fds_user = if fdspace.is_some() {
			//safety: this is temporary, and gets set once the 
			//underlying region is allocated, and any access 
			//before it is set will return None
			unsafe { Some(UnsafeRef::from_box(Box::new(FDArray::new(0, 0)))) }
		}else{
			None
		};

		let vspace = get_root_vspace();
		let suspend_handle = ThreadHandle::new(inner.get_tcb().clone(), runnable.clone(), fds_user.clone(), vspace.clone(), pid, base_tid);

		let fdspaces = if let Some(factory_fdspace) = fdspace {
			let thread_fdspace = match factory_fdspace.write().new_thread_root(suspend_handle, fds_user.unwrap()) {
				Ok(fdspace) => fdspace,
				Err(err) => return Err(SysThreadError::VFSError(err)),
			};

			Some((thread_fdspace, factory_fdspace.clone()))
		}else{
			None
		};

		Ok(SysThread {
			inner: InnerThread::Root(inner),
			pid,
			tid: base_tid,
			fdspace: fdspaces,
			vspace: Some(vspace),
			runnable,
		})

	}
	///Gets the process ID of this thread
	pub fn get_pid(&self) -> i32 {
		self.pid
	}
	///Gets the ID of this thread
	pub fn get_tid(&self) -> i32 {
		self.tid
	}
	///Gets the global ID of this thread
	pub fn get_gtid(&self) -> u64 {
		get_gtid(self.pid, self.tid)
	}
	///Sets the core on which this thread runs
	pub fn set_core(&mut self, core: usize) -> Result<(), SysThreadError>{
		let mut sched_params = self.get_sched_params().expect("no scheduler parameters for thread (this shouldn't happen)");
		sched_params.core = core;
		let kobj_alloc = get_kobj_alloc();
		base_to_sys(self.set_sched_params(sched_params, &kobj_alloc))
	}
	///Runs this thread with the given closure if it is a root server 
	///thread
	///
	///Always fails if this is not a root server thread
	pub fn run<F>(&mut self, mut f: F) -> Result<(), SysThreadError>
			where F: FnMut() -> Option<Vec<seL4_Word>> + Send + 'static {
		match self.inner {
			InnerThread::Root(ref mut inner) => {
				//info!("tid: {}", self.tid);
				let fdspace_opt = if let Some(fdspace) = self.fdspace.as_ref() {
					Some(fdspace.0.clone())
				}else{
					None
				};
				let tid = self.tid;
				let runnable = self.runnable.clone();
				base_to_sys(inner.run(move || {
					runnable.store(true, Ordering::Relaxed);
					unsafe { THREAD_ID = tid };
					if let Some(fdspace) = fdspace_opt.clone() {
						vfs_root_thread_init(fdspace);
					}
					let ret = f();
					runnable.store(false, Ordering::Relaxed);
					ret
				}))
			},
			_ => Err(SysThreadError::Base(ThreadError::InternalError)),
		}
	}
	///Gets the exit endpoint of this threasd (only for root server 
	///threads)
	pub fn get_exit_endpoint(&self) -> Option<Endpoint> {
		match self.inner {
			InnerThread::Root(ref inner) => inner.get_exit_endpoint(),
			_ => None,
		}
	}
	///Gets this thread's FDSpace
	pub fn get_thread_fdspace(&self) -> Option<Arc<ThreadFDSpace>> {
		if let Some((thread_fdspace, _)) = &self.fdspace {
			Some(thread_fdspace.clone())
		}else{
			None
		}
	}
	///Gets the factory FDSpace associated with this thread
	pub fn get_factory_fdspace(&self) -> Option<Arc<RwLock<FactoryFDSpace>>> {
		if let Some((_, factory_fdspace)) = &self.fdspace {
			Some(factory_fdspace.clone())
		}else{
			None
		}
	}
}

impl Drop for SysThread {
	fn drop(&mut self) {
		let common_config;
		let kobj_alloc = get_kobj_alloc();
		match self.inner {
			InnerThread::Kernel(_) => panic!("attempted to drop kernel thread"),
			InnerThread::RootInit(_) => panic!("attempted to drop root server initial thread"),
			InnerThread::Root(ref mut inner) => {
				//info!("dropping thread with ID {}", self.id);
				if let Some(endpoint) = inner.get_exit_endpoint() {
					kobj_alloc.cspace().free_and_delete_slot_with_object_fixed(&endpoint, &kobj_alloc).expect("failed to deallocate exit endpoint");
				}
				common_config = inner.get_space();
				inner.deallocate_objects(&kobj_alloc).expect("failed to deallocate thread");

			},
			InnerThread::User(ref mut inner) => {
				common_config = inner.get_space();
				inner.deallocate_objects(&kobj_alloc).expect("failed to deallocate thread");
			},
		}
		if let Some(config) = common_config {
			let cap = config.fault_endpoint.to_cap();
			if cap != 0 {
				kobj_alloc.cspace().free_and_delete_slot_raw(cap, &kobj_alloc).expect("failed to deallocate fault endpoint");
			}
		}
		if let Some(ref fdspace) = self.fdspace {
			fdspace.1.write().delete_thread(self.get_gtid()).expect("failed to delete thread FDSpace");
		}
	}
}

impl Job for SysThread {
}

impl fmt::Debug for SysThread {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "[SysThread: id: {}, name: {:?}]", self.tid, self.get_name())
	}
}

#[thread_local]
static mut THREAD_ID: i32 = 0;

///Gets the ID of the calling thread
pub fn get_current_tid() -> i32 {
	unsafe { THREAD_ID }
}

///Adds thread-related slabs
pub fn add_custom_slabs() {
	add_arc_slab!(AtomicBool, 1024, 4, 4, 2).expect("could not add custom slab for runnable flag");
}
/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
