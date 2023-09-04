/*
 * Copyright (c) 2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This module includes core code for testing threads, processes, and cgroups.
 */

use alloc::sync::Arc;

use crate::global_heap_alloc::get_kobj_alloc;
use crate::vm::get_root_common_config;
use crate::job::{
	process::get_root_sched_params,
	get_job_tree,
	thread::SysThread,
};

use core::cell::Cell;
#[cfg(feature = "test_alloc")]
use crate::tests::alloc::run_alloc_tests_looped;

use sel4_sys::CONFIG_SELFE_ROOT_STACK;

use sel4::{
	MSG_MAX_LENGTH,
	PAGE_BITS,
	PAGE_SIZE,
	CapRights,
	Endpoint,
	FaultMsg,
};

use sel4_alloc::{
	AllocatorBundle,
	cspace::CSpaceManager,
	utspace::UtZone,
	vspace::VSpaceManager,
};

use sel4_thread:: {
	BaseThread,
	CommonThreadConfig,
	LocalThread,
	LocalThreadConfig,
	SchedParams,
	WrappedThread,
};

use usync::RwLock;

use alloc::vec::Vec;

const INVALID_ADDRESS: usize = 0;

const THREAD_LOCAL_0_VALUE: u64 = 0x7577757775777577;
const THREAD_LOCAL_1_VALUE: u64 = 0x6f776f776f776f77;
const LOCAL_0_VALUE: u64 = 0x12345678;
const RET_VALUE: usize = 0x87654321;

#[thread_local]
static THREAD_LOCAL_0: u64 = THREAD_LOCAL_0_VALUE;
#[thread_local]
static THREAD_LOCAL_1: Cell<u64> = Cell::new(THREAD_LOCAL_1_VALUE);

fn test_fn_0(arg: u64){
	let res = THREAD_LOCAL_0 + THREAD_LOCAL_1.get();
	THREAD_LOCAL_1.set(THREAD_LOCAL_1.get() + 1);
	info!("test_fn_0: {:x} {:x}", res + arg, THREAD_LOCAL_1.get());
	assert!(THREAD_LOCAL_1.get() == THREAD_LOCAL_1_VALUE + 1);
}

pub fn test_base_thread(sched_params: SchedParams, common_config: CommonThreadConfig) {
  	info!("testing base thread");
	let kobj_alloc = get_kobj_alloc();
	let mut thread = BaseThread::new(&kobj_alloc).expect("could not allocate thread");
	thread.set_sched_params(sched_params, &kobj_alloc).expect("could not set scheduler parameters");
	thread.set_space(common_config).expect("could not configure thread");
	thread.allocate_reply(&kobj_alloc).expect("could not allocate reply slot for thread");
	let ipc_buffer_addr = kobj_alloc.vspace().allocate_and_map(PAGE_SIZE,  PAGE_BITS as usize, CapRights::all(), 0, UtZone::RamAny, &kobj_alloc).expect("failed to allocate IPC buffer");
	let ipc_buffer_cap = kobj_alloc.vspace().get_cap(ipc_buffer_addr).expect("could not get capability for IPC buffer");
	thread.set_ipc_buffer(ipc_buffer_addr, ipc_buffer_cap).expect("could not set IPC buffer");
	thread.deallocate_objects(&kobj_alloc).expect("could not deallocate kernel objects for thread");
	kobj_alloc.vspace().unmap_and_free(ipc_buffer_addr, PAGE_SIZE, PAGE_BITS as usize, &kobj_alloc).expect("could not deallocate IPC buffer");
}

pub fn create_local_threads() -> Vec<Arc<RwLock<SysThread>>>{
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

fn test_local_threads(threads: &mut Vec<Arc<RwLock<SysThread>>>){
	info!("testing local threads");
	let local0 = LOCAL_0_VALUE;
	let mut thread = threads[0].write();
	thread.run(move ||{
		info!("hello from the test thread");
		#[cfg(feature = "test_panic_secondary_thread")]
		access_invalid_address();

		info!("local1: {:x}", local0);
		info!("THREAD_LOCAL_0: {:x}", THREAD_LOCAL_0);
		info!("THREAD_LOCAL_1: {:x}", THREAD_LOCAL_1.get());
		test_fn_0(local0);
		info!("THREAD_LOCAL_1: {:x}", THREAD_LOCAL_1.get());
		for _ in 0..1<<24 {
		}
		assert!(THREAD_LOCAL_0 == THREAD_LOCAL_0_VALUE, "THREAD_LOCAL_0 has incorrect value {:x}", THREAD_LOCAL_0);
		assert!(THREAD_LOCAL_1.get() == THREAD_LOCAL_1_VALUE + 1, "THREAD_LOCAL_1 has incorrect value {:x}", THREAD_LOCAL_1.get());
		info!("allocating vector for thread return");
		let mut ret = Vec::new();
		ret.push(RET_VALUE);
		info!("returning from test thread");
		Some(ret)
	}).expect("failed to start local thread");

	info!("waiting for reply");
	let msg = thread.get_exit_endpoint().unwrap().recv_refuse_reply();
	let mut data = [0usize; MSG_MAX_LENGTH as usize]; 
	msg.get_data(&mut data).expect("failed to get thread return data");
	assert!(THREAD_LOCAL_0 == THREAD_LOCAL_0_VALUE, "THREAD_LOCAL_0 has incorrect value {:x}", THREAD_LOCAL_0);
	assert!(THREAD_LOCAL_1.get() == THREAD_LOCAL_1_VALUE, "THREAD_LOCAL_1 has incorrect value {:x}", THREAD_LOCAL_1.get());

	info!("THREAD_LOCAL_0: {:x}", THREAD_LOCAL_0);
	info!("THREAD_LOCAL_1: {:x}", THREAD_LOCAL_1.get());

	info!("return from test thread: {}", data[0]);
}

pub fn access_invalid_address(){
		info!("attempting to access invalid memory");
		let invalid0 = unsafe { *(INVALID_ADDRESS as *mut usize) + 1};
		info!("shouldn't get here: {:x}", invalid0);
}

pub fn test_page_fault(sched_params: SchedParams, mut common_config: CommonThreadConfig) {
	let kobj_alloc = get_kobj_alloc();
	let fault_endpoint = kobj_alloc.cspace().allocate_slot_with_object_fixed::<Endpoint, _>(&kobj_alloc).expect("could not allocate fault endpoint for test thread");
	common_config.fault_endpoint = fault_endpoint;

	let local_config = LocalThreadConfig {
		stack_size: CONFIG_SELFE_ROOT_STACK as usize,
		allocate_ipc_buffer: true,
		create_reply: true,
		exit_endpoint: None,
	};
	let mut thread = LocalThread::new(common_config, local_config, sched_params, &kobj_alloc).expect("could not allocate test thread");
	thread.run(move ||{
		access_invalid_address();
		None
	}).expect("failed to start local thread");
	let (fault, _msg) = FaultMsg::recv_refuse_reply(fault_endpoint);
	match fault {
		Some(FaultMsg::VmFault(_)) => {},
		_ => {panic!("test thread encountered non-VM fault: {:?}", fault);},
	}
	thread.deallocate_objects(&kobj_alloc);
	kobj_alloc.cspace().free_and_delete_slot_with_object_fixed(&fault_endpoint, &kobj_alloc).expect("could not deallocate fault endpoint");
}

#[cfg(feature = "test_alloc")]
fn test_allocation_multithreaded(threads: &mut Vec<Arc<RwLock<SysThread>>>){
	println!("testing allocation with multiple threads");
	let mut thread0 = threads[0].write();
	let mut thread1 = threads[1].write();
	thread0.run(move ||{
		run_alloc_tests_looped();
		None
	}).expect("failed to start local thread");

	thread1.run(move ||{
		run_alloc_tests_looped();
		None
	}).expect("failed to start local thread");
	thread0.get_exit_endpoint().unwrap().recv_refuse_reply();
	thread1.get_exit_endpoint().unwrap().recv_refuse_reply();
	info!("multi-threaded allocation tests finished");
}

pub fn deallocate_local_threads(threads: &mut Vec<Arc<RwLock<SysThread>>>){
	while threads.len() > 0 {
		let thread = threads.pop().unwrap();
		let id = thread.read().tid;
		info!("deallocating test thread {}", id);
		get_job_tree().delete_root_thread(id).expect("cannot delete root server thread");
	}
}

pub fn test_threads_base() {
	#[cfg(feature = "test_panic_main_thread")]
	access_invalid_address();

	test_base_thread(get_root_sched_params(), get_root_common_config());
}

pub fn test_threads_local(threads: &mut Vec<Arc<RwLock<SysThread>>>) {
	test_local_threads(threads);

	#[cfg(feature = "test_alloc")]
	test_allocation_multithreaded(threads);

	info!("thread tests finished");
}

/* vim: set softtabstop=8 tabstop=8 shiftwidth=8 noexpandtab */
