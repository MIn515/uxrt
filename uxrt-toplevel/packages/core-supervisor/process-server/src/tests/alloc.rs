/*
 * Copyright (c) 2019-2022 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 */

use core::mem;

use custom_slab_allocator::CustomSlabAllocator;

use alloc::{boxed::Box, vec::Vec};

use sel4::{CapRights, CNodeInfo, Endpoint, Notification, SchedContext, Reply, SlotRef, Thread, ToCap, Window, yield_now};

use sel4_alloc::{
	AllocatorBundle, 
	bootstrap::BootstrapAllocatorBundle,
	cspace::{
		AllocatableSlotRef, BumpAllocator, BitmapAllocator, 
		CSpaceManager, DynamicBitmapAllocator, SwitchingAllocator,
	},
	utspace::UtZone, 
};

use crate::utils::add_slab;
use crate::dump_heap;
use crate::global_heap_alloc::get_kobj_alloc;

use intrusive_collections::{LinkedList, LinkedListLink};

use log::LevelFilter;

const TEST_CNODE_SIZE: usize = 4;

fn test_initial_cnode(alloc: &BootstrapAllocatorBundle){
	let (initial_cnode, _, _) = &alloc;

	//mutate_to_new isn't tested here since endpoints can't be mutated

	info!("allocating test endpoint; slots remaining: {}", initial_cnode.slots_remaining());
	info!("initial_cnode: {:?}", initial_cnode);
	let endpoint = initial_cnode.allocate_slot_with_object::<Endpoint, _>(0, UtZone::RamAny, alloc).expect("failed to allocate test endpoint");
	let endpoint_slot = initial_cnode.obj_to_slot(&endpoint).expect("failed to get slot for test endpoint");
	info!("making first copy of test endpoint");
	let endpoint_slot_copy_1 = endpoint_slot.copy_to_new(initial_cnode, CapRights::all(), alloc).expect("failed to make first copy of test endpoint");
	info!("making second (badged) copy of test endpoint");
	let endpoint_slot_copy_2 = endpoint_slot.mint_to_new(initial_cnode, CapRights::all(), sel4::Badge::new(1234), alloc).expect("failed to make badged copy of test endpoint");
	info!("making third copy of test endpoint");
	let endpoint_slot_copy_3 = endpoint_slot.copy_to_new(initial_cnode, CapRights::all(), alloc).expect("failed to make third copy of test endpoint");
	info!("moving third copy of test endpoint");
	let endpoint_slot_copy_3_moved = endpoint_slot_copy_3.move_to_new(initial_cnode, alloc).expect("failed to move test endpoint");
	
	info!("freeing third copy of test endpoint");
	initial_cnode.free_and_delete_slot(endpoint_slot_copy_3_moved, alloc).expect("failed to deallocate moved copy of endpoint");
	info!("freeing original slot of third copy of test endpoint");
	initial_cnode.free_slot(endpoint_slot_copy_3, alloc).expect("failed to free empty slot from moving endpoint");
	info!("freeing second copy of test endpoint");
	initial_cnode.free_and_delete_slot(endpoint_slot_copy_2, alloc).expect("failed to free badged copy of endpoint");
	info!("freeing first copy of test endpoint");
	initial_cnode.free_and_delete_slot(endpoint_slot_copy_1, alloc).expect("failed to free unbadged copy of endpoint");

	info!("allocating test sublevel");
	let test_cnode = initial_cnode.allocate_sublevel_bump(2, true, alloc).expect("failed to allocate test sublevel");
	info!("copying endpoint to test sublevel");
	let endpoint_slot_sublevel_copy = endpoint_slot.copy_to_new(&test_cnode, CapRights::all(), alloc).expect("failed to copy test endpoint to sublevel");

	info!("freeing endpoint copy in test sublevel");

	test_cnode.free_and_delete_slot(endpoint_slot_sublevel_copy, alloc).expect("failed to deallocate copy of test endpoint from sublevel");
	info!("freeing test sublevel");
	initial_cnode.free_and_delete_sublevel(test_cnode, alloc).expect("failed to deallocate test sublevel");

	info!("freeing original endpoint");
	initial_cnode.free_and_delete_slot_with_object(&endpoint, 0, alloc).expect("failed to free original endpoint");
	info!("slots remaining at end of test: {}", initial_cnode.slots_remaining());
	info!("initial_cnode: {:?}", initial_cnode);
}

fn allocate_dynamic_test_endpoints(num: usize, dynamic_alloc: &DynamicBitmapAllocator, alloc: &BootstrapAllocatorBundle) -> Vec<SlotRef>{
	let mut test_endpoints: Vec<SlotRef> = Vec::new();
	for i in 0..num {
		info!("{}", i);
		let test_endpoint = dynamic_alloc.allocate_slot_with_object_ref::<Endpoint, _>(0, UtZone::RamAny, alloc).expect("failed to allocate test endpoint");
		test_endpoints.push(test_endpoint);
		//println!("test_endpoints[{}]: {} {:x}", i, test_endpoints[i].depth, test_endpoints[i].cptr);
	}
	test_endpoints
}

fn free_dynamic_test_endpoints(start: usize, end: usize, endpoints: &Vec<SlotRef>, dynamic_alloc: &DynamicBitmapAllocator, alloc: &BootstrapAllocatorBundle){
	for i in start..end{
		info!("{}", i);
		dynamic_alloc.free_and_delete_slot_with_object_ref::<Endpoint, _>(endpoints[i], 0, alloc).expect("failed to free test endpoint");
	}
	info!("{} slots remaining in dynamic allocator", dynamic_alloc.slots_remaining());
}

fn test_dynamic_cnode(root_cnode: &BumpAllocator, alloc: &BootstrapAllocatorBundle){
	let (initial_cnode, utspace, vspace) = &alloc;
	let dynamic_alloc = root_cnode.allocate_sublevel_dynamic_bitmap(4, false, 4, 0, 0, 1, alloc).expect("failed to allocate dynamic test sublevel");
	info!("allocated dynamic test sublevel with {} slots", dynamic_alloc.slots_remaining());

	info!("allocating test endpoints (0)");
	let test_endpoints = allocate_dynamic_test_endpoints(16, &dynamic_alloc, alloc);
	info!("allocating test endpoints (1)");
	let test_endpoints_1 = allocate_dynamic_test_endpoints(16, &dynamic_alloc, alloc);
	info!("allocating test endpoints (2)");
	let test_endpoints_2 = allocate_dynamic_test_endpoints(16, &dynamic_alloc, alloc);
	
	info!("allocating test endpoints (3)");
	let test_endpoints_3 = allocate_dynamic_test_endpoints(16, &dynamic_alloc, alloc);
	info!("allocating test endpoints (4)");
	let test_endpoints_4 = allocate_dynamic_test_endpoints(16, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (1)");
	free_dynamic_test_endpoints(0, 8, &test_endpoints_1, &dynamic_alloc, alloc);
	info!("allocating test endpoints (5)");
	let test_endpoints_5 = allocate_dynamic_test_endpoints(8, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (2)");
	free_dynamic_test_endpoints(0, 8, &test_endpoints_2, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (3)");
	free_dynamic_test_endpoints(0, 10, &test_endpoints_3, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (4)");
	free_dynamic_test_endpoints(0, 16, &test_endpoints_4, &dynamic_alloc, alloc);
	info!("allocating test endpoints (6)");
	let test_endpoints_6 = allocate_dynamic_test_endpoints(16, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (0)");
	free_dynamic_test_endpoints(0, 16, &test_endpoints, &dynamic_alloc, alloc);
	info!("allocating test endpoints (7)");
	let test_endpoints_7 = allocate_dynamic_test_endpoints(16, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (1)");
	free_dynamic_test_endpoints(8, 16, &test_endpoints_1, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (2)");
	free_dynamic_test_endpoints(8, 16, &test_endpoints_2, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (3)");
	free_dynamic_test_endpoints(10, 16, &test_endpoints_3, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (5)");
	free_dynamic_test_endpoints(0, 8, &test_endpoints_5, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (6)");
	free_dynamic_test_endpoints(0, 16, &test_endpoints_6, &dynamic_alloc, alloc);
	info!("freeing some test endpoints (7)");
	free_dynamic_test_endpoints(0, 16, &test_endpoints_7, &dynamic_alloc, alloc);
	info!("freeing dynamic test sublevel");
	root_cnode.free_and_delete_sublevel(dynamic_alloc, alloc).expect("could not free dynamic test sublevel");
}

fn test_sublevel_cnodes(root_cnode: &BumpAllocator, alloc: &BootstrapAllocatorBundle) {
	info!("creating test CNode");
	let test_cnode = root_cnode.allocate_sublevel_bitmap(TEST_CNODE_SIZE, false, alloc).expect("failed to allocate test sublevel");
	let dummy_slot = test_cnode.allocate_slot(alloc).expect("could not allocate dummy slot");
	let dummy_slot_1 = test_cnode.allocate_slot(alloc).expect("could not allocate dummy slot");
	info!("allocating endpoint in test CNode");
	let test_endpoint = test_cnode.allocate_slot_with_object::<Endpoint, _>(0, UtZone::RamAny, alloc).expect("failed to allocate test endpoint");
	info!("creating second-level test CNode");

	let test_cnode_1 = test_cnode.allocate_sublevel_bitmap(TEST_CNODE_SIZE, false, alloc).expect("failed to allocate dynamic test sublevel");
	info!("allocating dummy slots in test CNode");
	let dummy_slot_2 = test_cnode_1.allocate_slot(alloc).expect("could not allocate dummy slot");
	let dummy_slot_3 = test_cnode_1.allocate_slot(alloc).expect("could not allocate dummy slot");

	info!("allocating endpoints in second-level test CNode");
	let test_endpoint_1 = test_cnode_1.allocate_slot_with_object::<Endpoint, _>(0, UtZone::RamAny, alloc).expect("failed to allocate first test endpoint");
	let test_endpoint_2 = test_cnode_1.allocate_slot_with_object_ref::<Endpoint, _>(0, UtZone::RamAny, alloc).expect("failed to allocate second test endpoint");

	info!("copying test endpoint");
	let test_slot_3 = test_endpoint_2.copy_to_new(&test_cnode_1, CapRights::all(), alloc).expect("could not copy test endpoint");

	info!("freeing copy of second test endpoint");
	test_cnode_1.free_and_delete_slot(test_slot_3, alloc).expect("failed to free test endpoint copy");
	info!("freeing second test endpoint");
	test_cnode_1.free_and_delete_slot_with_object_ref::<Endpoint, _>(test_endpoint_2, 0, alloc).expect("failed to free second test endpoint");
	info!("freeing first test endpoint");
	test_cnode_1.free_and_delete_slot_with_object::<Endpoint, _>(&test_endpoint_1, 0, alloc).expect("failed to free first test endpoint");
	info!("freeing dummy slots");
	test_cnode_1.free_slot(dummy_slot_3, alloc).expect("failed to free dummy slot");
	test_cnode_1.free_slot(dummy_slot_2, alloc).expect("failed to free dummy slot");
	info!("freeing second-level test CNode");
	if test_cnode_1.slots_remaining() != 1 << TEST_CNODE_SIZE {
		panic!("used slots remaining in second-level test CNode (actual free: {}, expected free: {}", test_cnode_1.slots_remaining(), 1 << TEST_CNODE_SIZE);
	}
	test_cnode.free_and_delete_sublevel(test_cnode_1, alloc).expect("failed to free second-level test CNode");

	info!("freeing endpoint from first-level test CNode");
	test_cnode.free_and_delete_slot_with_object::<Endpoint, _>(&test_endpoint, 0, alloc).expect("could not free endpoint from first-level test CNode");

	info!("freeing dummy slots");
	test_cnode.free_slot(dummy_slot_1, alloc).expect("failed to deallocate dummy slot");
	test_cnode.free_slot(dummy_slot, alloc).expect("failed to deallocate dummy slot");
	info!("freeing first-level test CNode");
	if test_cnode.slots_remaining() != 1 << TEST_CNODE_SIZE {
		panic!("used slots remaining in first-level test CNode (actual free: {}, expected free: {}", test_cnode.slots_remaining(), 1 << TEST_CNODE_SIZE);
	}
	root_cnode.free_and_delete_sublevel(test_cnode, alloc).expect("failed to delete first-level test CNode");
}

fn test_device_allocation(initial_cnode: &SwitchingAllocator, alloc: &BootstrapAllocatorBundle){
	info!("allocating page at address 0");
	let page_0 = initial_cnode.allocate_slot_with_object::<sel4::Page, _>(0, UtZone::Device(0), alloc).expect("test allocation of page at 0x0 failed");
	info!("allocating page at address 0xf000");
	let page_f000 = initial_cnode.allocate_slot_with_object::<sel4::Page, _>(0, UtZone::Device(0xf000), alloc).expect("test allocation of page at 0xf000 failed");

	info!("allocating page at address 0x10000");
	let page_0x10000 = initial_cnode.allocate_slot_with_object::<sel4::Page, _>(0, UtZone::Device(0x10000), alloc).expect("test allocation of page at 0x10000 failed");
}

struct HeapTest {
	link: LinkedListLink,
	contents: Vec<u8>,
}

intrusive_adapter!(HeapTestAdapter = Box<HeapTest>: HeapTest { link: LinkedListLink });

pub(crate) fn test_heap() {
	info!("testing heap allocation");

	let mut list = LinkedList::new(HeapTestAdapter::new());
	const NUM_ALLOC_SIZES: usize = 12;
	let alloc_sizes: [usize; NUM_ALLOC_SIZES] = [
		1024,
		128,
		16384,
		16,
		2048,
		256,
		32,
		32768,
		4096,
		512,
		64,
		8192
	];
	for j in 0..128 {
		println!("running heap tests: {}", j); 
		let mut allocated = 0; 
		let mut size_idx = 0; 
		for i in 0..32768 {
			if i % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("allocating heap test node: {} {}", j, i);
			}
			let mut test_obj = Box::new(HeapTest {
				link: LinkedListLink::new(),
				contents: Vec::new(),
			});
			allocated += 64;
			//info!("allocating test vector {}", i);
			test_obj.contents.reserve_exact(alloc_sizes[size_idx]);
			size_idx += 1;
			if size_idx == NUM_ALLOC_SIZES {
				size_idx = 0;
			}
			list.push_front(test_obj);
			allocated += alloc_sizes[size_idx];
			/*if size_idx == NUM_ALLOC_SIZES - 1 {
				println!("total allocated: {}", allocated);
			}*/
		}
		info!("UTSpace status after allocation:");
		info!("{:?}", get_kobj_alloc().utspace());
		info!("Heap status after allocation:");
		dump_heap();
		let mut deallocated = 0;
		loop {
			let node = list.pop_front();
			if node.is_none() {
				break
			}
			let ptr = Box::into_raw(node.unwrap());
			if deallocated % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("dropping heap test node: {} {} {:p}", j, deallocated, ptr);
			}
			drop(unsafe{Box::from_raw(ptr)}); 
			deallocated += 1;
		}
		info!("UTSpace status after deallocation:");
		info!("{:?}", get_kobj_alloc().utspace());
		info!("Heap status after deallocation:");
		dump_heap();
	}
}

struct UtSlabTest {
	link: LinkedListLink,
	thread: Thread,
	endpoint: Endpoint,
	notification: Notification,
	sched_context: SchedContext,
	reply: Reply,
}

impl UtSlabTest {
	fn new() -> UtSlabTest {
		let kobj_alloc = get_kobj_alloc();

		debug!("allocating thread");
		let thread = kobj_alloc.cspace().allocate_slot_with_object::<Thread, _>(0, UtZone::RamAny, &kobj_alloc).expect("could not allocate thread");
		debug!("allocating endpoint");
		let endpoint = kobj_alloc.cspace().allocate_slot_with_object::<Endpoint, _>(0, UtZone::RamAny, &kobj_alloc).expect("could not allocate endpoint");
		debug!("allocating notification");
		let notification = kobj_alloc.cspace().allocate_slot_with_object::<Notification, _>(0, UtZone::RamAny, &kobj_alloc).expect("could not allocate notification");
		debug!("allocating scheduling context");
		let sched_context = kobj_alloc.cspace().allocate_slot_with_object::<SchedContext, _>(8, UtZone::RamAny, &kobj_alloc).expect("could not allocate scheduling context");
		debug!("allocating reply");
		let reply = kobj_alloc.cspace().allocate_slot_with_object::<Reply, _>(0, UtZone::RamAny, &kobj_alloc).expect("could not allocate reply");
		drop(kobj_alloc);
		UtSlabTest {
			link: LinkedListLink::new(),
			thread,
			endpoint,
			notification,
			sched_context,
			reply,
		}
	}
}
impl Drop for UtSlabTest {
	fn drop(&mut self){
		let kobj_alloc = get_kobj_alloc();
		debug!("deallocating thread");
		kobj_alloc.cspace().free_and_delete_slot_with_object(&self.thread, 0, &kobj_alloc).expect("failed to deallocate thread");
		debug!("deallocating endpoint");
		kobj_alloc.cspace().free_and_delete_slot_with_object(&self.endpoint, 0, &kobj_alloc).expect("failed to deallocate endpoint");
		debug!("deallocating notification");
		kobj_alloc.cspace().free_and_delete_slot_with_object(&self.notification, 0, &kobj_alloc).expect("failed to deallocate notification");
		debug!("deallocating scheduling context");
		kobj_alloc.cspace().free_and_delete_slot_with_object(&self.sched_context, 8, &kobj_alloc).expect("failed to deallocate scheduling context");
		debug!("deallocating reply");
		kobj_alloc.cspace().free_and_delete_slot_with_object(&self.reply, 0, &kobj_alloc).expect("failed to deallocate reply");
		drop(kobj_alloc);
	}
}

intrusive_adapter!(UtSlabTestAdapter = Box<UtSlabTest>: UtSlabTest { link: LinkedListLink });

fn dump_cnode(window_opt: Option<Window>, info_opt: Option<CNodeInfo>){
	let window = window_opt.unwrap();
	let info = info_opt.unwrap();
	println!("window.cnode.depth: {}", window.cnode.depth);
	println!("window.cnode.cptr: {:x}", window.cnode.cptr);
	println!("window.cnode.root: {:x}", window.cnode.root.to_cap());
	println!("window.num_slots: {}", window.num_slots);
	println!("window.first_slot_idx: {:x}", window.first_slot_idx);

	println!("info.guard_val: {}", info.guard_val);
	println!("info.radix_bits: {}", info.radix_bits);
	println!("info.guard_bits: {}", info.guard_bits);
	println!("info.prefix_bits: {}", info.prefix_bits);
}


pub(crate) fn test_utspace_slabs() {
	info!("testing UTSpace slab allocation");
	
	let mut list = LinkedList::new(UtSlabTestAdapter::new());
	for j in 0..128 {
		println!("running UTSpace slab tests: {}", j);
		let mut allocated = 0;
		let mut size_idx = 0;
		for i in 0..16384 {
			if i % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("allocating UTSpace test node: {} {}", j, i);
			}
			let mut test_obj = Box::new(UtSlabTest::new());
			list.push_front(test_obj);
			yield_now();
		}
		info!("UTSpace status after allocation:");
		info!("{:?}", get_kobj_alloc().utspace());
		info!("Heap status after allocation:");
		dump_heap();
		let mut deallocated = 0;
		loop {
			let opt = list.pop_front();
			if opt.is_none() {
				break
			}
			let ptr = Box::into_raw(opt.unwrap());
			if deallocated % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("dropping UTSpace test node: {} {} {:p}", j, deallocated, ptr);
			}
			let node = unsafe{Box::from_raw(ptr)};
			drop(node); 
			deallocated += 1;
			yield_now();
		}
		info!("UTSpace status after deallocation:");
		info!("{:?}", get_kobj_alloc().utspace());
		info!("Heap status after deallocation:");
		dump_heap();
	}
}

pub fn run_alloc_tests_initial(alloc: &BootstrapAllocatorBundle){
	//repeat this to check if slots are being left with capabilities
	//in them
	info!("running initial CNode allocator tests");
	test_initial_cnode(alloc);
	info!("running initial CNode allocator tests again");
	test_initial_cnode(alloc);
}
pub fn run_alloc_tests_pre_dynamic(initial_cnode: &SwitchingAllocator, root_cnode: &BumpAllocator, allocators: &BootstrapAllocatorBundle){
	let (initial_cnode, untyped, proc_vspace) = &allocators;
	let test_slot = initial_cnode.allocate_slot(allocators).unwrap();

	info!("running initial CNode tests again");
	test_initial_cnode(&allocators);

	info!("running sublevel CNode tests");
	test_sublevel_cnodes(&root_cnode, allocators);
	info!("running sublevel CNode tests again");
	test_sublevel_cnodes(&root_cnode, allocators);

	info!("running dynamic CNode allocator tests");
	test_dynamic_cnode(&root_cnode, allocators);
	info!("UTSpace status after tests:");
	info!("{:?}", untyped);
	test_device_allocation(initial_cnode, &allocators);
	info!("UTSpace status after tests:");
	info!("{:?}", untyped);

	info!("Heap status after tests:");
	dump_heap();

	println!("testing vector reallocation");
	let mut test_vec_1: Vec<usize> = Vec::new();
	for i in 0..1024 {
		//println!("test 1: push {}", i);
		test_vec_1.push(i);
		for j in 0..i {
			if test_vec_1[j] != j {
				panic!("unexpected value {} in test vector at index {}", test_vec_1[j], j);
			}
		}
	}

	let mut test_vec_2: Vec<usize> = Vec::new();
	for i in 0..1024 {
		//println!("test 2: push {}", i);
		if test_vec_2.capacity() <= i + 1 {
			test_vec_2.reserve_exact(1);
		}
		test_vec_2.push(i);
		for j in 0..i {
			if test_vec_2[j] != j {
				panic!("unexpected value {} in test vector at index {}", test_vec_2[j], j);
			}
		}
	}
}

pub fn run_alloc_tests_post_dynamic<A: CustomSlabAllocator>(alloc: &A){
	add_slab::<HeapTest>(512, 16, 16, 2).expect("failed to add custom slab for heap test nodes");
	add_slab::<UtSlabTest>(512, 16, 16, 2).expect("failed to add custom slab for UTSlab test nodes");
	#[cfg(all(feature = "test_alloc", not(feature = "test_job")))]
	{
		run_alloc_tests_looped();
	}
	info!("allocator tests finished");
}

pub fn run_alloc_tests_looped(){
	test_heap();
	test_utspace_slabs();
	#[cfg(all(feature = "test_alloc_random"))]
	{
		test_heap_random();
		test_utspace_slabs_random();
	}
	println!("Heap status after all allocator tests finished:");
	dump_heap();
	info!("allocator tests finished");
}


const RANDOM_ROUNDS: usize = 10485760;
const UTSPACE_MAX_ALLOCATIONS: usize = 256;
const HEAP_MAX_ALLOCATIONS: usize = 512;
const HEAP_MAX_ITEM_SIZE: usize = 16384;
const MIN_ALLOCATIONS: usize = 128;

use rand::{Rng, SeedableRng};
use rand_pcg::Pcg64Mcg;
use alloc::collections::VecDeque;

pub(crate) fn test_heap_random() {
	info!("fuzz testing heap allocation");
	let mut rng = Pcg64Mcg::seed_from_u64(1234567890);
	let mut list = VecDeque::new();
	let mut force_deallocation = false;
	for i in 0..RANDOM_ROUNDS {
		if !force_deallocation {
			force_deallocation = rng.gen_range(0..200) == 0;
		}
		if list.len() == 0 {
			force_deallocation = false;
		}
		if !force_deallocation && (list.len() < MIN_ALLOCATIONS || list.len() < HEAP_MAX_ALLOCATIONS && rng.gen_range(0..2) > 0) {
			let size = rng.gen_range(0..HEAP_MAX_ITEM_SIZE);
			if i % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("  allocating heap test object: {} {} {}", i, size, list.len());
			}
				
			let mut item: Vec<u8> = Vec::new();
			item.reserve_exact(size);
			list.push_back(item);
		}else{
			let obj = rng.gen_range(0..list.len());
			if i % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("deallocating heap test object: {} {} {}", i, obj, list.len());
			}
			list.remove(obj);
		}
		yield_now();
	}
}

pub(crate) fn test_utspace_slabs_random() {
	info!("fuzz testing UTSpace allocation");
	let mut rng = Pcg64Mcg::seed_from_u64(1234567890);
	let mut list = VecDeque::new();
	let mut force_deallocation = false;
	for i in 0..RANDOM_ROUNDS {
		if !force_deallocation {
			force_deallocation = rng.gen_range(0..200) == 0;
		}
		if list.len() == 0 {
			force_deallocation = false;
		}
		if !force_deallocation && (list.len() < MIN_ALLOCATIONS || list.len() < UTSPACE_MAX_ALLOCATIONS && rng.gen_range(0..2) > 0) {
			if i % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("  allocating UTSpace test object: {} {}", i, list.len());
			}
			list.push_back(UtSlabTest::new());
		}else{
			let obj = rng.gen_range(0..list.len());
			if i % 32 == 0 || log::max_level() == LevelFilter::Debug {
				info!("deallocating UTSpace test object: {} {} {}", i, obj, list.len());
			}
			list.remove(obj);
		}
	}
	yield_now();
}
/* set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab */
