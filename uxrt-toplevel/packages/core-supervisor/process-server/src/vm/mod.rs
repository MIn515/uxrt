/*
 * Copyright (c) 2019-2023 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This module includes basic memory management infrastructure (however,
 * user-facing memory management is not included here and is mostly implemented
 * in memfs and procfs, which wrap this module, instead).
 */

//TODO: move these into an architecture-dependent module, since they will depend on CPtr size (which is normally the same as word size)
//on 32-bit platforms, the top-level CNode will be 10 bits, and each process sub-level CNode will be 2 bits, allowing for 20 bits worth of mapping descriptors
const ROOT_CNODE_SIZE: usize = 2;
const DYNAMIC_HEAP_CNODE_SIZE: usize = 16;
const USER_TOPLEVEL_CNODE_SIZE: usize = 12;

use sel4::{
	Badge,
	CAP_NULL,
	WORD_BITS,
	CapRights,
	CNode,
	CNodeInfo,
	Endpoint,
	FromCap,
	FromSlot,
	SlotRef,
	Thread,
	ToCap,
	Window,
	seL4_Word,
};
use sel4_sys::seL4_CNode_Rotate;

use sel4_alloc::{
	AllocatorBundle,
	bootstrap::bootstrap_allocators,
	cspace::{
		AllocatableSlotRef, BumpAllocator, CSpaceError,
		CSpaceManager, CopyableCSpaceManager, DynamicBitmapAllocator,
		MovableCSpaceManager,
	},
	heap::DynamicSlabInfo,
	utspace::UTSpaceManager,
};

use sel4_thread::CommonThreadConfig;

use usync::Mutex;

#[cfg(feature = "test_alloc")]
use crate::tests;

use crate::{ALLOCATOR, dump_heap};
use crate::global_heap_alloc::get_kobj_alloc;
use crate::vm::ut_alloc::SwappingUtAllocator;

pub mod fault;
pub mod ut_alloc;
pub mod vspace;

static mut ROOT_COMMON_CONFIG: Option<CommonThreadConfig> = None;

static mut ROOT_ALLOCATOR_BUNDLE: RootAllocatorBundle = RootAllocatorBundle::new();


///Gets the `CommonThreadConfig` for root server threads
pub fn get_root_common_config() -> CommonThreadConfig {
	//safety: ROOT_COMMON_CONFIG is set once at boot and never modified 
	//after that
	unsafe { ROOT_COMMON_CONFIG.expect("root server thread configuration not initialized") }
}

///Gets the root allocator bundle
pub fn get_root_alloc() -> &'static RootAllocatorBundle {
	//safety: this is only ever borrowed as mutable once during boot to
	//initialize it
	unsafe { &ROOT_ALLOCATOR_BUNDLE }
}

///Sets the root allocator bundle
pub fn init_root_alloc(bootinfo: &'static sel4::seL4_BootInfo, user_start_addr: usize, user_end_addr: usize, root_server_end_addr: usize){
	unsafe { ROOT_ALLOCATOR_BUNDLE.init(bootinfo, user_start_addr, user_end_addr, root_server_end_addr) }
}

///Contains non-heap-related allocators
pub struct RootAllocatorBundle {
	pub user_root_cnode: Mutex<Option<DynamicBitmapAllocator>>,
	pub user_vm_cnode: Mutex<Option<DynamicBitmapAllocator>>,
	fault_endpoint: Option<SlotRef>,
	root_cnode: Option<BumpAllocator>,
}

///Dumps the `Window` and `CNodeInfo` for a CNode 
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

///Encodes the PID and TID into a Badge for the fault handler
#[cfg(target_pointer_width = "64")]
fn encode_fault_badge(pid: i32, tid: i32) -> Badge {
	Badge::new((pid as seL4_Word) << 32 | tid as seL4_Word)
}

///Decodes the badge from a page fault into a PID and TID
#[cfg(target_pointer_width = "64")]
fn decode_fault_badge(badge: seL4_Word) -> (i32, i32) {
	(badge.wrapping_shr(32) as i32, (badge & ((1<<32) - 1)) as i32)
}

impl RootAllocatorBundle {
	///Creates a `RootAllocatorBundle`
	const fn new() -> RootAllocatorBundle {
		RootAllocatorBundle {
			user_root_cnode: Mutex::new(None),
			user_vm_cnode: Mutex::new(None),
			fault_endpoint: None,
			root_cnode: None,
		}
	}
	///Gets the base fault endpoint (which is the unbadged prototype for
	///the badged endpoints used as thread fault endpoints)
	pub fn get_orig_fault_endpoint(&self) -> Endpoint {
		Endpoint::from_slot(self.fault_endpoint.expect("fault endpoint not initialized"))
	}
	///Allocates a new thread fault endpoint
	pub fn allocate_fault_endpoint<A: AllocatorBundle>(&self, pid: i32, tid: i32, alloc: &A) -> Result<Endpoint, CSpaceError>{
		let orig_endpoint = self.fault_endpoint.expect("fault endpoint unset");
		let badge = encode_fault_badge(pid, tid);
		match orig_endpoint.mint_to_new(alloc.cspace(), CapRights::all(), badge, alloc){
			Ok(slot) => Ok(Endpoint::from_slot(slot)),
			Err(err) => Err(err),
		}
	}
	///Initializes the `RootAllocatorBundle`
	fn init(&mut self, bootinfo: &'static sel4::seL4_BootInfo, user_start_addr: usize, user_end_addr: usize, root_server_end_addr: usize){
		info!("creating initial allocators");
		let mut allocators = bootstrap_allocators(bootinfo, user_start_addr, user_end_addr);
		let (initial_cnode, untyped, vspace) = &allocators;
		unsafe { sel4_thread::init_root(&allocators) };
		let vspace_cap = vspace.to_cap();
		info!("UTSpace status:");
		info!("{:?}", untyped);

		#[cfg(feature = "test_alloc")]
		tests::alloc::run_alloc_tests_initial(&allocators);

		info!("creating root CNode");
		let root_cnode = initial_cnode.allocate_sublevel_bump(ROOT_CNODE_SIZE, true, &allocators).expect("cannot initialize root CNode");

		info!("minting initial CNode into root CNode");
		let initial_cnode_guard_bits = WORD_BITS as usize - ROOT_CNODE_SIZE as usize - bootinfo.initThreadCNodeSizeBits as usize;
		initial_cnode.mint_to_new(&root_cnode, CapRights::all(), 0, initial_cnode_guard_bits as u8, &allocators).expect("cannot mint initial CNode capability into new root CNode");

		let initial_cnode_depth = ROOT_CNODE_SIZE;

		let mut new_initial_cnode_slot = initial_cnode.window().unwrap().cnode;
		new_initial_cnode_slot.depth = initial_cnode_depth as u8;
		new_initial_cnode_slot.cptr = 0;

		let new_initial_cnode_info = CNodeInfo {
			guard_val: 0,
			radix_bits: bootinfo.initThreadCNodeSizeBits as u8,
			guard_bits: initial_cnode_guard_bits as u8,
			prefix_bits: initial_cnode_depth as u8,
		};

		let root_slot = initial_cnode.to_slot().expect("initial CNode has no slot");
		info!("creating temporary slot for initial CNode");
		let temp_root_slot = initial_cnode.copy_to_new(initial_cnode, CapRights::all(), &allocators).expect("cannot copy initial CNode capability to temporary slot");
		let new_root_slot = root_cnode.to_slot().expect("root CNode has no slot");

		let initial_thread = Thread::from_cap(sel4_sys::seL4_CapInitThreadTCB);
		info!("replacing root pointer of initial CNode with new root");
		unsafe {
			let ret = seL4_CNode_Rotate(temp_root_slot.cptr,
					root_slot.cptr,
					WORD_BITS as u8,
					0,
					temp_root_slot.cptr,
					new_root_slot.cptr,
					WORD_BITS as u8,
					0,
					temp_root_slot.cptr,
					root_slot.cptr,
					WORD_BITS as u8);
			if ret != 0 {
				panic!("cannot replace root CNode self-pointer: seL4_CNode_Rotate failed with code {}", ret);
			}
		}

		info!("switching initial thread to new root CNode");
		initial_thread.set_space(CAP_NULL, CNode::from_cap(root_slot.cptr), 0, sel4_sys::seL4_CapInitThreadVSpace, 0).expect("cannot switch to new root CNode");

		let root_alloc_slot = SlotRef::new(root_slot.root, 0, 0);

		root_cnode.set_slot(root_alloc_slot).expect("cannot update slot of root CNode");

		initial_cnode.set_slot(new_initial_cnode_slot).expect("cannot update slot of initial CNode");
		initial_cnode.set_info(new_initial_cnode_info).expect("cannot update info of initial CNode");
		#[cfg(feature = "test_alloc")]
		tests::alloc::run_alloc_tests_pre_dynamic(&initial_cnode, &root_cnode, &allocators);

		info!("allocating dynamic CNode for heap");
		//TODO: use more than two levels here once support is added
		let dynamic_heap_cnode = root_cnode.allocate_sublevel_dynamic_bitmap(DYNAMIC_HEAP_CNODE_SIZE, false, DYNAMIC_HEAP_CNODE_SIZE, 1024, 1024, 2, &allocators).expect("cannot allocate dynamic heap CNode");

		let user_root_cnode = root_cnode.allocate_sublevel_dynamic_bitmap(USER_TOPLEVEL_CNODE_SIZE, false, USER_TOPLEVEL_CNODE_SIZE, 1024, 1024, 2, &allocators).expect("cannot allocate top-level CNode for user roots");
		let user_vm_cnode = root_cnode.allocate_sublevel_dynamic_bitmap(USER_TOPLEVEL_CNODE_SIZE, false, USER_TOPLEVEL_CNODE_SIZE, 1024, 1024, 2, &allocators).expect("cannot allocate top-level CNode for user pages");

		allocators.0.add_second(dynamic_heap_cnode).expect("could not add dynamic heap to initial CSpace");

		unsafe { ROOT_COMMON_CONFIG = Some(CommonThreadConfig {
			cspace_root: root_cnode.to_cnode().unwrap(),
			cspace_root_data: 0,
			vspace_root: vspace_cap,
			vspace_root_data: 0,
			//this gets replaced when allocating a new root server
			//thread
			fault_endpoint: Endpoint::from_cap(0),
		}); }

		self.root_cnode = Some(root_cnode);

		let cspace_alloc = allocators.0;
		let utspace_alloc = SwappingUtAllocator::new(allocators.1).expect("could not initialize swapping allocator");
		let vspace_alloc = allocators.2;
		info!("initializing dynamic heap allocation");
		unsafe { ALLOCATOR.init_dynamic((cspace_alloc, utspace_alloc, vspace_alloc),
		[
			DynamicSlabInfo(256,  64, 64,  2), //16
			DynamicSlabInfo(128,  64, 64,  2), //32
			DynamicSlabInfo(128,  64, 64,  2), //64
			DynamicSlabInfo(128,  64, 64,  2), //128
			DynamicSlabInfo(128,  64, 64,  2), //256
			DynamicSlabInfo(128,  64, 64,  2), //512
			DynamicSlabInfo(64,   32, 32,  2), //1024
			DynamicSlabInfo(32,   16, 16,  2), //2048
			DynamicSlabInfo(32,   16, 16,  2), //4096
			DynamicSlabInfo(32,   16, 16,  2), //8192
			DynamicSlabInfo(4,    2,  2,   2), //16384
			DynamicSlabInfo(2,    2,  2,   2), //32768
		],
		)}

		info!("initializing UTSpace slab allocator");

		let kobj_alloc = get_kobj_alloc();
		kobj_alloc.utspace().init_slabs(&[], &kobj_alloc);

		info!("UTSpace status after initialization:");
		info!("{:?}", kobj_alloc.utspace());
		info!("Heap status after initialization:");
		dump_heap();

		#[cfg(feature = "test_alloc")]
		tests::alloc::run_alloc_tests_post_dynamic(&ALLOCATOR);

		self.user_vm_cnode.lock().replace(user_vm_cnode);
		self.user_root_cnode.lock().replace(user_root_cnode);

		info!("allocating fault endpoint");
		let fault_endpoint = kobj_alloc.cspace().allocate_slot_with_object_ref_fixed::<Endpoint, _>(&kobj_alloc);
		if let Err(err) = fault_endpoint {
			panic!("could not allocate fault endpoint {:?}", err);
		}

		self.fault_endpoint = Some(fault_endpoint.unwrap());

		info!("initializing VSpaces");
		vspace::init_vspaces();
	}
}

///Adds slabs for virtual-memory-related objects
pub fn add_custom_slabs(){
	vspace::add_custom_slabs();
}

/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
