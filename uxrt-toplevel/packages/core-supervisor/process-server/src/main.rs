/*
 * Copyright (c) 2018-2023 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 */

#![no_std]

#![feature(default_alloc_error_handler)]
#![feature(allocator_api, core_intrinsics)]
#![feature(thread_local)]
#![feature(const_btree_new)]
#![feature(map_first_last)]
#[macro_use]
extern crate alloc;

#[macro_use]
extern crate static_assertions;

#[macro_use]
extern crate intrusive_collections;

extern crate bitmap;
extern crate sel4_sys;
extern crate sel4_start;
#[macro_use]
extern crate sel4;
#[macro_use]
extern crate sel4_alloc;
extern crate usync;
#[macro_use]
extern crate slab_allocator_core;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

extern crate uxrt_transport_layer;

#[macro_use]
mod logger;

mod bootinfo;
mod drivers;
mod job;
mod vfs;
mod vm;
mod utils;

mod tests;

use bootinfo::process_bootinfo;
use sel4_alloc::heap::NUM_GENERIC_SLABS;
use sel4_alloc::AllocatorBundle;

mod bootstrap_heap {
	use sel4::PAGE_SIZE;
	use sel4_alloc::heap::NUM_GENERIC_SLABS;
	const SCRATCH_LEN_BYTES: usize = 1712128;
	bootstrap_heap!(SCRATCH_LEN_BYTES, PAGE_SIZE);
}

use bootstrap_heap::bootstrap_heap_info;

mod global_heap_alloc {
	use sel4_alloc::{
		cspace::SwitchingAllocator,
		vspace::Hier,
	};
	use crate::vm::ut_alloc::SwappingUtAllocator;
	global_alloc!((SwitchingAllocator, SwappingUtAllocator, Hier));
}
use global_heap_alloc::{
	GlobalSlabAllocator,
	get_kobj_alloc,
};

#[global_allocator] 
static ALLOCATOR: GlobalSlabAllocator = GlobalSlabAllocator::new();

const VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub fn dump_heap() {
	info!("{:?})", ALLOCATOR);
}

pub fn dump_utspace() {
	info!("{:?}", get_kobj_alloc().utspace());
}


const BOOTSTRAP_SLAB_SIZES: [usize; NUM_GENERIC_SLABS] = [
	256, //16
	128, //32
	512, //64
	512, //128
	128, //256
	128, //512
	128, //1024
	32,  //2048
	32,  //4096
	64,  //8192
	8,   //16384
	16,  //32768
];

pub fn add_custom_slabs() {
	job::add_custom_slabs();
	vfs::add_custom_slabs();
	vm::add_custom_slabs();
}

pub fn main() {
	println!("\nUX/RT version {}", VERSION);
	logger::init().expect("failed to initialize logging");

	let bootinfo: &'static sel4_sys::seL4_BootInfo = unsafe { &*sel4_start::BOOTINFO };
	unsafe { ALLOCATOR.init(bootstrap_heap_info(BOOTSTRAP_SLAB_SIZES)); }

	let mbi_handler = process_bootinfo(bootinfo);
	vm::init_root_alloc(bootinfo, mbi_handler.user_start_addr, mbi_handler.user_end_addr, mbi_handler.root_server_end_addr);
	add_custom_slabs();

	vfs::init_spaces();

	job::init_job_tree(bootinfo, mbi_handler);

	vfs::init();
	
	vm::fault::get_fault_handler().init();

	#[cfg(feature = "test_job")]
	tests::job::test_threads_base();
	#[cfg(any(feature = "test_job", feature = "test_vfs"))]
	let mut local_threads = tests::create_local_test_threads();
	#[cfg(feature = "test_job")]
	tests::job::test_threads_local(&mut local_threads);
	#[cfg(feature = "test_vfs")]
	tests::vfs::test_vfs(&mut local_threads);
	#[cfg(any(feature = "test_job", feature = "test_vfs"))]
	tests::deallocate_local_threads(&mut local_threads);

	info!("processes after initialization:");
	job::get_job_tree().dump_processes();

	info!("end of main reached; halting");
	loop {
		unsafe { sel4_sys::seL4_DebugHalt() };
	}
}

/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
