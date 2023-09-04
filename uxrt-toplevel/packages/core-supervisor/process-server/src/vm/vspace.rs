/*
 * Copyright (c) 2023 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This is the core VSpace manager, providing support for buffer and file 
 * mappings
 */

use core::mem::{
	forget,
	size_of,
};
use core::ptr::copy;

use core::cell::Cell;

use core::sync::atomic::{
	AtomicI32,
	AtomicUsize,
	Ordering,
};

use alloc::boxed::Box;

use alloc::sync::{
	Arc,
	Weak,
};

use usync::{
	Mutex,
	RwLock,
	RwLockReadGuard,
	RwLockWriteGuard
};

use sel4::{
	CapRights,
	Mappable,
	PAGE_BITS,
	PAGE_SIZE,
	SlotRef,
	ToCap,
	seL4_CPtr,
};

use sel4_alloc::{
	AllocatorBundle,
	seL4_ARCH_VMAttributes,
};

use core::ops::Deref;

use custom_slab_allocator::CustomSlabAllocator;

use sel4_alloc::utspace::UtZone;

use sel4_alloc::vspace::{
	HierReservation,
	Hier,
	MemRegion,
	PageDeallocType,
	VSpaceError,
	VSpaceManager,
};

use intrusive_collections::{
	Bound,
	KeyAdapter,
	RBTree,
	RBTreeAtomicLink,
	UnsafeRef
};


use crate::add_arc_slab;
use crate::utils::add_slab;
use crate::vfs::transport::UserSecondaryBufferArray;

use crate::utils::GlobalIDAllocator;
use crate::global_heap_alloc::{
	AllocatorBundleGuard,
	get_kobj_alloc,
};

//TODO: add generic definitions for the various flags (the actual values will be arch-dependent)
pub type VMAttributes = u64;

///Permissions for a memory region
#[derive(Copy, Clone)]
pub struct MemRights {
	cap_rights: CapRights,
	attrs: seL4_ARCH_VMAttributes,
}

impl MemRights {
	///Creates a new `MemRights` instance
	///
	///Currently, allow_exec has no effect, but support for it will be
	///added eventually
	pub fn new(allow_read: bool, allow_write: bool, allow_exec: bool) -> MemRights {
		let attrs = 0; //TODO: actually support non-executable pages (this will need kernel support for the NX bit, which is missing on x86)
		MemRights {
			cap_rights: CapRights::new(false, false, allow_read, allow_write),
			attrs,
		}
	}
	///Gets the `CapRights` and `VMAttributes` corresponding to this 
	///`MemRights`
	fn to_raw(&self, attrs: seL4_ARCH_VMAttributes) -> (CapRights, seL4_ARCH_VMAttributes) {
		(self.cap_rights, self.attrs | attrs)
	}
	///Creates a read-write `MemRights` instance
	pub fn rw() -> MemRights {
		MemRights::new(true, true, false)
	}
	///Creates a read-execute `MemRights` instance
	pub fn rx() -> MemRights {
		MemRights::new(true, false, true)
	}
	///Creates a read-only `MemRights` instance
	pub fn r() -> MemRights {
		MemRights::new(true, false, false)
	}
	///Create a write-only `MemRights` instance
	pub fn w() -> MemRights {
		MemRights::new(false, true, false)
	}
}

//TODO: reserve the upper half of userspace for buffers and FD/buffer arrays, and add a flag to VRegionFactory to indicate a region that should be mapped into this space
//TODO: add support in VRegionFactory for tracking the associated file and automatically freeing its contents on drop

///A memory region that may be mapped into multiple VSpaces
///
///Each mapping of a page requires a separate copy of the capability. This is
///implemented as a factory in order to abstract away the copying
pub struct VRegionFactory {
	phys_region: MemRegion,
	virt_regions: RBTree<VRegionFactoryAdapter>,
	self_ref: Cell<Weak<Mutex<VRegionFactory>>>,
	rights: MemRights,
	attrs: VMAttributes,

}

impl VRegionFactory {
	//TODO: add methods to create factories for device and boot image memory, as well as ones that reserve a greater number of pages than they map
	///Creates a new VRegionFactory from RAM or device memory
	pub fn new(bytes: usize, size_bits: usize, rights: MemRights, attrs: VMAttributes, zone: UtZone) -> Result<Arc<Mutex<VRegionFactory>>, VSpaceError> {
		let kobj_alloc = get_kobj_alloc();
		let (raw_rights, raw_attrs) = rights.to_raw(attrs);
		match MemRegion::new(bytes, size_bits, raw_rights, raw_attrs, zone, &kobj_alloc, kobj_alloc.cspace()) {
			Ok(phys_region) => {
				let factory = Arc::new(Mutex::new(VRegionFactory {
					phys_region,
					virt_regions: Default::default(),
					self_ref: Cell::new(Weak::new()),
					rights,
					attrs,
				}));
				factory.lock().self_ref.set(Arc::downgrade(&factory));
				Ok(factory)
			},
			Err(err) => Err(err),
		}
	}
	///Internal method to create a new copy of this region to map into a
	///VSpace
	fn new_region(&mut self, rights: Option<MemRights>, attrs: Option<VMAttributes>) -> Result<(MemRegion, VRegion), VSpaceError> {
		//info!("new_region: {:p}", self);
		let r = rights.unwrap_or(self.rights);
		let a = attrs.unwrap_or(self.attrs);
		let (raw_rights, raw_attrs) = r.to_raw(a);
		let kobj_alloc = get_kobj_alloc();
		let p_region = match self.phys_region.new_clone(&kobj_alloc, Some(raw_rights), Some(raw_attrs), kobj_alloc.cspace()) {
			Ok(r) => r,
			Err((_, err)) => {
				return Err(err);
			},
		};

		let bytes = self.get_size();
		let v_region = VRegion::new(bytes, self.phys_region.get_size_bits(), r, a, self.self_ref.get_mut().clone());
		Ok((p_region, v_region))
	}
	///Gets the size in bytes of this region
	pub fn get_size(&self) -> usize {
		self.phys_region.get_caps().len() * (1 << self.phys_region.get_size_bits())
	}
	///Internal method to add a VSpace's copy of a region to the list
	fn add_region(&mut self, region: Arc<VRegion>){
		self.virt_regions.insert(region);
	}
	///Internal method to remove a VSpace's copy of a region from the list
	fn del_region(&mut self, vspace_id: i32, vaddr: usize) {
		let mut cursor = self.virt_regions.find_mut(&(vspace_id, vaddr));
		if !cursor.is_null(){
			cursor.remove();
		}
	}
	///Unmaps this region from all VSpaces it may be mapped into
	pub fn unmap_all(&mut self) -> Result<(), VSpaceError>{
		//info!("unmap_all: {:p}", self);
		let mut cursor = self.virt_regions.front_mut();
		if cursor.is_null(){
			return Ok(());
		}
		let vspaces = get_vspace_list();
		let mut res = Ok(());
		while !cursor.is_null(){
			let region = cursor.get().unwrap();
			if let Some(vspace) = vspaces.get(region.vspace_id) {
				if let Err(err) = vspace.write().unmap_from_factory(region.vaddr, region.bytes) {
					//info!("unmap_all: unmap {:x}", region.vaddr);
					res = Err(err);
				}
			}
			cursor.remove();
		}
		res
	}
	///Unmaps this region from an individual VSpace
	///
	///The start and end addresses specify the range to search for 
	///mappings. If multiple mappings are contained within the range, all
	///will be unmapped. If the range is less than an entire mapping, only
	///the part of the mapping within the range will be unmapped.
	pub fn unmap(&mut self, vspace_id: i32, start_addr: usize, end_addr: usize) -> Result<(), VSpaceError>{
		let mut cursor = self.virt_regions.lower_bound_mut(Bound::Included(&(vspace_id, start_addr)));
		if cursor.is_null(){
			return Ok(());
		}
		let vspaces = get_vspace_list();
		let mut res = Ok(());
		while !cursor.is_null() {
			let region = cursor.get().unwrap();
			if region.vaddr > end_addr {
				break;
			}
			if let Some(vspace) = vspaces.get(region.vspace_id) {
				if let Err(err) = vspace.write().unmap_from_factory(region.vaddr, region.bytes) {
					res = Err(err);
				}
			}
			cursor.remove();
		}
		res
	}
}

impl Drop for VRegionFactory {
	fn drop(&mut self){
		if !self.virt_regions.front().is_null(){
			let region = self.virt_regions.front().get().unwrap();
			panic!("attempted to drop VRegionFactory that is still mapped in VSpace {} at address {:x} with size {}", region.vspace_id, region.vaddr, region.bytes);
		}
		let kobj_alloc = get_kobj_alloc();
		self.phys_region.free(&kobj_alloc, kobj_alloc.cspace()).expect("failed to free physical pages for VRegion");
	}
}

pub struct SharedArc<T> {
	contents: Arc<SharedArcContents<T>>,
}

impl<T> SharedArc<T> {
	pub fn new(contents: T) -> SharedArc<T> {
		SharedArc {
			contents: Arc::new(SharedArcContents::new(contents)),
		}
	}
	pub fn to_region(arc: &Self) -> Arc<Mutex<VRegionFactory>>{
		SharedArcContents::to_region(&arc.contents)
	}
}

impl<T> Clone for SharedArc<T> {
	fn clone(&self) -> SharedArc<T>{
		SharedArc {
			contents: Arc::clone(&self.contents),
		}
	}
}

//TODO?: get rid of the redundant inner Arc somehow?
struct SharedArcContents<T> {
	contents_ref: UnsafeRef<T>,
	region: Arc<Mutex<VRegionFactory>>,
}

impl<T> SharedArcContents<T> {
	pub fn new(contents: T) -> SharedArcContents<T> {
		let region = VRegionFactory::new(size_of::<T>(), PAGE_BITS as usize, MemRights::rw(), 0, UtZone::RamAny).expect("cannot create region for shared data structure");
		let tmp = get_root_vspace();
		let mut vspace = tmp.write();

		let vaddr = vspace.map(region.clone(), None, None).expect("cannot map shared data structure into process server VSpace");

		unsafe { copy(&contents, vaddr as *mut T, 1) };
		let contents_ref = unsafe { UnsafeRef::from_raw(vaddr as *const T) };

		let ret = SharedArcContents {
			contents_ref,
			region,
		};
		forget(contents);
		info!("SharedArc::new: {:x}", vaddr);
		ret
	}
	pub fn to_region(contents: &Self) -> Arc<Mutex<VRegionFactory>>{
		contents.region.clone()
	}
}

impl<T> Deref for SharedArc<T> {
	type Target = T;
	fn deref(&self) -> &T {
		UnsafeRef::deref(&self.contents.contents_ref)
	}
}

impl<T> Drop for SharedArcContents<T> {
	fn drop(&mut self){
		let contents = self.contents_ref.clone();
		let ptr = UnsafeRef::into_raw(contents);
		info!("SharedArc::drop: {:p}", ptr);
		drop(ptr);
		self.region.lock().unmap_all().expect("cannot unmap SharedArc");
	}
}

///A VSpace's copy of a region
///
///This is purely internal; VRegionFactory is the public interface
struct VRegion {
	vspace_id: i32,
	vaddr: usize,
	bytes: usize,
	size_bits: usize,
	rights: MemRights,
	attrs: VMAttributes,
	pages_mapped: AtomicUsize,
	factory: Weak<Mutex<VRegionFactory>>,
	factory_link: RBTreeAtomicLink,
	vspace_link: RBTreeAtomicLink,
}

impl VRegion {
	///Creates a new `VRegion`
	fn new(bytes: usize, size_bits: usize, rights: MemRights, attrs: VMAttributes, factory: Weak<Mutex<VRegionFactory>>) -> VRegion {
		let mut pages = bytes / PAGE_SIZE;
		if bytes % PAGE_SIZE > 0 {
			pages += 1;
		}
		VRegion {
			vspace_id: 0,
			vaddr: 0,
			bytes,
			size_bits,
			rights,
			attrs,
			pages_mapped: AtomicUsize::new(pages),
			factory,
			factory_link: Default::default(),
			vspace_link: Default::default(),
		}
	}
}

intrusive_adapter!(VRegionFactoryAdapter = Arc<VRegion>: VRegion { factory_link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for VRegionFactoryAdapter {
	type Key = (i32, usize);
	fn get_key(&self, region: &'a VRegion) -> (i32, usize) {
		(region.vspace_id, region.vaddr)
	}
}

intrusive_adapter!(VRegionVSpaceAdapter = Arc<VRegion>: VRegion { vspace_link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for VRegionVSpaceAdapter {
	type Key = usize;
	fn get_key(&self, region: &'a VRegion) -> usize {
		region.vaddr
	}
}

///An allocator wrapped by `VSpace`
enum VSpaceContents {
	Root,
	User(Hier),
}

impl VSpaceContents {
	///Gets a mutex guard for the contained VSpace allocator
	fn lock(&self) -> VSpaceGuard {
		match self {
			VSpaceContents::Root => {
				let kobj_alloc = get_kobj_alloc();
				VSpaceGuard::Root(kobj_alloc)
			},
			VSpaceContents::User(ref vspace) => {
				VSpaceGuard::User(vspace)
			},
		}
	}
}

enum VSpaceGuard<'a> {
	Root(AllocatorBundleGuard<'a>),
	User(&'a Hier),
}

impl<'a> VSpaceManager for VSpaceGuard<'a> {
	type Reservation = HierReservation;
	///Maps the page capabilities given as wrapper objects into the VSpace
	///starting at the given virtual address
	fn map_at_vaddr<A: AllocatorBundle, M: Copy + Mappable + ToCap>(
		&self,
		caps: &[M],
		vaddr: usize,
		size_bits: usize,
		reservation: &Self::Reservation,
		rights: CapRights,
		attrs: seL4_ARCH_VMAttributes,
		alloc: &A,
	) -> Result<(), VSpaceError> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().map_at_vaddr(caps, vaddr, size_bits, reservation, rights, attrs, alloc),
			VSpaceGuard::User(vspace) => vspace.map_at_vaddr(caps, vaddr, size_bits, reservation, rights, attrs, alloc),
		}
	}
	///Maps the page capabilities given as SlotRefs into the VSpace starting at
	///the given virtual address
	fn map_at_vaddr_ref<A: AllocatorBundle>(
		&self,
		caps: &[SlotRef],
		vaddr: usize,
		size_bits: usize,
		reservation: &Self::Reservation,
		rights: CapRights,
		attrs: seL4_ARCH_VMAttributes,
		alloc: &A,
	) -> Result<(), VSpaceError> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().map_at_vaddr_ref(caps, vaddr, size_bits, reservation, rights, attrs, alloc),
			VSpaceGuard::User(vspace) => vspace.map_at_vaddr_ref(caps, vaddr, size_bits, reservation, rights, attrs, alloc),
		}
	}
	///Maps the page capabilities given as raw CPtrs into the VSpace 
	///starting at the given virtual address
	fn map_at_vaddr_raw<A: AllocatorBundle>(
		&self,
		caps: &[seL4_CPtr],
		vaddr: usize,
		size_bits: usize,
		reservation: &Self::Reservation,
		rights: CapRights,
		attrs: seL4_ARCH_VMAttributes,
		alloc: &A,
	) -> Result<(), VSpaceError> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().map_at_vaddr_raw(caps, vaddr, size_bits, reservation, rights, attrs, alloc),
			VSpaceGuard::User(vspace) => vspace.map_at_vaddr_raw(caps, vaddr, size_bits, reservation, rights, attrs, alloc),
		}
	}
	///Changes the protection on all pages mapped starting at `vaddr` 
	///going for `bytes` to `rights` and `attrs`.
	fn change_protection<A: AllocatorBundle>(
		&self,
		vaddr: usize,
		bytes: usize,
		rights: CapRights,
		attrs: seL4_ARCH_VMAttributes,
		alloc: &A,
	) -> Result<(), VSpaceError> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().change_protection(vaddr, bytes, rights, attrs, alloc),
			VSpaceGuard::User(vspace) => vspace.change_protection(vaddr, bytes, rights, attrs, alloc),
		}
	}

	///Unmaps pages which cover the region starting at `vaddr` going for 
	///`bytes` bytes.
	fn unmap<A: AllocatorBundle>(&self,
		vaddr: usize,
		bytes: usize,
		dealloc_type: PageDeallocType,
		alloc: &A
	) -> Result<usize, (usize, VSpaceError)> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().unmap(vaddr, bytes, dealloc_type, alloc),
			VSpaceGuard::User(vspace) => vspace.unmap(vaddr, bytes, dealloc_type, alloc),
		}
	}

	///Reserves a region of virtual memory.
	///
	///This will reserve at least `bytes` worth of virtual memory,
	///possibly rounded up to some multiple of some page size.
	fn reserve<A: AllocatorBundle>(&self, bytes: usize, alloc: &A) -> Option<Self::Reservation> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().reserve(bytes, alloc),
			VSpaceGuard::User(vspace) => vspace.reserve(bytes, alloc),
		}
	}

	///Reserves a region of virtual memory at a specific address.
	///
	///This will fail if the requested region overlaps an existing
	///reservation somewhere.
	///
	///This will reserve at least `bytes` worth of virtual memory,
	///possibly rounded up to some multiple of some page size.
	fn reserve_at_vaddr<A: AllocatorBundle>(
		&self,
		vaddr: usize,
		bytes: usize,
		alloc: &A,
	) -> Option<Self::Reservation> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().reserve(bytes, alloc),
			VSpaceGuard::User(vspace) => vspace.reserve(bytes, alloc),
		}
	}

	///Gets the reservation associated with an address.
	fn get_reservation(&self, vaddr: usize) -> Result<Self::Reservation, ()> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().get_reservation(vaddr),
			VSpaceGuard::User(vspace) => vspace.get_reservation(vaddr),
		}
	}

	///Unreserves a region.
	fn unreserve<A: AllocatorBundle>(&self, reservation: Self::Reservation, alloc: &A) -> Result<(), VSpaceError> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().unreserve(reservation, alloc),
			VSpaceGuard::User(vspace) => vspace.unreserve(reservation, alloc),
		}
	}

	///Unreserve a region given a pointer into it.
	///
	///`vaddr` can be any address in a region, it does not need to be the 
	///start address.
	fn unreserve_at_vaddr<A: AllocatorBundle>(&self, vaddr: usize, alloc: &A) -> Result<(), VSpaceError> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().unreserve_at_vaddr(vaddr, alloc),
			VSpaceGuard::User(vspace) => vspace.unreserve_at_vaddr(vaddr, alloc),
		}
	}

	///Unreserves only part of a region given a pointer into it and a
	///length.
	fn unreserve_range_at_vaddr<A: AllocatorBundle>(&self, vaddr: usize, bytes: usize, alloc: &A) -> Result<(), VSpaceError> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().unreserve_range_at_vaddr(vaddr, bytes, alloc),
			VSpaceGuard::User(vspace) => vspace.unreserve_range_at_vaddr(vaddr, bytes, alloc),
		}
	}

	///Gets the cap mapped in at an address.
	fn get_cap(&self, vaddr: usize) -> Option<seL4_CPtr> {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().get_cap(vaddr),
			VSpaceGuard::User(vspace) => vspace.get_cap(vaddr),
		}
	}

	///Gets the cap to the top-level paging structure.
	fn root(&self) -> seL4_CPtr {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().root(),
			VSpaceGuard::User(vspace) => vspace.root(),
		}
	}


	fn minimum_slots(&self) -> usize {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().minimum_slots(),
			VSpaceGuard::User(vspace) => vspace.minimum_slots(),
		}
	}

	fn minimum_untyped(&self) -> usize {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().minimum_untyped(),
			VSpaceGuard::User(vspace) => vspace.minimum_untyped(),
		}
	}


	fn minimum_vspace(&self) -> usize {
		match self {
			VSpaceGuard::Root(ref guard) => guard.vspace().minimum_vspace(),
			VSpaceGuard::User(vspace) => vspace.minimum_vspace(),
		}
	}
}

///Outer wrapper for `VSpaceContainer`, in order to allow easily giving out 
///`Arc`s to it while in a tree
struct VSpaceListWrapper {
	vspace: Arc<VSpaceContainer>,
	link: RBTreeAtomicLink,
}

///Wrapper for `VSpace` that holds the ID and an RwLock
pub struct VSpaceContainer {
	id: i32,
	contents: RwLock<VSpace>,
}

impl VSpaceContainer {
	///Creates a new VSpaceContainer
	fn new(id: i32, contents: VSpace) -> UnsafeRef<VSpaceListWrapper> {
		let vspace = Arc::new(VSpaceContainer {
			id,
			contents: RwLock::new(contents),
		});
		UnsafeRef::from_box(Box::new(VSpaceListWrapper {
			vspace,
			link: Default::default(),
		}))
	}
	///Gets the ID of this VSpace
	pub fn get_id(&self) -> i32 {
		self.id
	}
	///Gets a read-only guard for this VSpace
	pub fn read(&self) -> RwLockReadGuard<VSpace> {
		self.contents.read()
	}
	///Get a read-write guard for this VSpace
	pub fn write(&self) -> RwLockWriteGuard<VSpace> {
		self.contents.write()
	}
}

///The user-level interface to VSpaces
pub struct VSpace {
	id: i32,
	contents: VSpaceContents,
	mappings: RBTree<VRegionVSpaceAdapter>,
	secondary_buffers: Option<UserSecondaryBufferArray>,
}

impl VSpace {
	///Creates a new VSpace for the root server (currently only one of 
	///these is supported)
	fn new_root() -> VSpace {
		VSpace {
			id: 0,
			contents: VSpaceContents::Root,
			mappings: Default::default(),
			secondary_buffers: None,
		}
	}
	///Maps a `VRegionFactory` into this VSpace at the first available 
	///address (the address may be anywhere within the usable user-level 
	///address space). 
	///
	///`rights` and `attrs` may be none, in which case the ones from the
	///region are used.
	///
	///Returns the new address on success, or `VSpaceError` on failure.
	pub fn map(&mut self, factory: Arc<Mutex<VRegionFactory>>, rights: Option<MemRights>, attrs: Option<VMAttributes>) -> Result<usize, VSpaceError>{
		let kobj_alloc = get_kobj_alloc();
		let (mut p_region, mut v_region) = factory.lock().new_region(rights, attrs)?;
		let contents = self.contents.lock();
		let ret = match contents.map_region(&p_region, &kobj_alloc){
			Ok(vaddr) => {
				v_region.vspace_id = self.id;
				v_region.vaddr = vaddr;
				let v_region_arc = Arc::new(v_region);
				factory.lock().add_region(v_region_arc.clone());
				self.mappings.insert(v_region_arc);
				Ok(vaddr)
			},
			Err(err) => Err(err),
		};
		p_region.get_caps_mut().clear();
		ret
	}
	///Maps a `VRegionFactory` into this VSpace at a given virtual 
	///address.
	///
	///`rights` and `attrs` may be None, in which case the ones from the
	///region are used
	pub fn map_at_vaddr(&mut self, factory: Arc<Mutex<VRegionFactory>>, vaddr: usize, rights: Option<MemRights>, attrs: Option<VMAttributes>) -> Result<(), VSpaceError>{
		let kobj_alloc = get_kobj_alloc();
		let mut f = factory.lock();
		let contents = self.contents.lock();
		let res = if let Some(r) = contents.reserve_at_vaddr(vaddr, f.get_size(), &kobj_alloc) {
			r
		}else{
			return Err(VSpaceError::ReservationFailure);
		};

		let (p_region, mut v_region) = f.new_region(rights, attrs)?;

		if let Err(err) = contents.map_at_vaddr_region(&p_region, vaddr, &res, &kobj_alloc) {
			Err(err)
		}else{
			v_region.vspace_id = self.id;
			v_region.vaddr = vaddr;
			let arc_region = Arc::new(v_region);
			self.mappings.insert(arc_region.clone());
			f.add_region(arc_region);
			Ok(())
		}
	}
	///Unmaps any pages in the given address range, if any are mapped 
	///there (this still succeeds if the range is empty).
	pub fn unmap(&mut self, address: usize, bytes: usize) -> Result<(), VSpaceError> {
		self.unmap_base(address, bytes, false)
	}
	///Internal equivalent of unmap() called when unmapping a region from
	///a `VRegionFactory`. The only difference currently is that the 
	///`VRegion` isn't removed from the factory, since that will already
	///have been done (attempting to do it here would cause a deadlock).
	fn unmap_from_factory(&mut self, address: usize, bytes: usize) -> Result<(), VSpaceError> {
		self.unmap_base(address, bytes, true)
	}
	///Internal implementation of unmap() and unmap_from_factory()
	fn unmap_base(&mut self, address: usize, bytes: usize, factory: bool) -> Result<(), VSpaceError> {
		//info!("VRegionFactory::unmap_base: {:x}", address);
		let kobj_alloc = get_kobj_alloc();
		let mut cursor = self.mappings.lower_bound_mut(Bound::Included(&address));
		let end = address + bytes;
		let mut bytes_remaining = bytes;
		while let Some(region) = cursor.get() {
			if region.vaddr + region.bytes < address {
				cursor.move_next();
				continue;
			}
			if region.vaddr > end {
				break;
			}
			let mut region_end = region.vaddr + region.bytes;
			if region_end > end {
				region_end = end;
			}
			//info!("bytes_remaining: {}", bytes_remaining);
			//info!("region.vaddr: {:x}", region.vaddr);
			//info!("address: {:x}", address);
			//info!("region_end: {:x}", region_end);
			//info!("region.end - region.vaddr: {}", region_end - region.vaddr);
			bytes_remaining -= region_end - region.vaddr;
			let start = if region.vaddr < address {
				address
			}else{
				region.vaddr
			};

			let unmap_size = region_end - start;
			let contents = self.contents.lock();
			match contents.unmap(start, unmap_size, PageDeallocType::FreeSlotOnly, &kobj_alloc) {
				Ok(unmapped_pages) => {
					let region_pages = region.pages_mapped.fetch_sub(unmapped_pages, Ordering::Relaxed);
					//info!("region_pages: {}", region_pages);
					//info!("unmapped_pages: {}", unmapped_pages);
					if region_pages - unmapped_pages == 0 {
						//remove the reservation if no
						//more pages are present
						if let Err(err) = contents.unreserve_at_vaddr(region.vaddr, &kobj_alloc) {
							return Err(err);
						}
						if !factory {
							if let Some(f) = region.factory.upgrade() {
								f.lock().del_region(region.vspace_id, region.vaddr);
							}
						}
						cursor.remove();
						//info!("unmapping region");
					}else{
						cursor.move_next();
					}
				},
				Err((_, err)) => {
					return Err(err);
				},
			}
		}
		Ok(())
	}
	///Sets the secondary buffer array for this VSpace (but doesn't map 
	///it; it already should have been mapped before calling this)
	pub fn set_secondary_buffers(&mut self, buffers: UserSecondaryBufferArray) {
		if self.secondary_buffers.is_some(){
			panic!("VSpace::set_secondary_buffers: secondary buffers already set (this should never happen!)");
		}
		self.secondary_buffers = Some(buffers);
	}
	///Gets the secondary buffer array of this VSpace
	pub fn get_secondary_buffers(&self) -> &UserSecondaryBufferArray {
		if let Some(ref buffers) = self.secondary_buffers {
			buffers
		}else{
			panic!("VSpace::get_secondary_buffers: secondary buffers unset (this should never happen!)");
		}
	}
}

impl GlobalIDAllocator for VSpaceList {
	fn has_id(&self, id: i32) -> bool {
		!self.contents.read().find(&id).is_null()
	}
	fn get_next_id(&self) -> i32 {
		self.next_id.load(Ordering::SeqCst)
	}
	fn increment_id(&self) -> i32 {
		self.next_id.fetch_add(1, Ordering::SeqCst)
	}
}

intrusive_adapter!(VSpaceAdapter = UnsafeRef<VSpaceListWrapper>: VSpaceListWrapper { link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for VSpaceAdapter {
	type Key = i32;
	fn get_key(&self, wrapper: &'a VSpaceListWrapper) -> i32 {
		wrapper.vspace.id
	}
}

///The list of all VSpaces in the system.
pub struct VSpaceList {
	next_id: AtomicI32,
	contents: RwLock<RBTree<VSpaceAdapter>>,
}

impl VSpaceList {
	///Creates a new VSpaceList
	fn new() -> VSpaceList {
		VSpaceList {
			next_id: AtomicI32::new(0),
			contents: Default::default(),
		}
	}

	///Adds a VSpace to the list
	fn add(&self, mut vspace: VSpace) -> Result<i32, ()> {
		let id = self.allocate_id()?;
		let mut contents = self.contents.write();

		vspace.id = id;
		contents.insert(VSpaceContainer::new(id, vspace));
		Ok(id)
	}
	///Gets a VSpace from the list
	pub fn get(&self, id: i32) -> Option<Arc<VSpaceContainer>> {
		let contents = self.contents.read();
		if let Some(wrapper) = contents.find(&id).get(){
			//XXX: make sure that the reference count is actually getting incremented here!
			Some(wrapper.vspace.clone())
		}else{
			None
		}
	}
	///Removes a VSpace from the list
	pub fn remove(&self, id: i32) -> Result<(), ()> {
		let mut contents = self.contents.write();
		let mut cursor = contents.find_mut(&id);
		if cursor.is_null(){
			Err(())
		}else{
			let wrapper = cursor.remove().unwrap();
			unsafe { drop(UnsafeRef::into_box(wrapper)) };
			Ok(())
		}
	}
}

static mut ROOT_VSPACE: Option<Arc<VSpaceContainer>> = None;
static mut VSPACE_LIST: Option<VSpaceList> = None;

///Gets the VSpace list
pub fn get_vspace_list() -> &'static VSpaceList {
	unsafe { VSPACE_LIST.as_ref().expect("VSpace list unset") }
}

///Gets the root VSpace
pub fn get_root_vspace() -> Arc<VSpaceContainer> {
	unsafe { ROOT_VSPACE.as_ref().expect("root VSpace unset").clone() }
}

const ROOT_SECONDARY_BUFFERS: usize = 65536;
const ROOT_VSPACE_ID: i32 = 0;

///Initializes VSpace management
pub fn init_vspaces(){
	unsafe { VSPACE_LIST = Some(VSpaceList::new()) };
	info!("creating root VSpace");
	let root_vspace = VSpace::new_root();
	info!("adding root VSpace to list");
	let vspace_list = get_vspace_list();
	vspace_list.add(root_vspace).expect("could not add root VSpace to list");

	info!("creating root secondary buffer array");
	unsafe { ROOT_VSPACE = Some(vspace_list.get(ROOT_VSPACE_ID).expect("could not get root VSpace")) };
	let secondary_buffers = UserSecondaryBufferArray::new_root(ROOT_SECONDARY_BUFFERS);
	info!("setting root secondary buffer array");
	let tmp = get_root_vspace();
	let mut root_vspace_guard = tmp.write();
	root_vspace_guard.set_secondary_buffers(secondary_buffers);
	info!("root secondary buffers: {:p}", root_vspace_guard.get_secondary_buffers());
}

///Adds slabs for VSpace-related structs
pub fn add_custom_slabs(){
	add_arc_slab!(Mutex<VRegionFactory>, 512, 4, 4, 2).expect("could not add custom slab for VRegionFactory");
	add_arc_slab!(VRegion, 512, 4, 4, 2).expect("could not add custom slab for VRegion");
	add_arc_slab!(VSpaceContainer, 512, 4, 4, 2).expect("could not add custom slab for VSpaceContainer");
	add_slab::<VSpaceListWrapper>(512, 4, 4, 2).expect("could not add custom slab for VSpaceListWrapper");
}

/* vim: set softtabstop=8 tabstop=8 noexpandtab: */
