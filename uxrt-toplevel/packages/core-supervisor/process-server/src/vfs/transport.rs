/*
 * Copyright (c) 2022-2023 Andrew Warkentin
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2 or (at your option) any later
 * version. Note that NO WARRANTY is provided. See "LICENSE-GPLv2" for
 * details.
 *
 * This includes FDSpace support and glue code for the transport layer
 */

use core::sync::atomic::{
	AtomicBool,
	AtomicI32,
	AtomicU64,
	AtomicUsize,
	Ordering,
};

use core::mem::size_of;

use alloc::{
	boxed::Box,
	collections::BTreeMap,
	sync::Arc,
	vec::Vec,
};

use bitmap::Treemap;

use sel4::{
	Badge,
	CNode,
	CNodeInfo,
	CapRights,
	Endpoint,
	FromCap,
	FromSlot,
	Notification,
	PAGE_BITS,
	PAGE_SIZE,
	Reply,
	SlotRef,
	ToCap,
	Window,
	null_slot,
	seL4_CPtr,
};

use sel4_alloc::AllocatorBundle;
use sel4_alloc::cspace::{
	AllocatableSlotRef,
	CSpaceError,
	CSpaceManager,
	DynamicBitmapAllocator,
};

use sel4_alloc::utspace::UtZone;
use sel4_alloc::vspace::{
	VSpaceError,
	VSpaceManager,
	VSpaceReservation,
};

use sel4_thread::WrappedThread;

use intrusive_collections::{
	Bound,
	KeyAdapter,
	RBTree,
	RBTreeAtomicLink,
	UnsafeRef
};

use crate::vm::vspace::{
	MemRights,
	SharedArc,
	VRegionFactory,
	VSpace,
	VSpaceContainer,
	get_root_vspace,
};

use crate::global_heap_alloc::{
	AllocatorBundleGuard,
	get_kobj_alloc,
};
use crate::utils::GlobalIDAllocator;
use crate::job::get_job_tree;
use crate::job::thread_pool::{
	ThreadPoolHandle,
	get_helper_pool,
};

use crate::job::thread::ThreadHandle;
use crate::job::process::ROOT_PID;
use crate::add_arc_slab;
use crate::utils::add_slab;

use usync::{
	MutexGuard,
	Mutex,
	RwLock,
};

use custom_slab_allocator::CustomSlabAllocator;

use uxrt_transport_layer::{
	AccessMode,
	ClientFileDescriptorState,
	ClunkFileDescriptor,
	FD_ALIGN,
	FDArray,
	FileDescriptor,
	FileDescriptorRef,
	IOError,
	MsgStatus,
	MsgType,
	NotificationFileDescriptorState,
	OffsetType,
	TransferMode,
	SECONDARY_BUFFER_ALIGN,
	SecondaryBufferInfo,
	ServerFileDescriptorState,
	UnifiedFileDescriptor,
	UnsafeArray,
	set_fd_array,
	set_secondary_buffers,
};

use super::VFSError;

static mut CLIENT_CLUNK_ENDPOINT: Option<SlotRef> = None;


///Gets the client-side clunk endpoint (which replaces closed endpoints for server FDs)
fn get_client_clunk_endpoint() -> SlotRef {
	unsafe { CLIENT_CLUNK_ENDPOINT.expect("client clunk endpoint unset") }
}

static mut SERVER_CLUNK_ENDPOINT: Option<SlotRef> = None;

///Gets the server-side clunk endpoint (which replaces closed endpoints for client FDs)
fn get_server_clunk_endpoint() -> SlotRef {
	unsafe { SERVER_CLUNK_ENDPOINT.expect("server clunk endpoint unset") }
}

///Creates and starts the client- and server-side clunk threads
///
///These threads wait for incoming messages and send clunk replies to them in
///order to unblock threads blocking on FDs that get closed.
pub fn init_clunk_threads() {
	let kobj_alloc = get_kobj_alloc();
	let client_endpoint = kobj_alloc.cspace().allocate_slot_with_object_ref_fixed::<Endpoint, _>(&kobj_alloc).expect("could not create synchronous client clunk thread");
	unsafe { CLIENT_CLUNK_ENDPOINT = Some(client_endpoint) };

	let client_thread = get_job_tree().new_root_helper_thread().expect("could not create synchronous client clunk thread");
	let mut client_guard = client_thread.write();
	client_guard.set_name("sync_clunk_client");
	client_guard.run(move || {
		let fd = ClunkFileDescriptor::new_client(Endpoint::from_slot(client_endpoint), TransferMode::Synchronous);
		loop{
			let _ = fd.clunk();
		}
	}).expect("failed to start clunk client thread");

	let server_endpoint = kobj_alloc.cspace().allocate_slot_with_object_ref_fixed::<Endpoint, _>(&kobj_alloc).expect("could not create synchronous server clunk thread");
	let reply = kobj_alloc.cspace().allocate_slot_with_object_fixed::<Reply, _>(&kobj_alloc).expect("could not create synchronous server clunk endpoint");
	unsafe { SERVER_CLUNK_ENDPOINT = Some(server_endpoint) };

	let server_thread = get_job_tree().new_root_helper_thread().expect("could not create synchronous server clunk thread");
	let mut server_guard = server_thread.write();
	server_guard.set_name("sync_clunk_server");
	server_guard.run(move || {
		let fd = ClunkFileDescriptor::new_server(Endpoint::from_slot(server_endpoint), reply, TransferMode::Synchronous);
		loop{
			let _ = fd.clunk();
		}
	}).expect("failed to start client clunk thread");
}

//TODO: map a dummy page (one per VSpace) into the area where the buffer was when a secondary buffer is deallocated (this could probably be done in a page fault handler)

///State and parameters specific to client FDs
#[derive(Clone)]
struct ClientParams {
	state: SharedArc<ClientFileDescriptorState>,
}

///State and parameters specific to server FDs
#[derive(Clone)]
struct ServerParams {
	state: SharedArc<ServerFileDescriptorState>,
}

///State and parameters specific to client FDs
#[derive(Clone)]
struct NotificationParams {
	state: SharedArc<NotificationFileDescriptorState>,
}

///State shared between a group of interconnected file descriptors. May 
///contain any number of clients and servers.
struct FDGroup {
	base_type: FDType,
	secondary_size: usize,
	combine_reply: bool,
	base_endpoint: SlotRef,
	base_reply: SlotRef,
	base_notification: SlotRef,
	num_clients: AtomicUsize,
	num_servers: AtomicUsize,
	client_fds: Mutex<RBTree<StateAdapter>>,
	server_fds: Mutex<RBTree<StateAdapter>>,
	vspaces: Mutex<RBTree<FDVSpaceAdapter>>,
	access: AccessMode,
	transfer: TransferMode,
	shared_client_state: Option<SharedArc<ClientFileDescriptorState>>,
	shared_server_state: Option<SharedArc<ServerFileDescriptorState>>,
	shared_notification_state: Option<SharedArc<NotificationFileDescriptorState>>,
}

impl FDGroup {
	///Gets the base reply object for this FDGroup (which is used directly
	///for root server threads, and copied for user threads)
	fn get_base_reply(&self) -> Reply {
		Reply::from_slot(self.base_reply)
	}

	///Internal implementation of close|remove)_thread_(client|server)
	fn drop_thread(&self, tree: &Mutex<RBTree<StateAdapter>>, id: u128, endpoint: Option<SlotRef>) -> Result<(), VFSError> {
		let mut tmp = tree.lock();
		let mut cursor = tmp.find_mut(&id);
		if cursor.is_null() {
			return Ok(());
		}
		let fd = cursor.remove().unwrap();
		if let Some(reply) = fd.local_reply {
			let kobj_alloc = get_kobj_alloc();
			//TODO: handle non-root CSpaces here
			kobj_alloc.cspace().free_and_delete_slot_with_object_ref_fixed::<Reply, _>(reply, &kobj_alloc).expect("failed to free thread-local reply");
		}
		drop(cursor);
		drop(tmp);

		match self.base_type {
			FDType::IPCChannel => {
				if let Some(endpoint_slot) = endpoint {
					fd.close_local(endpoint_slot)?;
				}
			},
			FDType::Notification => {
			},
		}
		let vspace = fd.thread.get_vspace();
		self.remove_vspace(vspace)?;
		self.remove_buffer(&fd.secondary_buffer)?;
		Ok(())
	}
	///Drops a client thread from the list and replaces its endpoint with
	///the server clunk endpoint. Called when removing an `FDFactory` from
	///an FDSpace.
	fn close_thread_client(&self, id: u128) -> Result<(), VFSError> {
		self.drop_thread(&self.client_fds, id, Some(get_client_clunk_endpoint()))
	}
	///Drops a client thread from the list without replacing it. Called 
	///when removing a thread from an FDSpace.
	fn remove_thread_client(&self, id: u128) -> Result<(), VFSError> {
		self.drop_thread(&self.client_fds, id, None)
	}
	///Drops a server thread from the list and replaces its endpoint with
	///the client clunk endpoint. Called when removing an `FDFactory` from
	///an FDSpace.
	fn close_thread_server(&self, id: u128) -> Result<(), VFSError> {
		self.drop_thread(&self.server_fds, id, Some(get_server_clunk_endpoint()))
	}
	///Drops a server thread from the list without replacing it. Called 
	///when removing a thread from an FDSpace.
	fn remove_thread_server(&self, id: u128) -> Result<(), VFSError> {
		self.drop_thread(&self.server_fds, id, None)
	}
	///Adds a secondary buffer to this `FDGroup`
	fn add_buffer(&self, secondary: &Option<SecondaryBufferInternal>, vspace_id: i32) -> Result<usize, VFSError> {
		let mut buffer_addr = 0;
		if let Some(ref buffer) = secondary {
			let vspaces = self.vspaces.lock();
			let mut cursor = vspaces.front();
			while !cursor.is_null(){
				let vspace = cursor.get().unwrap();
				match buffer.map(vspace.contents.clone()) {
					Ok(addr) => {
						if vspace.contents.get_id() == vspace_id {
							buffer_addr = addr;
						}
					},
					Err(err) => { return Err(VFSError::VSpaceError(err)); },
				}
				cursor.move_next();
			}
		};
		Ok(buffer_addr)
	}
	///Removes a secondary buffer from this FDGroup
	fn remove_buffer(&self, secondary: &Option<SecondaryBufferInternal>) -> Result<(), VFSError> {
		if let Some(ref buffer) = secondary {
			let vspaces = self.vspaces.lock();
			let mut cursor = vspaces.front();
			while !cursor.is_null(){
				let vspace = cursor.get().unwrap();
				if let Err(err) = buffer.unmap(vspace.contents.clone()) {
					return Err(VFSError::VSpaceError(err));
				}
				cursor.move_next();
			}
		}
		Ok(())
	}
	///Adds a VSpace to this FDGroup if it isn't already in the list
	fn add_vspace(&self, vspace: Arc<VSpaceContainer>, params: &FDFactoryParams) -> Result<Option<usize>, VFSError> {
		let mut vspaces = self.vspaces.lock();
		let client_state = if let Some(ref state) = self.shared_client_state {
			match vspace.write().map(SharedArc::to_region(&state), None, None){
				Ok(addr) => Some(addr),
				Err(err) => return Err(VFSError::VSpaceError(err)),
			}
		}else{
			None
		};

		let server_state = if let Some(ref state) = self.shared_server_state {
			match vspace.write().map(SharedArc::to_region(&state), None, None){
				Ok(addr) => Some(addr),
				Err(err) => return Err(VFSError::VSpaceError(err)),
			}
		}else if let Some(ref state) = self.shared_notification_state {
			match vspace.write().map(SharedArc::to_region(&state), None, None){
				Ok(addr) => Some(addr),
				Err(err) => return Err(VFSError::VSpaceError(err)),
			}
		}else{
			None
		};


		if let Some(existing_vspace) = vspaces.find(&vspace.get_id()).get(){
			existing_vspace.inc_fds();
			return Ok(existing_vspace.get_state_addr(params));
		}
		let fd_vspace = FDVSpace::new(vspace, client_state, server_state);
		vspaces.insert(fd_vspace.clone());
		let mut client_fds = self.client_fds.lock();
		let mut cursor = client_fds.front_mut();
		while !cursor.is_null(){
			let client_state = cursor.get().unwrap();
			if let Some(ref buffer) = client_state.secondary_buffer {
				buffer.map(fd_vspace.contents.clone()).expect("FDGroup::add_vspace: could not map secondary buffer");
			}
			cursor.move_next();
		}
		Ok(fd_vspace.get_state_addr(params))
	}
	///Removes a VSpace from this `FDGroup`
	fn remove_vspace(&self, vspace: Arc<VSpaceContainer>) -> Result<(), VFSError> {
		let mut vspaces = self.vspaces.lock();
		let mut vspace_cursor = vspaces.find_mut(&vspace.get_id());
		if vspace_cursor.is_null(){
			warn!("attempted to remove VSpace with ID {} from FDGroup {:p}, but it was not found", vspace.get_id(), self);
			return Err(VFSError::InternalError);
		}

		let existing_vspace = vspace_cursor.get().unwrap();
		if existing_vspace.dec_fds() > 0 {
			return Ok(())
		}
		let mut res = Ok(());
		let mut client_fds = self.client_fds.lock();
		let mut thread_cursor = client_fds.front_mut();
		while !thread_cursor.is_null(){
			let client_state = thread_cursor.get().unwrap();
			if let Some(ref buffer) = client_state.secondary_buffer {
				if let Err(err) = buffer.unmap(existing_vspace.contents.clone()) {
					res = Err(VFSError::VSpaceError(err));
				}
			}
			thread_cursor.move_next();
		}
		vspace_cursor.remove();
		res
	}
}

impl Drop for FDGroup {
	fn drop(&mut self) {
		//info!("FDGroup::drop");
		let kobj_alloc = get_kobj_alloc();
		if self.base_endpoint.cptr != 0 {
			kobj_alloc.cspace().free_and_delete_slot_with_object_fixed(&Endpoint::from_slot(self.base_endpoint), &kobj_alloc).expect("failed to free endpoint for FD");
		}
		if self.base_reply.cptr != 0 {
			kobj_alloc.cspace().free_and_delete_slot_with_object_fixed(&Reply::from_slot(self.base_reply), &kobj_alloc).expect("failed to free endpoint for FD");
		}
		if self.base_notification.cptr != 0 {
			kobj_alloc.cspace().free_and_delete_slot_with_object_fixed(&Notification::from_slot(self.base_notification), &kobj_alloc).expect("failed to free notification for FD");
		}
	}
}

///Holds client/server-specific FD state/parameters
#[derive(Clone)]
enum FDFactoryParams {
	ThreadLocalClient,
	ThreadLocalServer,
	SharedClient(ClientParams),
	SharedServer(ServerParams),
	NotificationClient(NotificationParams),
	NotificationServer(NotificationParams),
}

impl FDFactoryParams {
	fn get_notification_state(&self) -> Option<SharedArc<NotificationFileDescriptorState>> {
		match self {
			FDFactoryParams::NotificationClient(params) => Some(params.state.clone()),
			FDFactoryParams::NotificationServer(params) => Some(params.state.clone()),
			_ => None,
		}
	}
	fn allocate_client_state(&self, vspace: &Arc<VSpaceContainer>) -> Result<(SharedArc<ClientFileDescriptorState>, Option<usize>), VSpaceError> {
		match self {
			FDFactoryParams::ThreadLocalClient => {
				let state = SharedArc::new(ClientFileDescriptorState::new());
				//info!("allocate_client_state: local");
				match vspace.write().map(SharedArc::to_region(&state), None, None) {
					Ok(addr) => {
						Ok((state, Some(addr)))
					},
					Err(err) => Err(err),
				}
			}
			FDFactoryParams::SharedClient(ref params) => {
				//info!("allocate_client_state: shared");
				Ok((params.state.clone(), None))
			}
			_ => Err(VSpaceError::InternalError),
		}
	}
	fn allocate_server_state(&self, vspace: &Arc<VSpaceContainer>) -> Result<(SharedArc<ServerFileDescriptorState>, Option<usize>), VSpaceError> {
		match self {
			FDFactoryParams::ThreadLocalServer => {
				let state = SharedArc::new(ServerFileDescriptorState::new());
				//info!("allocate_server_state: local");
				match vspace.write().map(SharedArc::to_region(&state), None, None) {
					Ok(addr) => {
						Ok((state, Some(addr)))
					},
					Err(err) => Err(err),
				}
			}
			FDFactoryParams::SharedServer(ref params) => {
				//info!("allocate_server_state: shared");
				Ok((params.state.clone(), None))
			}
			_ => Err(VSpaceError::InternalError),
		}
	}
}

///Gets the global ID for an `FDFactory` given an FDSpace ID and an FD ID
#[inline]
fn get_global_fd_factory_id(fdspace_id: u64, fd_id: u64) -> u64 {
	((fdspace_id << 32) | fd_id) as u64
}

///Gets the global ID for a thread FD given an FDSpace ID, an FD ID, and a 
///GTID
#[inline]
fn get_global_thread_fd_id(fdspace_id: u64, fd_id: u64, gtid: u64) -> u128 {
	((gtid as u128) << 64) | get_global_fd_factory_id(fdspace_id, fd_id) as u128
}

#[derive(Debug)]
pub enum FDType {
	IPCChannel,
	Notification,
}

//TODO: add the option to make an individual file descriptor not share state other than endpoint/reply and reference counts between its ThreadFDs

///A file descriptor factory, which constructs ThreadFDs
pub struct FDFactory {
	fdspace_id: AtomicI32,
	fd_id: AtomicI32,
	fd_group: Arc<FDGroup>,
	type_params: FDFactoryParams,
	fdspace_link: RBTreeAtomicLink,
	cspace: FactoryCSpace,
}

impl FDFactory {
	///Creates a new pair of `FDFactory` objects, one for the client and
	///one for the server.
	pub fn new(base_type: FDType, access: AccessMode, transfer: TransferMode, combine_reply: bool, secondary_size: usize, client_cspace: FactoryCSpace, server_cspace: FactoryCSpace, shared_client: bool, shared_server: bool) -> Result<(FDFactory, FDFactory), VFSError> {
		//info!("FDFactory::new: secondary_size: {}", secondary_size);
		let kobj_alloc = get_kobj_alloc();
		let (base_endpoint, base_reply, base_notification, client_params, server_params, shared_client_state, shared_server_state, shared_notification_state) = match base_type {
			FDType::IPCChannel => {
				let (endpoint, reply, notification) = match transfer {
					TransferMode::Synchronous => {
						let endpoint = match kobj_alloc.cspace().allocate_slot_with_object_ref_fixed::<Endpoint, _>(&kobj_alloc) {
							Ok(e) => e,
							Err(err) => { return Err(VFSError::CSpaceError(err)); },
						};
						let reply = match kobj_alloc.cspace().allocate_slot_with_object_ref_fixed::<Reply, _>(&kobj_alloc) {
							Ok(r) => r,
							Err(err) => { return Err(VFSError::CSpaceError(err)); },
						};
						let notification = null_slot();
						(endpoint, reply, notification)
					},
					TransferMode::AsyncMPMC => {
						panic!("TODO: implement support for async FDs");
					},
				};

				let (client_state, client_params) = if shared_client {

					let state = SharedArc::new(ClientFileDescriptorState::new());
					let params = FDFactoryParams::SharedClient(ClientParams {
						state: state.clone(),
					});
					(Some(state), params)
				}else{
					(None, FDFactoryParams::ThreadLocalClient)
				};

				let (server_state, server_params) = if shared_server {

					let state = SharedArc::new(ServerFileDescriptorState::new());
					let params = FDFactoryParams::SharedServer(ServerParams {
						state: state.clone(),
					});
					(Some(state), params)
				}else{
					(None, FDFactoryParams::ThreadLocalServer)
				};
				(endpoint, reply, notification, client_params, server_params, client_state, server_state, None)
			},
			FDType::Notification => {
				if transfer != TransferMode::AsyncMPMC {
					return Err(VFSError::InternalError);
				}
				let endpoint = null_slot();
				let reply = null_slot();
				let notification = match kobj_alloc.cspace().allocate_slot_with_object_ref_fixed::<Notification, _>(&kobj_alloc) {
					Ok(n) => n,
					Err(err) => { return Err(VFSError::CSpaceError(err)); },
				};
				let state = SharedArc::new(NotificationFileDescriptorState::new());

				let client_params = FDFactoryParams::NotificationClient(NotificationParams {
					state: state.clone(),
				});

				let server_params = FDFactoryParams::NotificationServer(NotificationParams {
					state: state.clone(),
				});
				(endpoint, reply, notification, client_params, server_params, None, None, Some(state))

			},
		};
		let fd_group = Arc::new(FDGroup {
			base_type,
			secondary_size,
			combine_reply,
			base_endpoint,
			base_reply,
			base_notification,
			num_clients: AtomicUsize::new(1),
			num_servers: AtomicUsize::new(1),
			client_fds: Default::default(),
			server_fds: Default::default(),
			vspaces: Default::default(),
			access,
			transfer,
			shared_client_state,
			shared_server_state,
			shared_notification_state,
		});

		let client = FDFactory {
			fdspace_id: AtomicI32::new(i32::MIN),
			fd_id: AtomicI32::new(i32::MIN),
			fd_group,
			type_params: client_params,
			fdspace_link: Default::default(),
			cspace: client_cspace,
		};

		let server = FDFactory {
			fdspace_id: AtomicI32::new(i32::MIN),
			fd_id: AtomicI32::new(i32::MIN),
			fd_group: client.fd_group.clone(),
			type_params: server_params,
			fdspace_link: Default::default(),
			cspace: server_cspace,
		};
		Ok((server, client))
	}
	///Called when this is added to an FDSpace.
	fn added(&self, fdspace_id: i32, fd_id: i32){
		self.fdspace_id.store(fdspace_id, Ordering::Relaxed);
		self.fd_id.store(fd_id, Ordering::Relaxed);
	}
	///Gets the ID of this factory
	fn get_id(&self) -> i32 {
		self.fd_id.load(Ordering::Relaxed)
	}
	///Gets this factory's associated thread FD ID for a GTID
	fn get_thread_id(&self, gtid: u64) -> u128 {
		let fdspace_id = self.fdspace_id.load(Ordering::Relaxed) as u64;
		let fd_id = self.fd_id.load(Ordering::Relaxed) as u64;
		get_global_thread_fd_id(fdspace_id, fd_id, gtid)
	}
	///Creates a new client thread FD. Should not be used directly; use
	///new_thread() instead
	fn new_thread_client(&self, thread: ThreadHandle, params: &FDFactoryParams) -> Result<UnifiedFileDescriptor, VFSError> {
		//info!("FDFactory::new_thread_client");
		let kobj_alloc = get_kobj_alloc();
		let cspace = self.cspace.lock();

		let (secondary_buffer, secondary_offset) = if self.fd_group.secondary_size == 0 {
			(None, 0)
		}else{
			if let Ok(offset) = get_secondary_allocator().allocate() {
				match SecondaryBufferInternal::new(offset, self.fd_group.secondary_size) {
					Ok(buf) => (Some(buf), offset),
					Err(err) => { return Err(VFSError::VSpaceError(err)); },
				}
			}else{
				return Err(VFSError::TooManyFiles);
			}
		};
		let endpoint = match self.fd_group.base_endpoint
			.mint_to_new(&cspace, CapRights::all(), Badge::new(secondary_offset), &kobj_alloc) {
			Ok(slot) => slot,
			Err(err) => {
				warn!("FDFactory::new_thread_client: could not copy endpoint: {:?}", err);
				return Err(VFSError::CSpaceError(err));
			},
		};

		let vspace = thread.get_vspace();
		let vspace_id = vspace.get_id();
		let shared_state_addr = self.fd_group.add_vspace(vspace.clone(), params).expect("TODO?: recover from VSpace add failure");

		let (state, local_state_addr) = match params.allocate_client_state(&vspace) {
			Ok((s, a)) => {
				(s, a)
			},
			Err(err) => {
				error!("non-client FD passed to new_thread_client (this should never happen!)");
				return Err(VFSError::VSpaceError(err));
			},
		};

		let state_addr = if let Some(a) = shared_state_addr {
			a
		}else{
			if let Some(a) = local_state_addr {
				a
			}else{
				error!("client FD has neither shared nor local state (this should never happen!)");
				return Err(VFSError::InternalError);
			}
		};
		let state_ref = unsafe { UnsafeRef::from_raw(state_addr as *const ClientFileDescriptorState) };

		let secondary_buffer_addr = self.fd_group.add_buffer(&secondary_buffer, vspace_id)?;

		let internal_fd = ThreadFDInternal::new(FDType::IPCChannel, 
						self.fdspace_id.load(Ordering::Relaxed), 
						self.fdspace_id.load(Ordering::Relaxed),
						Some((endpoint, endpoint.cptr)), 
						None,
						ThreadFDSharedState::Client(state),
						thread.clone(), 
						secondary_buffer);
		self.fd_group.client_fds.lock().insert(internal_fd);
		Ok(UnifiedFileDescriptor::new_client(self.fd_id.load(Ordering::Relaxed), Endpoint::from_slot(endpoint), self.fd_group.access, self.fd_group.transfer, secondary_buffer_addr, self.fd_group.secondary_size, state_ref))
	}
	///Creates a new client thread FD. Should not be used directly; use
	///new_thread() instead
	fn new_thread_server(&self, thread: ThreadHandle, params: &FDFactoryParams) -> Result<UnifiedFileDescriptor, VFSError> {
		//TODO: there should be an API that allows borrowing another 
		//thread's state and reply; there should be three functions; 
		//one that returns an opaque ID; one that takes the ID, 
		//switches the active state for the associated FD to that of
		//the thread that saved it, and returns the ID; and one that
		//ends a borrow given an FD; borrowing should prevent the 
		//underlying ThreadFD from being dropped even if the original
		//thread exits (but once the borrow has ended, the state 
		//should be dropped if the original thread exited)
		let kobj_alloc = get_kobj_alloc();
		let cspace = self.cspace.lock();

		let endpoint = match self.fd_group.base_endpoint
			.mint_to_new(&cspace, CapRights::all(), Badge::new(0), &kobj_alloc) {
			Ok(slot) => slot,
			Err(err) => {
				warn!("FDFactory::new_thread_server: could not copy endpoint: {:?}", err);
				return Err(VFSError::CSpaceError(err));
			}
		};
		let vspace = thread.get_vspace();

		let (reply, local_reply) = match params {
			FDFactoryParams::ThreadLocalServer => {
				let r = kobj_alloc.cspace().allocate_slot_with_object_ref_fixed::<Reply, _>(&kobj_alloc).expect("could not create thread-local reply object for server FD");
				(Reply::from_slot(r), Some(r))
			},
			_ => {
				//TODO: copy the reply here to handle non-root
				//CSpaces properly (when freeing the reply,
				//only the slot should be deleted, not the
				//underlying object)
				(self.fd_group.get_base_reply(), None)
			},
		};

		let shared_state_addr = self.fd_group.add_vspace(vspace.clone(), params).expect("TODO?: recover from VSpace add failure");

		let (state, local_state_addr) = match params.allocate_server_state(&vspace) {
			Ok((s, a)) => {
				(s, a)
			},
			Err(err) => {
				error!("non-server FD passed to new_thread_server (this should never happen!)");
				return Err(VFSError::VSpaceError(err));
			},
		};

		let state_addr = if let Some(a) = shared_state_addr {
			a
		}else{
			if let Some(a) = local_state_addr {
				a
			}else{
				error!("server FD has neither shared nor local state (this should never happen!)");
				return Err(VFSError::InternalError);
			}
		};

		//TODO: support user threads
		let internal_fd = ThreadFDInternal::new(
			FDType::IPCChannel, 
			self.fdspace_id.load(Ordering::Relaxed), 
			self.fd_id.load(Ordering::Relaxed), 
			Some((endpoint, endpoint.cptr)),
			local_reply,
			ThreadFDSharedState::Server(state),
			thread.clone(), 
			None);
		self.fd_group.server_fds.lock().insert(internal_fd);

		//info!("FDFactory::new_thread_server");

		/*info!("new_thread_server: {:x}", state_addr.unwrap());*/
		let state_ref = unsafe { UnsafeRef::from_raw(state_addr as *const ServerFileDescriptorState) };

		//info!("FDFactory::new_thread_server {:p}: secondary_size: {}", self, self.fd_group.secondary_size);
		Ok(UnifiedFileDescriptor::new_server(self.get_id(), Endpoint::from_slot(endpoint), reply, self.fd_group.access, self.fd_group.transfer, self.fd_group.combine_reply, self.fd_group.secondary_size, state_ref))
	}
	///Internal method to create a notification FD
	fn new_thread_notification(&self, thread: ThreadHandle, params: &FDFactoryParams) -> Result<(UnifiedFileDescriptor, Arc<ThreadFDInternal>), VFSError> {
		let kobj_alloc = get_kobj_alloc();
		let cspace = self.cspace.lock();

		let notification = match self.fd_group.base_notification
			.mint_to_new(&cspace, CapRights::all(), Badge::new(0), &kobj_alloc) {
			Ok(slot) => slot,
			Err(err) => {
				warn!("FDFactory::new_thread_client: could not copy endpoint: {:?}", err);
				return Err(VFSError::CSpaceError(err));
			},
		};

		let internal_fd = ThreadFDInternal::new(FDType::Notification, 
						self.fdspace_id.load(Ordering::Relaxed), 
						self.fd_id.load(Ordering::Relaxed),
						None,
						None,
						ThreadFDSharedState::Notification(
							Notification::from_slot(self.fd_group.base_notification),
							params.get_notification_state().expect("non-notification parameter type for a notification FD (this should never happen!)")
						),
						thread.clone(), 
						None);
		let state_addr = self.fd_group.add_vspace(thread.get_vspace(), params).expect("TODO?: recover from VSpace add failure");
		let state_ref = unsafe { UnsafeRef::from_raw(state_addr.expect("no virtual address for server FD state") as *const NotificationFileDescriptorState) };
		let thread_fd = UnifiedFileDescriptor::new_notification(self.get_id(), Notification::from_slot(notification), self.fd_group.access, state_ref);

		Ok((thread_fd, internal_fd))


	}
	///Internal method to create a client-side notification FD
	fn new_thread_notification_client(&self, thread: ThreadHandle, params: &FDFactoryParams) -> Result<UnifiedFileDescriptor, VFSError> {
		let (thread_fd, internal_fd) = self.new_thread_notification(thread, params)?;
		//info!("new_thread_notification_client: adding FD");
		self.fd_group.client_fds.lock().insert(internal_fd);
		Ok(thread_fd)
	}
	///Internal method to create a server-side notification FD
	fn new_thread_notification_server(&self, thread: ThreadHandle, params: &FDFactoryParams) -> Result<UnifiedFileDescriptor, VFSError> {
		let (thread_fd, internal_fd) = self.new_thread_notification(thread, params)?;
		self.fd_group.server_fds.lock().insert(internal_fd);
		Ok(thread_fd)
	}
	///Creates a new thread FD (the type is determined by the type of the
	///factory)
	pub fn new_thread(&self, thread: ThreadHandle) -> Result<UnifiedFileDescriptor, VFSError>{
		match self.type_params {
			FDFactoryParams::ThreadLocalClient => {
				self.new_thread_client(thread, &self.type_params)
			},
			FDFactoryParams::ThreadLocalServer => {

				self.new_thread_server(thread, &self.type_params)
			},
			FDFactoryParams::SharedClient(_) => {
				self.new_thread_client(thread, &self.type_params)
			},
			FDFactoryParams::SharedServer(_) => {

				self.new_thread_server(thread, &self.type_params)
			},
			FDFactoryParams::NotificationClient(_) => {


				self.new_thread_notification_client(thread, &self.type_params)
			}
			FDFactoryParams::NotificationServer(_) => {

				self.new_thread_notification_server(thread, &self.type_params)
			}
		}
	}
	///Removes a client thread from the list. Should not be called 
	///directly; remove_thread should be used instead,
	fn remove_thread_client(&self, thread: ThreadHandle) -> Result<(), VFSError> {
		self.fd_group.remove_thread_client(self.get_thread_id(thread.get_gtid()))
	}
	///Removes a server thread from the list. Should not be called 
	///directly; remove_thread should be used instead,
	fn remove_thread_server(&self, thread: ThreadHandle) -> Result<(), VFSError> {
		self.fd_group.remove_thread_server(self.get_thread_id(thread.get_gtid()))
	}
	///Removes a thread from the list without replacing the endpoint
	fn remove_thread(&self, thread: ThreadHandle) -> Result<(), VFSError>{
		match self.type_params {
			FDFactoryParams::ThreadLocalClient => {
				self.remove_thread_client(thread)
			},
			FDFactoryParams::ThreadLocalServer => {
				self.remove_thread_server(thread)
			},
			FDFactoryParams::SharedClient(_) => {
				self.remove_thread_client(thread)
			},
			FDFactoryParams::SharedServer(_) => {
				self.remove_thread_server(thread)
			},
			FDFactoryParams::NotificationClient(_) => {
				self.remove_thread_client(thread)
			},
			FDFactoryParams::NotificationServer(_) => {
				self.remove_thread_server(thread)
			},
		}
	}
	///Removes a thread from the list, replacing the endpoint with the 
	///clunk endpoint
	fn close_thread(&self, thread: ThreadHandle) -> Result<(), VFSError>{
		//info!("FDFactory::close_thread");
		match self.type_params {
			FDFactoryParams::ThreadLocalClient => {
				self.fd_group.close_thread_client(self.get_thread_id(thread.get_gtid()))
			},
			FDFactoryParams::ThreadLocalServer => {
				self.fd_group.close_thread_server(self.get_thread_id(thread.get_gtid()))
			},
			FDFactoryParams::SharedClient(_) => {
				self.fd_group.close_thread_client(self.get_thread_id(thread.get_gtid()))
			},
			FDFactoryParams::SharedServer(_) => {
				self.fd_group.close_thread_server(self.get_thread_id(thread.get_gtid()))
			},
			FDFactoryParams::NotificationClient(_) => {
				self.fd_group.close_thread_client(self.get_thread_id(thread.get_gtid()))
			},
			FDFactoryParams::NotificationServer(_) => {
				self.fd_group.close_thread_server(self.get_thread_id(thread.get_gtid()))
			}

		}
	}
	fn drop_thread(&self, num_fds: usize, fd_list: &Mutex<RBTree<StateAdapter>>, clunk_endpoint: SlotRef) -> bool {
		//XXX: there was a bug where server-side FDs would get closed
		//in addition to the client-side ones when trying to close
		//the client side (causing the server thread to fault on 
		//access to the shared state; this seems to be no longer 
		//showing up, but may still be around
		if num_fds == 0 {
			//if this was the last on one side, wake up all 
			//threads on the other side if possible and drop the 
			//state
			//info!("FDFactory::drop_thread: getting FD list");
			let mut tmp = fd_list.lock();
			let mut cursor = tmp.front_mut();
			while !cursor.is_null(){
				let fd = cursor.get().unwrap();
				fd.close_remote(clunk_endpoint).expect("failed to close remote file descriptor");
				cursor.move_next();
			}
			//info!("FDFactory::drop_thread: done");
			true

		}else{
			false
		}
	}
}

impl Clone for FDFactory {
	fn clone(&self) -> Self {
		match self.type_params {
			FDFactoryParams::ThreadLocalClient => {
				self.fd_group.num_clients.fetch_add(1, Ordering::Relaxed);
			},
			FDFactoryParams::ThreadLocalServer => {
				self.fd_group.num_servers.fetch_add(1, Ordering::Relaxed);
			},
			FDFactoryParams::SharedClient(_) => {
				self.fd_group.num_clients.fetch_add(1, Ordering::Relaxed);
			},
			FDFactoryParams::SharedServer(_) => {
				self.fd_group.num_servers.fetch_add(1, Ordering::Relaxed);
			},
			FDFactoryParams::NotificationClient(_) => {
				self.fd_group.num_clients.fetch_add(1, Ordering::Relaxed);
			},
			FDFactoryParams::NotificationServer(_) => {
				self.fd_group.num_servers.fetch_add(1, Ordering::Relaxed);
			},
		}
		FDFactory {
			fdspace_id: AtomicI32::new(i32::MIN),
			fd_id: AtomicI32::new(i32::MIN),
			fd_group: self.fd_group.clone(),
			type_params: self.type_params.clone(),
			fdspace_link: Default::default(),
			cspace: self.cspace.clone(),
		}
	}
}

impl Drop for FDFactory {
	fn drop(&mut self) {
		//info!("FDFactory::drop");
		match self.type_params {
			FDFactoryParams::ThreadLocalClient => {
				let clients = self.fd_group.num_clients.fetch_sub(1, Ordering::Relaxed) - 1;
				self.drop_thread(clients, &self.fd_group.server_fds, get_client_clunk_endpoint());
				(clients, self.fd_group.num_servers.load(Ordering::Relaxed))
			},
			FDFactoryParams::ThreadLocalServer => {
				let servers = self.fd_group.num_servers.fetch_sub(1, Ordering::Relaxed) - 1;
				self.drop_thread(servers, &self.fd_group.client_fds, get_server_clunk_endpoint());
				(self.fd_group.num_clients.load(Ordering::Relaxed), servers)
			},
			FDFactoryParams::SharedClient(_) => {
				let clients = self.fd_group.num_clients.fetch_sub(1, Ordering::Relaxed) - 1;
				self.drop_thread(clients, &self.fd_group.server_fds, get_client_clunk_endpoint());
				(clients, self.fd_group.num_servers.load(Ordering::Relaxed))
			},
			FDFactoryParams::SharedServer(_) => {
				let servers = self.fd_group.num_servers.fetch_sub(1, Ordering::Relaxed) - 1;
				self.drop_thread(servers, &self.fd_group.client_fds, get_server_clunk_endpoint());
				(self.fd_group.num_clients.load(Ordering::Relaxed), servers)
			},
			FDFactoryParams::NotificationClient(_) => {
				let clients = self.fd_group.num_clients.fetch_sub(1, Ordering::Relaxed) - 1;
				self.drop_thread(clients, &self.fd_group.server_fds, null_slot());
				(clients, self.fd_group.num_servers.load(Ordering::Relaxed))
			},
			FDFactoryParams::NotificationServer(_) => {
				let servers = self.fd_group.num_servers.fetch_sub(1, Ordering::Relaxed) - 1;
				self.drop_thread(servers, &self.fd_group.client_fds, null_slot());

				(self.fd_group.num_clients.load(Ordering::Relaxed), servers)
			},
		};
	}
}



intrusive_adapter!(FactoryFDSpaceAdapter = Arc<FDFactory>: FDFactory { fdspace_link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for FactoryFDSpaceAdapter {
	type Key = i32;
	fn get_key(&self, fd: &'a FDFactory) -> i32 {
		fd.fd_id.load(Ordering::Relaxed)
	}
}

///A thread's copy of a file descriptor
#[derive(Clone)]
pub struct ThreadFD {
	base_fd: FileDescriptorRef,
}

impl ThreadFD {
	///Wrapper around preadbuf() that parses the message tyoe, size, 
	///offset type, and offset received from a client
	pub fn awaitmsg(&mut self) -> Result<(usize, MsgType, usize, OffsetType), IOError> {
		//info!("awaitmsg");
		let (primary_size, secondary_size) = self.getbufsize();
		//info!("awaitmsg: {} {}", primary_size, secondary_size);
		let res = self.preadbuf(primary_size + secondary_size, 0, OffsetType::Start);
		self.awaitmsg_common(res)
	}

	///Combines pwritebuf() and awaitmsg()
	pub fn pwritebuf_awaitmsg(&mut self, size: usize, offset: isize) -> Result<(usize, MsgType, usize, OffsetType), IOError> {
		let res = self.pwritereadbuf(size, offset, OffsetType::Start);
		self.awaitmsg_common(res)
	}

	///Internal implementation of awaitmsg()
	pub fn awaitmsg_common(&mut self, res: Result<(usize, usize), (usize, usize, IOError)>) -> Result<(usize, MsgType, usize, OffsetType), IOError> {
		match res {
			Ok((size, _)) => {
				let buf = self.getbuf().expect("no buffer for FD");
				let status = MsgStatus::from_buf(&buf);
				if let Some(msgtype) = status.msgtype_enum() && let Some(whence) = status.whence_enum() {
					Ok((size, msgtype, status.offset as usize, whence))
				}else{
					Err(IOError::InvalidMessage)
				}
			},
			Err((_, _, err)) => Err(err),
		}
	}
}

impl FileDescriptor for ThreadFD {
	fn get_base_fd(&self) -> UnsafeRef<UnifiedFileDescriptor> {
		self.base_fd.get_base_fd()
	}
}

///Internal state specific to notification FDs
struct NotificationState {
	base_notification: Notification,
	state: SharedArc<NotificationFileDescriptorState>,
}

enum ThreadFDSharedState {
	Client(SharedArc<ClientFileDescriptorState>),
	Server(SharedArc<ServerFileDescriptorState>),
	Notification(Notification, SharedArc<NotificationFileDescriptorState>),
}

///Internal state for a ThreadFD
struct ThreadFDInternal {
	base_type: FDType,
	fdspace_id: i32,
	fd_id: i32,
	thread: ThreadHandle,
	endpoint: Option<(SlotRef, seL4_CPtr)>,
	local_reply: Option<SlotRef>,
	closed: AtomicBool,
	secondary_buffer: Option<SecondaryBufferInternal>,
	state: ThreadFDSharedState,
	state_link: RBTreeAtomicLink,
}

impl ThreadFDInternal {
	///Creates a new `ThreadFDInternal`
	fn new(base_type: FDType, 
	       fdspace_id: i32, 
	       fd_id: i32, 
	       endpoint: Option<(SlotRef, seL4_CPtr)>,
	       local_reply: Option<SlotRef>,
	       state: ThreadFDSharedState, 
	       thread: ThreadHandle, 
	       secondary_buffer: Option<SecondaryBufferInternal>,
	) -> Arc<ThreadFDInternal> {
		Arc::new(ThreadFDInternal {
			base_type,
			fdspace_id,
			fd_id,
			thread,
			endpoint,
			local_reply,
			state,
			closed: AtomicBool::new(false),
			secondary_buffer,
			state_link: Default::default(),
		})
	}
	///Closes this FD from another thread sharing the same FDSpace
	fn close_local(&self, clunk_endpoint: SlotRef) -> Result<(), VFSError>{
		self.close_base(clunk_endpoint, true)
	}
	///Closes this FD from a thread with a different FDSpace
	fn close_remote(&self, clunk_endpoint: SlotRef) -> Result<(), VFSError>{
		self.close_base(clunk_endpoint, false)
	}
	///Closes a synchronous FD
	fn close_base_endpoint(&self, clunk_endpoint: SlotRef, local: bool) -> Result<(), VFSError>{
		//info!("close_base_endpoint: {}", local);
		if let Some((endpoint, cptr)) = self.endpoint {
			//info!("{} {} {}", self.thread.get_gtid(), self.fd_id, cptr);
			let waiting_endpoint = self.thread.get_waiting_endpoint().expect("tried to get waiting endpoint, but thread is still runnable");
			let clunk = if local  {
				if cptr == waiting_endpoint {
				//TODO: once timeouts are supported, remove this panic and add a thread that periodically checks for threads that were blocking on FDs closed in their own FDSpaces and deallocates the endpoint slots once the threads are no longer blocking on them (make sure to suspend the thread before deallocating the endpoint slot)
					panic!("TODO: implement a thread to clean up in-use endpoints for FDs that are closed locally");
					true
				}else{
					false
				}
			}else{
				true
			};

			if let Err(err) = endpoint.delete() {
				return Err(VFSError::CSpaceError(CSpaceError::SyscallError { details: err}));
				}
			if clunk {
				if let Err(err) = clunk_endpoint.copy(endpoint, CapRights::all()) {
					return Err(VFSError::CSpaceError(CSpaceError::SyscallError { details: err}));
				}
			}else{
				panic!("TODO: deallocate the FD from the appropriate CSpace here");
			}

		}
		Ok(())
	}
	///Closes a notification FD
	fn close_base_notification(&self, local: bool) -> Result<(), VFSError>{
		//info!("close_base_notification: {}", local);
		if !local {
			match self.state {
				ThreadFDSharedState::Notification(notification, ref state) => {
					state.seteof();
					notification.signal();
				},
				_ => {
					error!("attempt to close a notification FD with a non-notification state type (this should never happen!)");
					return Err(VFSError::InternalError);
				}
			}
			//info!("close_base_notification: {:p}", UnsafeRef::as_ref(&notification.state));
		}
		Ok(())
	}
	///Internal implementation of close_remote and close_local
	fn close_base(&self, clunk_endpoint: SlotRef, local: bool) -> Result<(), VFSError>{
		//info!("ThreadFDInternal::close_base: {}", self.fd_id);
		if self.closed.load(Ordering::Relaxed) {
			//info!("already closed");
			return Ok(())
		}
		let runnable = self.thread.suspend_if_other();
		//info!("runnable: {}, endpoint: {:?}", runnable, self.endpoint);
		match self.base_type {
			FDType::IPCChannel => {
				self.close_base_endpoint(clunk_endpoint, local)?;
			},
			FDType::Notification => {
				self.close_base_notification(local)?;
			},
		}
		self.thread.resume_if_other(runnable);
		self.closed.store(true, Ordering::Relaxed);
		Ok(())
	}
	///Gets the global ID of this FD
	fn get_global_id(&self) -> u128 {
		get_global_thread_fd_id(self.fdspace_id as u64, self.fd_id as u64, self.thread.get_gtid())
	}
}

intrusive_adapter!(StateAdapter = Arc<ThreadFDInternal>: ThreadFDInternal { state_link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for StateAdapter {
	type Key = u128;
	fn get_key(&self, fd: &'a ThreadFDInternal) -> u128 {
		fd.get_global_id()
	}
}

///An entry in the list of VSpaces associated with an `FDGroup`
struct FDVSpace {
	contents: Arc<VSpaceContainer>,
	num_fds: AtomicUsize,
	shared_server_state: Option<usize>,
	shared_client_state: Option<usize>,
	link: RBTreeAtomicLink,
}

impl FDVSpace {
	///Creates a new `FDVSpace`
	pub fn new(contents: Arc<VSpaceContainer>, shared_client_state: Option<usize>, shared_server_state: Option<usize>) -> Arc<FDVSpace> {
		Arc::new(FDVSpace {
			contents,
			num_fds: AtomicUsize::new(1),
			shared_client_state,
			shared_server_state,
			link: Default::default(),
		})
	}
	///Increments the number of ThreadFDs associated with this VSpace
	fn inc_fds(&self) {
		self.num_fds.fetch_add(1, Ordering::Relaxed);
	}
	///Decrements the number of ThreadFDs associated with this VSpace
	fn dec_fds(&self) -> usize {
		self.num_fds.fetch_sub(1, Ordering::Relaxed) - 1
	}
	fn get_state_addr(&self, params: &FDFactoryParams) -> Option<usize> {
		match params {
			FDFactoryParams::ThreadLocalClient => None,
			FDFactoryParams::ThreadLocalServer => None,
			FDFactoryParams::SharedClient(_) => Some(self.shared_client_state.expect("no shared client state present for an FD that requires it (this shouldn't happen)")),
			FDFactoryParams::SharedServer(_) => Some(self.shared_server_state.expect("no shared server state present for an FD that requires it (this shouldn't happen)")),
			//there is only one shared state struct for 
			//a notification FD, so the server state field
			//is also used for clients in this case
			FDFactoryParams::NotificationClient(_) => Some(self.shared_server_state.expect("no shared client state present for an FD that requires it (this shouldn't happen)")),
			FDFactoryParams::NotificationServer(_) => Some(self.shared_server_state.expect("no shared server state present for an FD that requires it (this shouldn't happen)")),

		}
	}
}

intrusive_adapter!(FDVSpaceAdapter = Arc<FDVSpace>: FDVSpace { link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for FDVSpaceAdapter {
	type Key = i32;
	fn get_key(&self, vspace: &'a FDVSpace) -> i32 {
		vspace.contents.get_id()
	}
}

///The CSpace associated with a `FactoryFDSpace`
pub enum FactoryCSpace {
	Root,
	User(Arc<Mutex<DynamicBitmapAllocator>>),
}

impl FactoryCSpace {
	///Acquires the mutex to the CSpace, returning a guard
	pub fn lock(&self) -> FactoryCSpaceGuard {
		match self {
			FactoryCSpace::Root => {
				FactoryCSpaceGuard::Root(get_kobj_alloc())
			},
			FactoryCSpace::User(ref cspace) => {
				FactoryCSpaceGuard::User(cspace.lock())
			},
		}
	}
}
impl Clone for FactoryCSpace {
	fn clone(&self) -> Self {
		match self {
			FactoryCSpace::Root => FactoryCSpace::Root,
			FactoryCSpace::User(ref contents) => FactoryCSpace::User(contents.clone()),
		}
	}
}

impl Drop for FactoryCSpace {
	fn drop(&mut self) {
		match self {
			FactoryCSpace::Root => {},
			FactoryCSpace::User(ref contents) => {
				let kobj_alloc = get_kobj_alloc();
				kobj_alloc.cspace().free_and_delete_sublevel(self.lock(), &kobj_alloc).expect("could not free user CSpace");
			},
		}
	}
}

///A guard to a `FactoryCSpace`, which wraps the underlying CSpace allocator
///(the heap CSpace allocator for the root server FDSpace, and a dedicated on 
///for each user FDSpace)
pub enum FactoryCSpaceGuard<'a> {
	Root(AllocatorBundleGuard<'a>),
	User(MutexGuard<'a, DynamicBitmapAllocator>),
}

impl<'a> CSpaceManager for FactoryCSpaceGuard<'a> {
	fn allocate_slot<A: AllocatorBundle>(&self, alloc: &A) -> Result<SlotRef, CSpaceError> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().allocate_slot(alloc),
			FactoryCSpaceGuard::User(ref guard) => guard.allocate_slot(alloc),
		}
	}
	fn allocate_slot_raw<A: AllocatorBundle>(&self, alloc: &A) -> Result<seL4_CPtr, CSpaceError> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().allocate_slot_raw(alloc),
			FactoryCSpaceGuard::User(ref guard) => guard.allocate_slot_raw(alloc),
		}
	}
	fn free_slot_raw<A: AllocatorBundle>(&self, cptr: seL4_CPtr, alloc: &A) -> Result<(), CSpaceError> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().free_slot_raw(cptr, alloc),
			FactoryCSpaceGuard::User(ref guard) => guard.free_slot_raw(cptr, alloc),
		}
	}
	fn slot_info_raw(&self, cptr: seL4_CPtr) -> Option<CNodeInfo> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().slot_info_raw(cptr),
			FactoryCSpaceGuard::User(ref guard) => guard.slot_info_raw(cptr),
		}
	}
	fn slot_window_raw(&self, cptr: seL4_CPtr) -> Option<Window> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().slot_window_raw(cptr),
			FactoryCSpaceGuard::User(ref guard) => guard.slot_window_raw(cptr),
		}
	}
	fn window(&self) -> Option<Window> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().window(),
			FactoryCSpaceGuard::User(ref guard) => guard.window(),
		}
	}
	fn info(&self) -> Option<CNodeInfo> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().info(),
			FactoryCSpaceGuard::User(ref guard) => guard.info(),
		}
	}
	fn slots_remaining(&self) -> usize {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().slots_remaining(),
			FactoryCSpaceGuard::User(ref guard) => guard.slots_remaining(),
		}
	}
	fn num_slots(&self) -> usize {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().num_slots(),
			FactoryCSpaceGuard::User(ref guard) => guard.num_slots(),
		}
	}
	fn parent_root(&self) -> Option<CNode> {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().parent_root(),
			FactoryCSpaceGuard::User(ref guard) => guard.parent_root(),
		}
	}
	fn minimum_slots(&self) -> usize {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().minimum_slots(),
			FactoryCSpaceGuard::User(ref guard) => guard.minimum_slots(),
		}
	}
	fn minimum_untyped(&self) -> usize {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().minimum_untyped(),
			FactoryCSpaceGuard::User(ref guard) => guard.minimum_untyped(),
		}
	}
	fn minimum_vspace(&self) -> usize {
		match self {
			FactoryCSpaceGuard::Root(ref guard) => guard.cspace().minimum_vspace(),
			FactoryCSpaceGuard::User(ref guard) => guard.minimum_vspace(),
		}
	}
}

///A factory FDSpace, which contains FDFactories
pub struct FactoryFDSpace {
	id: i32,
	cspace: FactoryCSpace,
	max_size: i32,
	search_start: i32,
	allocated: usize,
	fds: RBTree<FactoryFDSpaceAdapter>,
	thread_spaces: RBTree<ThreadFDSpaceAdapter>,
}

impl FactoryFDSpace {
	///Creates a `FactoryFDSpace` for the root server
	pub fn new_root(id: i32) -> FactoryFDSpace {
		FactoryFDSpace {
			id,
			cspace: FactoryCSpace::Root,
			max_size: i32::MAX,
			search_start: 0,
			allocated: 0,
			fds: Default::default(),
			thread_spaces: Default::default(),
		}
	}
	///Sets the maximum size of the FDSpace
	pub fn set_max_size(&mut self, size: i32){
		self.max_size = size;
	}
	///Adds an `FDFactory` to the FDSpace
	///
	///If `id` is Some, the factory will be added with that ID (if an FD
	///with that ID already exists, it will be closed).
	pub fn insert(&mut self, fd: FDFactory, id: Option<i32>) -> Result<i32, VFSError> {
		//info!("FactoryFDSpace::insert");
		if self.allocated >= self.max_size as usize {
			return Err(VFSError::TooManyFiles)
		}

		let (new_id, in_use) = if let Some(existing_id) = id {
			let c = self.fds.find_mut(&existing_id);
			let replace = if c.is_null(){
				false
			}else{
				self.remove(existing_id)?;
				true
			};
			(existing_id, replace)
		}else{
			let mut c = self.fds.upper_bound_mut(Bound::Included(&self.search_start));
			//info!("search_start: {} null: {}", self.search_start, c.is_null());
			let mut id = 0;
			while !c.is_null(){
				let next = c.peek_next();
				id = c.get().unwrap().fd_id.load(Ordering::Relaxed) + 1;
				if next.is_null() || next.get().unwrap().fd_id.load(Ordering::Relaxed) - id > 0 {
					break;
				}
				c.move_next();
			}
			if c.is_null() {
				c = self.fds.back_mut();
				if let Some(fd) = c.get(){
					id = fd.fd_id.load(Ordering::Relaxed) + 1;
				}
			}
			(id, false)
		};
		//info!("id: {}", id);
		fd.added(self.id, new_id);
		if !in_use {
			self.allocated += 1;
		}
		let arc_fd = Arc::new(fd);
		self.fds.insert(arc_fd.clone());
		for fdspace in self.thread_spaces.iter() {
			//info!("adding FD to thread {}", fdspace.thread.get_gtid());
			match arc_fd.new_thread(fdspace.thread.clone()){
				Ok(new_thread) => fdspace.insert(new_id as i32, new_thread),
				Err(err) => return Err(err),
			}
		}
		Ok(new_id)
	}
	///Duplicates an FD. The resulting FD is part of the same FDGroup as
	///the original.
	pub fn dup(&self, src_id: i32, dest: Arc<RwLock<FactoryFDSpace>>, dest_id: Option<i32>) -> Result<i32, VFSError> {
		let cursor = self.fds.find(&src_id);
		if let Some(fd) = cursor.get() {
			dest.write().insert(fd.clone(), dest_id)
		}else{
			Err(VFSError::IOError(IOError::InvalidOperation))
		}
	}
	///Removes an FD from this FDSpace.
	pub fn remove(&mut self, id: i32) -> Result<(), VFSError>{
		//info!("FactoryFDSpace::remove");
		let mut cursor = self.fds.find_mut(&id);
		if let Some(fd) = cursor.remove(){
			if id < self.search_start {
				self.search_start = id;
			}
			let mut res = Ok(());
			for fdspace in self.thread_spaces.iter() {
				res = fd.close_thread(fdspace.thread.clone());
				fdspace.remove(id);
			}
			self.allocated -= 1;
			res
		}else{
			Err(VFSError::IOError(IOError::InvalidOperation))
		}
	}
	///Creates a new thread FD for a a root server thread.
	pub fn new_thread_root(&mut self, thread: ThreadHandle, fds_user: UnsafeRef<FDArray>) -> Result<Arc<ThreadFDSpace>, VFSError>{
		//info!("FactoryFDSpace::new_thread_root");
		let id = (ROOT_PID << size_of::<i32>()) as isize | thread.get_tid() as isize;
		let fdspace = Arc::new(ThreadFDSpace::new_root(thread.clone(), fds_user)?);
		for factory in self.fds.iter() {
			match factory.new_thread(thread.clone()){
				Ok(fd) => fdspace.insert(id as i32, fd),
				Err(err) => return Err(err),
			}
		}
		self.thread_spaces.insert(fdspace.clone());
		Ok(fdspace)
	}
	///Removes a thread from this FDSpace (all thread FDs for the given 
	///thread are removed).
	pub fn delete_thread(&mut self, id: u64) -> Result<(), VFSError> {
		let mut cursor = self.thread_spaces.find_mut(&id);
		if let Some(fdspace) = cursor.remove() {
			for fd in self.fds.iter(){
				fd.remove_thread(fdspace.thread.clone())?;
			}
			Ok(())
		}else{
			Err(VFSError::IOError(IOError::InvalidOperation))
		}
	}
}

///A secondary buffer for a client thread
struct SecondaryBufferInternal {
	offset: usize,
	region: Arc<Mutex<VRegionFactory>>,
}

impl SecondaryBufferInternal {
	///Creates a new secondary buffer.
	fn new(offset: usize, size: usize) -> Result<SecondaryBufferInternal, VSpaceError> {
		match VRegionFactory::new(size, PAGE_BITS as usize, MemRights::rw(), 0, UtZone::RamAny) {
			Ok(region) => {
				Ok(SecondaryBufferInternal {
					offset,
					region,
				})
			},
			Err(err) => Err(err),
		}
	}
	///Maps this buffer into a VSpace.
	fn map(&self, vspace: Arc<VSpaceContainer>) -> Result<usize, VSpaceError> {
		let mut v = vspace.write();
		match v.map(self.region.clone(), None, None){
			Ok(addr) => {
				v.get_secondary_buffers().insert(self, addr);
				Ok(addr)
			}
			Err(err) => Err(err)
		}
	}
	///Unmaps this buffer from a VSpace.
	fn unmap(&self, vspace: Arc<VSpaceContainer>) -> Result<(), VSpaceError>{
		let mut region = self.region.lock();
		if let Err(err) = region.unmap(vspace.get_id(), 0, usize::MAX) {
			Err(err)
		}else{
			vspace.write().get_secondary_buffers().remove(self);
			get_secondary_allocator().free(self.offset);
			Ok(())
		}
	}
}

impl Drop for SecondaryBufferInternal {
	fn drop(&mut self) {
		self.region.lock().unmap_all().expect("failed to unmap secondary buffer region");
	}
}

///The global allocator for secondary buffer IDs.
struct SecondaryBufferAllocator {
	bitmap: Mutex<Treemap>,
}

const MAX_SECONDARY_BUFFERS: usize = 1048576;
const BITMAP_SIZE_BITS: u8 = 10;

impl SecondaryBufferAllocator {
	///Creates a new `SecondaryBufferAllocator`
	fn new() -> SecondaryBufferAllocator {
		SecondaryBufferAllocator {
			bitmap: Mutex::new(Treemap::new(MAX_SECONDARY_BUFFERS, BITMAP_SIZE_BITS).expect("could not allocate bitmap for secondary buffers")),
		}
	}
	///Allocates a new secondary buffer ID
	fn allocate(&self) -> Result<usize, ()> {
		let mut bitmap = self.bitmap.lock();
		let offset = bitmap.first_set().ok_or(())?;
		bitmap.set(offset, 0);
		Ok(offset + 1)
	}
	///Frees a secondary buffer ID
	fn free(&self, mut offset: usize) {
		offset -= 1;
		let mut bitmap = self.bitmap.lock();
		match bitmap.get(offset) {
			Some(1) => panic!("Double free of secondary buffer offset {:?}", offset),
			Some(_) => (),
			None => panic!("Free of out-of-bounds secondary buffer offset {:?}", offset),
		}
		bitmap.set(offset, 1);
	}
}

static mut SECONDARY_BUFFER_ALLOCATOR: Option<SecondaryBufferAllocator> = None;

///Initialize the secondary buffer ID allocator
pub fn init_secondary_allocator(){
	unsafe { SECONDARY_BUFFER_ALLOCATOR = Some(SecondaryBufferAllocator::new()); }
}

///Get the secondary buffer ID allocator
fn get_secondary_allocator() -> &'static SecondaryBufferAllocator {
	unsafe { SECONDARY_BUFFER_ALLOCATOR
		.as_ref()
		.expect("secondary buffer bitmap unset") }
}

//TODO: dynamically adjust the allocation size (any pages that are deallocated should be returned as all nulls by the page fault handler)
///A user-level secondary buffer array
pub struct UserSecondaryBufferArray {
	contents_root: Mutex<UnsafeArray<SecondaryBufferInfo>>,
	contents_user: UnsafeRef<UnsafeArray<SecondaryBufferInfo>>,
	region: Arc<Mutex<VRegionFactory>>,
}

impl UserSecondaryBufferArray {
	///Creates the secondary buffer array for the root server
	pub fn new_root(len: usize) -> UserSecondaryBufferArray {
		let (ptr, initial_size, region) = reserve_array(len, SECONDARY_BUFFER_ALIGN).expect("failed to allocate secondary buffer array for root server");
		//info!("UserSecondaryBufferArray::new: {:x}, {}", ptr, initial_size);

		//safety: reserve_array always returns a valid region address 
		//and size
		let contents_user = unsafe { UnsafeRef::from_box(Box::new(UnsafeArray::new(len, ptr, SECONDARY_BUFFER_ALIGN, 0))) };
		set_secondary_buffers(contents_user.clone());
		UserSecondaryBufferArray {
			contents_root: Mutex::new(UnsafeArray::clone(&contents_user)),
			contents_user,
			region,
		}
	}
	///Adds a buffer to this array
	fn insert(&self, buffer: &SecondaryBufferInternal, addr: usize) {
		let info = SecondaryBufferInfo::new(addr);
		self.contents_root.lock()[buffer.offset] = info;
	}
	///Removes a buffer from this array
	fn remove(&self, buffer: &SecondaryBufferInternal) {
		self.contents_root.lock()[buffer.offset] = SecondaryBufferInfo::null();
	}
}

impl Drop for UserSecondaryBufferArray {
	fn drop(&mut self){
		self.region.lock().unmap_all().expect("could not drop secondary buffer; unmapping failed");
	}
}

///Reserves a shared array for FDs or secondary buffers
fn reserve_array(max_size: usize, align: usize) -> Result<(usize, usize, Arc<Mutex<VRegionFactory>>), VFSError>{
	let res_size = max_size * align;

	let region = match VRegionFactory::new(res_size, PAGE_BITS as usize, MemRights::rw(), 0, UtZone::RamAny){
		Ok(f) => f,
		Err(err) => { return Err(VFSError::VSpaceError(err)); },
	};

	let initial_size = PAGE_SIZE / align;
	let tmp = get_root_vspace();
	let mut vspace = tmp.write();
	match vspace.map(region.clone(), None, None) {
		Ok(addr) => Ok((addr, res_size, region)),
		Err(err) => Err(VFSError::VSpaceError(err)),
	}
}

const_assert!(size_of::<ThreadFD>() < FD_ALIGN);

///A thread's copy of an FDSpace
pub struct ThreadFDSpace {
	fds_user: UnsafeRef<FDArray>,
	fds_root: Mutex<FDArray>,
	fds_region: Arc<Mutex<VRegionFactory>>,
	root_start_vaddr: AtomicUsize,
	size: AtomicUsize,
	max_size: AtomicUsize,
	thread: ThreadHandle,
	fdspace_link: RBTreeAtomicLink,
}

impl ThreadFDSpace {
	///Creates an FDSpace for a root thread
	pub fn new_root(thread: ThreadHandle, fds: UnsafeRef<FDArray>) -> Result<ThreadFDSpace, VFSError> {
		let max_size = 8192;
		let (start_vaddr, initial_size, region) = reserve_array(max_size, FD_ALIGN)?;
		//info!("ThreadFDSpace::new: {:x}, {}", start_vaddr, initial_size);
		//safety: reserve_array always returns a valid region address 
		//and size
		unsafe { 
			fds.set_len(initial_size);
			fds.set_ptr(start_vaddr);
		}
		let fds_root = FDArray::clone(&fds);
		Ok(ThreadFDSpace {
			fds_user: fds,
			fds_root: Mutex::new(fds_root),
			fds_region: region,
			root_start_vaddr: AtomicUsize::new(start_vaddr),
			size: AtomicUsize::new(initial_size),
			max_size: AtomicUsize::new(max_size),
			thread,
			fdspace_link: Default::default(),
		})
	}
	///Adds a thread FD to this FDSpace
	pub fn insert(&self, id: i32, fd: UnifiedFileDescriptor) {
		let mut fds_root = self.fds_root.lock();

		if id >= fds_root.len() as i32 {
			panic!("TODO: implement FDSpace expansion");
			//TODO: make sure to update the size of fds_user as well as fds_root here
		}
		let runnable = self.thread.suspend_if_other();
		fds_root.insert(id, fd);
		self.thread.resume_if_other(runnable);
	}
	///Removes a thread FD from this FDSpace
	pub fn remove(&self, id: i32) {
		let mut fds_root = self.fds_root.lock();
		let runnable = self.thread.suspend_if_other();
		fds_root.remove(id as i32);
		self.thread.resume_if_other(runnable);
	}
	///Gets the user-visible array of thread FDs 
	pub fn get_user_fds(&self) -> UnsafeRef<FDArray> {
		self.fds_user.clone()
	}
}

impl Drop for ThreadFDSpace {
	fn drop(&mut self) {
		let fds = unsafe { UnsafeRef::into_box(self.fds_user.clone()) };
		drop(fds);
		self.fds_region.lock().unmap_all().expect("could not unmap FD region for ThreadFDSpace");
	}
}

intrusive_adapter!(ThreadFDSpaceAdapter = Arc<ThreadFDSpace>: ThreadFDSpace { fdspace_link: RBTreeAtomicLink });

impl<'a> KeyAdapter<'a> for ThreadFDSpaceAdapter {
	type Key = u64;
	fn get_key(&self, fdspace: &'a ThreadFDSpace) -> u64 {
		fdspace.thread.get_gtid()
	}
}

///The global list of FDSpaces
pub struct FDSpaceList {
	contents: RwLock<BTreeMap<i32, Arc<RwLock<FactoryFDSpace>>>>,
	next_id: AtomicI32,
}

impl FDSpaceList {
	///Creates a new `FDSpaceList`.
	fn new() -> FDSpaceList {
		let list = FDSpaceList {
			contents: Default::default(),
			next_id: AtomicI32::new(0),
		};
		list.new_fdspace_root().expect("failed to initialize process server FDSpace");
		list
	}
	///Gets an FDSpace from the list
	pub fn get(&self, id: i32) -> Option<Arc<RwLock<FactoryFDSpace>>> {
		if let Some(fd) = self.contents.read().get(&id) {
			Some(fd.clone())
		}else{
			None
		}
	}
	///Creates a new FDSpace for the root server
	pub fn new_fdspace_root(&self) -> Option<Arc<RwLock<FactoryFDSpace>>> {
		let id = self.get_next_id();
		let fdspace = Arc::new(RwLock::new(FactoryFDSpace::new_root(id)));
		self.contents.write().insert(id, fdspace.clone());
		Some(fdspace)
	}
	///Removes an FDSpace from the list
	pub fn remove(&self, id: i32) -> Result<(), ()> {
		let mut contents = self.contents.write();
		if contents.contains_key(&id) {
			contents.remove(&id);
			Ok(())
		}else{
			Err(())
		}
	}
}

impl GlobalIDAllocator for FDSpaceList {
	fn has_id(&self, id: i32) -> bool {
		self.contents.read().contains_key(&id)
	}
	fn get_next_id(&self) -> i32 {
		self.next_id.load(Ordering::SeqCst)
	}
	fn increment_id(&self) -> i32 {
		self.next_id.fetch_add(1, Ordering::SeqCst)
	}
}

pub const ROOT_FDSPACE_ID: i32 = 0;
static mut FDSPACE_LIST: Option<FDSpaceList> = None;

///Initializes the FDSpace list
pub fn init_fdspace_list() {
	unsafe { FDSPACE_LIST = Some(FDSpaceList::new()) }
}

///Gets the FDSpace list
pub fn get_fdspace_list() -> &'static FDSpaceList {
	unsafe { &FDSPACE_LIST.as_ref().expect("FDSPACE_LIST uninitialized") }
}

///Gets the root FDSpace
pub fn get_root_fdspace() -> Arc<RwLock<FactoryFDSpace>> {
	get_fdspace_list().get(ROOT_FDSPACE_ID).expect("root FDSpace not initialized").clone()
}

#[thread_local]
static mut THREAD_FDSPACE: Option<Arc<ThreadFDSpace>> = None;

///Called to set the thread-local FD array for root threads
pub fn fdspace_root_thread_init(fdspace: Arc<ThreadFDSpace>) {
	set_fd_array(fdspace.fds_user.clone());
}

///Gets an FD from the current thread's FDSpace
pub fn get_fd(id: i32) -> ThreadFD {
	let base_fd = uxrt_transport_layer::get_fd(id);
	ThreadFD {
		base_fd
	}
}

///Adds FDSpace-related custom slabs
pub fn add_custom_slabs() {
	add_arc_slab!(FDGroup, 512, 4, 4, 2).expect("could not add custom slab for FDGroup");
	add_arc_slab!(ServerParams, 512, 4, 4, 2).expect("could not add custom slab for ServerParams");
	add_arc_slab!(ThreadFDInternal, 512, 4, 4, 2).expect("could not add custom slab for ThreadFDInternal");
	add_arc_slab!(FDFactory, 512, 4, 4, 2).expect("could not add custom slab for FDFactory");
	add_arc_slab!(ThreadFDSpace, 512, 4, 4, 2).expect("could not add custom slab for ThreadFDSpace");
	add_arc_slab!(RwLock<FactoryFDSpace>, 512, 4, 4, 2).expect("could not add custom slab for FactoryFDSpace");
	add_arc_slab!(FDVSpace, 512, 4, 4, 2).expect("could not add custom slab for FDVSpace");
	add_slab::<ClientFileDescriptorState>(512, 4, 4, 2).expect("could not add custom slab for client state");
	add_slab::<ServerFileDescriptorState>(512, 4, 4, 2).expect("could not add custom slab for server state");
	add_slab::<FDArray>(512, 4, 4, 2).expect("could not add custom slab for client state");
	add_slab::<UnifiedFileDescriptor>(512, 4, 4, 2).expect("could not add custom slab for client state");
}
