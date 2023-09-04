// Copyright 2022 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::{
    base_thread::*,
    thread_debug_println,
};

use alloc::vec::Vec;
use alloc::sync::Arc;

use sel4::{
    PAGE_BITS,
    PAGE_SIZE,
    CapRights,
    Endpoint,
    Notification,
    Thread,
    ToCap,
    seL4_Word,
};

use sel4_alloc::{
    AllocatorBundle,
    cspace::CSpaceManager,
    utspace::UtZone,
    vspace::{
        VSpaceError,
        VSpaceManager,
        VSpaceReservation,
    },
};

use sel4_sys::{
    seL4_Fault_NullFault,
    seL4_IPCBuffer,
    tls
};

use sel4_thread_park::Parker;

///Configuration specific to local threads.
#[derive(Copy, Clone, Debug)]
pub struct LocalThreadConfig {
    pub stack_size: usize,
    pub allocate_ipc_buffer: bool,
    pub create_reply: bool,
    pub exit_endpoint: Option<Endpoint>,
}

///A thread in the same address space as the parent thread, using a closure as
///an entry point.
pub struct LocalThread {
    base_thread: BaseThread,
    stack_size: usize,
    pub(crate) stack_top: usize,
    pub(crate) initial_stack_pointer: usize,
    unpark_notification: Notification,
    exit_endpoint: Option<Endpoint>,
    parker: Arc<Parker>,
}

impl LocalThread {
    ///Creates a new LocalThread, automatically allocating all required objects.
    pub fn new<A: AllocatorBundle>(common_config: CommonThreadConfig, local_config: LocalThreadConfig, sched_params: SchedParams, alloc: &A) -> Result<Self, ThreadError>{
        thread_debug_println!("LocalThread::new");
        let base_thread_opt = BaseThread::new(alloc);
        if let Err(err) = base_thread_opt {
            return Err(err);
        }
        let mut base_thread = base_thread_opt.unwrap();

        let unpark_notification = alloc.cspace().allocate_slot_with_object_fixed::<Notification, _>(alloc);
        if let Err(err) = unpark_notification {
            return Err(ThreadError::CSpaceAllocationError {
                details: err,
            });
        }

        if let Err(err) = base_thread.set_space(common_config){
            return Err(err);
        }

        if local_config.create_reply {
            if let Err(err) = base_thread.allocate_reply(alloc){
                return Err(err);
            }
        }

        if let Err(err) = base_thread.set_sched_params(sched_params, alloc){
            let _ = base_thread.deallocate_objects(alloc);
            return Err(err);
        }

        let mut ipc_buffer_addr = None;

        if local_config.allocate_ipc_buffer {
            let ipc_buffer_res = alloc.vspace().allocate_and_map(1<<PAGE_BITS, PAGE_BITS as usize, CapRights::all(), 0, UtZone::RamAny, alloc);
            if let Err(err) = ipc_buffer_res {
                let _ = base_thread.deallocate_objects(alloc);
                return Err(ThreadError::VSpaceAllocationError { details: err });
            }
            ipc_buffer_addr = Some(ipc_buffer_res.unwrap());

            let ipc_buffer_cap = alloc.vspace().get_cap(ipc_buffer_addr.unwrap());
            thread_debug_println!("ipc_buffer_addr: {:x}, ipc_buffer_cap: {:x}", ipc_buffer_addr.unwrap(), ipc_buffer_cap.unwrap());
            if ipc_buffer_cap.is_none() {
                let _ = base_thread.deallocate_objects(alloc);
                return Err(ThreadError::VSpaceAllocationError { details: VSpaceError::InternalError });
            }
            if let Err(err) = base_thread.set_ipc_buffer(ipc_buffer_addr.unwrap(), ipc_buffer_cap.unwrap()) {
                let _ = base_thread.deallocate_objects(alloc);
                return Err(err);
            }
        }
       
        let stack_size = (local_config.stack_size + (PAGE_SIZE - 1)) & !(PAGE_SIZE - 1);
        let stack_reservation_opt = alloc.vspace().reserve(stack_size + PAGE_SIZE, alloc);
        if stack_reservation_opt.is_none(){
            let _ = base_thread.deallocate_objects(alloc);
            return Err(ThreadError::VSpaceAllocationError { details: VSpaceError::ReservationFailure });
        }
        let stack_reservation = stack_reservation_opt.unwrap();
        if let Err(err) = alloc.vspace().allocate_and_map_at_vaddr(
            &stack_reservation.start_vaddr() + PAGE_SIZE,
            stack_size,
            PAGE_BITS as usize,
            &stack_reservation,
            CapRights::all(),
            0,
            UtZone::RamAny,
            alloc
        ){
            let _ = base_thread.deallocate_objects(alloc);
            let _ = alloc.vspace().unreserve_and_free(ipc_buffer_addr.unwrap(), PAGE_SIZE, PAGE_BITS as usize, alloc);
            let _ = alloc.vspace().unreserve(stack_reservation, alloc);
            return Err(ThreadError::VSpaceAllocationError { details: err });
        }

        let stack_top = stack_reservation.end_vaddr();
        thread_debug_println!("stack bottom: {:x}", stack_reservation.start_vaddr());

        Ok(LocalThread {
            base_thread,
            stack_size,
            stack_top, 
            initial_stack_pointer: stack_top,
            unpark_notification: unpark_notification.unwrap(),
            parker: Parker::new(unpark_notification.unwrap()),
            exit_endpoint: local_config.exit_endpoint,
        })
    }
    ///Sets up the thread to run `f`, but does not actually start it (which 
    ///must be done with the resume() method). 
    pub fn setup<F>(&mut self, mut f: F) -> Result<(), ThreadError> 
            where F: FnMut() -> Option<Vec<seL4_Word>> + Send + 'static {
        let tls_size = unsafe { tls::get_size() };
        if tls_size > self.stack_size / 8 {
            warn!("TLS size of {} would use over 1/8 of available stack space of {}", tls_size, self.stack_size);
            return Err(ThreadError::StackTooSmall);
        }
        self.initial_stack_pointer = self.stack_top;
        self.initial_stack_pointer -= tls_size;
        thread_debug_println!("initial_stack_pointer: {:x}", self.initial_stack_pointer);
        self.initial_stack_pointer = self.initial_stack_pointer & !(self.get_stack_align() - 1);
        let tls_start = self.initial_stack_pointer;
        let tls_base;
        thread_debug_println!("tls_start: {:x}", tls_start);
        if let Some(ipcbuf) = self.get_ipc_buffer(){
            thread_debug_println!("writing TLS image starting at {:p} with IPC buffer at {:p}", tls_start as *mut u8, ipcbuf.1 as *const seL4_IPCBuffer);
            tls_base = unsafe { tls::write_image_with_ipcbuf(tls_start as *mut u8, ipcbuf.1 as *const seL4_IPCBuffer) };
        }else{
            thread_debug_println!("writing TLS image starting at {:p} without IPC buffer", tls_start as *mut u8);
            tls_base = unsafe { tls::write_image(tls_start as *mut u8) };
        }
        thread_debug_println!("tls_base: {:x}", tls_base);

        thread_debug_println!("setting up user context");
        thread_debug_println!("initial_stack_pointer: {:x}", self.initial_stack_pointer);
        let tcb = self.get_tcb();
        let mut fault_endpoint = None;
        if let Some(config) = self.get_space() {
            if config.fault_endpoint.to_cap() != 0 {
                fault_endpoint = Some(config.fault_endpoint);
            }
        }
        let parker = self.parker.clone();
        let mut exit_endpoint = fault_endpoint;
        if self.exit_endpoint.is_some() {
            exit_endpoint = self.exit_endpoint;
        }
        let context = self.setup_local_user_context(move ||{
            unsafe { sel4_thread_park::init(parker.clone()) };
            let ret = f();
            if let Some(endpoint) = exit_endpoint {
                if let Some(vec) = ret{
                    let _ = endpoint.send_data(seL4_Fault_NullFault as usize, &vec);
                }else{
                    let _ = endpoint.send_data(seL4_Fault_NullFault as usize, &[]);
                }
            }
            let _ = tcb.suspend();
            panic!("LocalThread::setup: shouldn't get here");
        });

        if let Err(err) = context {
            return Err(err);
        }

        thread_debug_println!("setting up registers");
        if let Err(err) = self.write_registers(false, 0, &context.unwrap()){
            return Err(ThreadError::SyscallError { details: err }) 
        }

        thread_debug_println!("setting TLS base");
        if let Err(err) = self.set_tls_base(tls_base){
            return Err(ThreadError::SyscallError { details: err }) 
        }

        thread_debug_println!("setup done");
        Ok(())
    }
    ///Sets up the thread to run `f` and starts it.
    pub fn run<F>(&mut self, f: F) -> Result<(), ThreadError>
            where F: FnMut() -> Option<Vec<seL4_Word>> + Send + 'static {
        thread_debug_println!("setting up thread");
        if let Err(err) = self.setup(f){
            return Err(err);
        }
        thread_debug_println!("starting thread");
        if let Err(err) = self.resume(){
            return Err(ThreadError::SyscallError { details: err });
        }
        thread_debug_println!("thread started");
        Ok(())
    }
    pub fn get_exit_endpoint(&self) -> Option<Endpoint> {
        self.exit_endpoint
    }
    ///Deallocates all objects related to this thread. Must be called before the
    ///thread is dropped (otherwise a panic will occur).
    pub fn deallocate_objects<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        if let Err(err) = self.base_thread.deallocate_objects(alloc){
            return Err(err);
        }
        if let Some(buf) = self.base_thread.get_ipc_buffer(){
            if let Err(err) = alloc.vspace().unreserve_and_free(buf.1, PAGE_SIZE, PAGE_BITS as usize, alloc){
                return Err(ThreadError::VSpaceAllocationError { details: err.1 });
            }
            if let Err(err) = self.base_thread.set_ipc_buffer(0, 0){
                return Err(err);
            }
        }
        
        if self.stack_top != 0 {
            if let Ok(reservation) = alloc.vspace().get_reservation(self.stack_top - PAGE_SIZE){
                if let Err(err) = alloc.vspace().unmap_and_free(reservation.start_vaddr() + PAGE_SIZE, self.stack_size, PAGE_BITS as usize, alloc){
                    return Err(ThreadError::VSpaceAllocationError { details: err.1 })
                }
                if let Err(err) = alloc.vspace().unreserve(reservation, alloc) {
                    return Err(ThreadError::VSpaceAllocationError { details: err });
                }
                self.stack_top = 0;
                self.stack_size = 0;
            }else{
                return Err(ThreadError::InternalError);
            }
        }
        if self.unpark_notification.to_cap() != 0 {
            if let Err(err) = alloc.cspace().free_and_delete_slot_with_object_fixed(&self.unpark_notification, alloc){
                return Err(ThreadError::CSpaceAllocationError { details: err })
            }
        }
        Ok(())
    }
}

impl WrappedThread for LocalThread {
    fn get_base_thread(&self) -> &BaseThread {
        &self.base_thread   
    }
    fn get_base_thread_mut(&mut self) -> &mut BaseThread {
        &mut self.base_thread   
    }
    fn get_tcb(&self) -> Thread {
        self.base_thread.get_tcb()
    }
}

impl Drop for LocalThread {
    fn drop(&mut self) {
        if self.stack_top != 0{
            panic!("attempted to drop LocalThread at {:p} with non-null stack top address {:x}", self, self.stack_top);
        }
        if let Some(buf) = self.base_thread.get_ipc_buffer(){
            panic!("attempted to drop LocalThread at {:p} with non-null IPC buffer at address {:x} and CPtr {:x}", self, buf.0, buf.1);
        }
    }
}
