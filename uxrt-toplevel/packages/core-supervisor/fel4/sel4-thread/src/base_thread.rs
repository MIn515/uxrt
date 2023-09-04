// Copyright 2022 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::thread_debug_println;
use alloc::string::String;

use sel4::{
    CNode, 
    DomainSet, 
    Endpoint,
    FromCap,
    Notification,
    Reply,
    SchedContext, 
    SchedControl, 
    Thread,
    ToCap,
    seL4_Word, 
    seL4_CPtr, 
    seL4_UserContext,
};

#[cfg(HardwareDebugAPI)]
use sel4::Breakpoint;

#[cfg(KernelVTX)]
use sel4::VCPU;

#[cfg(feature = "kobj_alloc")]
use sel4_alloc::{
    AllocatorBundle,
    cspace::{
        CSpaceError,
        CSpaceManager,
    },
    vspace::VSpaceError,
};

#[derive(Clone, Copy, Debug, Fail)]
pub enum ThreadError {
    #[fail(display = "CSpace allocation error")]
    CSpaceAllocationError { details: CSpaceError },
    #[fail(display = "VSpace allocation error")]
    VSpaceAllocationError { details: VSpaceError },
    #[fail(display = "System call error")]
    SyscallError { details: sel4::Error },
    #[fail(display = "Field already set")]
    AlreadySet,
    #[fail(display = "Field unset")]
    Unset,
    #[fail(display = "Stack too small")]
    StackTooSmall,
    #[fail(display = "Internal error")]
    InternalError,
}

///Contains all the scheduling-related parameters for threads. 
///
///May be used to configure multiple threads and seheduling contexts (although
///each thread will get its own copy when it is configured).
#[derive(Copy, Clone, Debug)]
pub struct SchedParams {
    pub priority: u8,
    pub mcp: u8,
    pub core: usize,
    pub context_bits: usize,
    pub sched_ctrl: SchedControl,
    pub period: u64,
    pub budget: u64,
    pub extra_refills: usize,
    pub flags: usize,
    pub badge: usize,
}

impl SchedParams {
    ///Create a new scheduling context
    #[cfg(feature = "kobj_alloc")]
    pub fn new_context<A: AllocatorBundle>(self, alloc: &A) -> Result<SchedContext, ThreadError>{
        let res = alloc.cspace().allocate_slot_with_object_ram::<SchedContext, _>(self.context_bits, alloc);
        if res.is_err(){
            return Err(ThreadError::CSpaceAllocationError { details: res.unwrap_err() });
        }
        thread_debug_println!("LocalThread::new_context: {:x}", res.unwrap().to_cap());
        let context = res.unwrap();
        if let Err(err) = self.configure_context(context){
            let _ = alloc.cspace().free_and_delete_slot_with_object(&context, self.context_bits, alloc);
            Err(err)
        }else{
            Ok(context)
        }
    }
    ///Frees a scheduling context allocated from this object (attempting to
    ///deallocate a context from another one may fail since the size may be 
    ///different, so this should be avoided)
    pub fn free_context<A: AllocatorBundle>(self, context: SchedContext, alloc: &A) -> Result<(), ThreadError>{
        thread_debug_println!("free_context: {:x}", context.to_cap());
        if let Err(err) = alloc.cspace().free_and_delete_slot_with_object::<SchedContext, _>(&context, self.context_bits, alloc) {
            Err(ThreadError::CSpaceAllocationError { details: err })
        }else{
            Ok(())
        }
    }
    ///Configures a scheduling context with the relevant parameters from this object
    pub fn configure_context(self, context: SchedContext) -> Result<(), ThreadError>{
        if let Err(err) = self.sched_ctrl.configure(
            context,
            self.budget,
            self.period,
            self.extra_refills,
            self.badge,
            self.flags,
        ){
            Err(ThreadError::SyscallError { details: err })
        }else{
            Ok(())
        }
    }
}

///Contains the CSpace, VSpace, and fault endpoint for a thread. May be used
///to configure multiple threads.
#[derive(Copy, Clone, Debug)]
pub struct CommonThreadConfig {
    pub cspace_root: CNode,
    pub cspace_root_data: seL4_Word,
    pub vspace_root: seL4_CPtr,
    pub vspace_root_data: seL4_Word,
    pub fault_endpoint: Endpoint,
}

///A generic TCB wrapper
pub trait WrappedThread {
    ///Gets the base thread object associated with this object as a mutable reference.
    fn get_base_thread_mut(&mut self) -> &mut BaseThread;
    ///Gets the base thread object associated with this object as a reference.
    fn get_base_thread(&self) -> &BaseThread;
    ///Gets the TCB associated with this object.
    fn get_tcb(&self) -> Thread;
    ///Binds a notification object to this thread.
    #[inline(always)]
    fn bind_notification(&mut self, notification: Notification) -> Result<(), ThreadError> {
        self.get_base_thread_mut().bind_notification(notification)
    }
    ///Unbinds any notification object from this thread.
    ///
    ///Returns the notification if one was bound, or ThreadError if there was 
    ///none or an error happened when unbinding.
    #[inline(always)]
    fn unbind_notification(&mut self) -> Result<Notification, ThreadError> {
        self.get_base_thread_mut().unbind_notification()
    }
    ///Returns the notification object bound this thread.
    #[inline(always)]
    fn get_bound_notification(&self) -> Option<Notification>{
        self.get_base_thread().get_bound_notification()
    }
    ///Configures this thread with a new CommonThreadConfig.
    #[inline(always)]
    fn set_space(&mut self, config: CommonThreadConfig) -> Result<(), ThreadError>{
        self.get_base_thread_mut().set_space(config)
    }
    ///Returns a CommonThreadConfig with this thread's parameters.
    ///
    ///The return value is a copy of the original config.
    #[inline(always)]
    fn get_space(&self) -> Option<CommonThreadConfig> {
        self.get_base_thread().get_space()
    }
    /// Set this thread's IPC buffer.
    ///
    /// `address` is where in the virtual address space the IPC buffer will be   located, and `frame`
    /// is a capability to the physical memory that will back that page.  `add  ress` must be
    /// naturally aligned to 512-bytes.
    #[inline(always)]
    fn set_ipc_buffer(&mut self, address: seL4_Word, frame: seL4_CPtr) -> Result<(), ThreadError>{
        self.get_base_thread_mut().set_ipc_buffer(address, frame)
    }
    ///Gets the virtual address and capability of the IPC buffer
    #[inline(always)]
    fn get_ipc_buffer(&self) -> Option<(seL4_Word, seL4_CPtr)> {
        self.get_base_thread().get_ipc_buffer()
    }
    ///Configures this thread with a new CommonThreadConfig and IPC buffer.
    ///
    ///The IPC buffer arguments are the same as those to `set_ipc_buffer`.
    #[inline(always)]
    fn configure(&mut self, config: CommonThreadConfig, ipc_buffer_addr: usize, ipc_buffer_frame: seL4_CPtr) -> Result<(), ThreadError>{
        self.get_base_thread_mut().configure(config, ipc_buffer_addr, ipc_buffer_frame)
    }
    ///Sets the scheduler parameters for this thread.
    ///
    ///Creates a copy of the scheduler parameters.
    #[inline(always)]
    fn set_sched_params<A: AllocatorBundle>(&mut self, params: SchedParams, alloc: &A) -> Result<(), ThreadError>{
        self.get_base_thread_mut().set_sched_params(params, alloc)
    }
    ///Gets a copy of the scheduler parameters for this thread.
    #[inline(always)]
    fn get_sched_params(&self) -> Option<SchedParams> {
        self.get_base_thread().get_sched_params()
    }
    ///Creates a new scheduling context for this thread from the scheduler 
    ///parameters.
    ///
    ///The scheduler parameters must have been previously set by 
    ///`set_sched_params()`.
    #[cfg(feature = "kobj_alloc")]
    #[inline(always)]
    fn new_sched_context<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        self.get_base_thread_mut().new_sched_context(alloc)
    }
    ///Unbinds and deallocates this thread's scheduling context.
    #[cfg(feature = "kobj_alloc")]
    #[inline(always)]
    fn deallocate_sched_context<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        self.get_base_thread_mut().deallocate_sched_context(alloc)
    }
    ///Binds a pre-existing scheduling context to this thread.
    #[inline(always)]
    fn bind_sched_context(&mut self, context: SchedContext) -> Result<(), ThreadError>{
        self.get_base_thread_mut().bind_sched_context(context)
    }
    ///Unbinds this thread's scheduling context and returns it.
    #[inline(always)]
    fn unbind_sched_context(&mut self) -> Result<SchedContext, ThreadError>{
        self.get_base_thread_mut().unbind_sched_context()
    }
    ///Gets this thread's scheduling context.
    #[inline(always)]
    fn get_sched_context(&self) -> Option<SchedContext>{
        self.get_base_thread().get_sched_context()
    }
    ///Allocates a reply slot for this thread.
    #[cfg(feature = "kobj_alloc")]
    #[inline(always)]
    fn allocate_reply<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<Reply, ThreadError> {
        self.get_base_thread_mut().allocate_reply(alloc)
    }
    ///Deallocates this thread's reply slot.
    #[cfg(feature = "kobj_alloc")]
    #[inline(always)]
    fn deallocate_reply<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        self.get_base_thread_mut().deallocate_reply(alloc)
    }
    ///Gets this thread's reply slot.
    #[inline(always)]      
    fn get_reply(&self) -> Option<Reply> {
        self.get_base_thread().get_reply()
    }
    
    ///Sets this thread's name.
    fn set_name(&mut self, name: &str) {
        self.get_base_thread_mut().set_name(name)
    }

    ///Gets this thread's name.
    fn get_name(&self) -> Option<String> {
        self.get_base_thread().get_name()
    }

    /// Configure single stepping for this thread.
    ///
    /// `bp_num`: Hardware breakpoint number to use. May or may not be used de  pending on
    /// hardware architecture.
    ///
    /// `num_instructions`: Number of instructions to step over before trigger  ing breakpoint.
    /// Set to 0 to disable single stepping.
    ///
    /// Result contains an optional value. If optional value is Some(()), the   hardware breakpoint  
    /// was consumed and should not be used again until single stepping is dis  abled.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    fn configure_single_stepping(&self, bp_num: u16, num_instructions: seL4_Word) -> Result<Option<()>, sel4::Error> {
        self.get_tcb().configure_single_stepping(bp_num, num_instructions)
    }
    /// Copy the registers from this thread to `dest`.
    ///
    /// If `suspend_source` is true, this thread is suspended before the transfer.
    ///
    /// If `resume_dest` is true, the destination thread is resumed after the transfer.
    ///
    /// If `transfer_frame`, is true, frame registers will be transfered. These are the registers
    /// read, modified, or preserved by system calls.
    ///
    /// If `transfer_integer` is true, all the registers not transfered by `transfer_frame` will be
    /// transfered.
    #[inline(always)]
    fn copy_registers(&self, dest: BaseThread, suspend_source: bool, resume_dest: bool,
                            transfer_frame: bool, transfer_integer: bool, arch_flags: u8) 
                            -> sel4::Result {
        self.get_tcb().copy_registers(dest.tcb, suspend_source, resume_dest, transfer_frame, transfer_integer, arch_flags)
    }
    /// Read this thread's registers.
    ///
    /// If `suspend`, suspend this thread before copying.
    #[inline(always)]
    fn read_registers(&self, suspend: bool, arch_flags: u8)
            -> Result<seL4_UserContext, sel4::Error> {
        self.get_tcb().read_registers(suspend, arch_flags)
    }
    /// Set this thread's registers from the provided context.
    ///
    /// If `resume`, resume this thread after writing.
    #[inline(always)]
    fn write_registers(&self, resume: bool, arch_flags: u8, regs: &seL4_UserContext) -> sel4::Result{
        self.get_tcb().write_registers(resume, arch_flags, regs)
    }
    /// Returns the breakpoint previously set on this thread for `bp_num`.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    fn get_breakpoint(&self, bp_num: u16) -> Result<Option<Breakpoint>, sel4::Error> {
        self.get_tcb().get_breakpoint(bp_num)
    }
    /// Returns this thread's utilization counters.
    ///
    /// Only available when KernelBenchmarksTrackUtilisation is set.
    #[cfg(KernelBenchmarksTrackUtilisation)]
    #[inline(always)]
    fn get_utilization(&self) -> benchmark_track_util {
        self.get_tcb().get_utilization()
    }
    /// Resets this thread's utilization counters.
    ///
    /// Only available when KernelBenchmarksTrackUtilisation is set.
    #[cfg(KernelBenchmarksTrackUtilisation)]
    #[inline(always)]
    fn reset_utilization(&self) {
        self.get_tcb().reset_utilization()
    }
    /// Resume this thread
    #[inline(always)]
    fn resume(&self) -> sel4::Result {
        self.get_tcb().resume()
    }
    /// Suspend this thread.
    #[inline(always)]
    fn suspend(&self) -> sel4::Result {
        self.get_tcb().suspend()
    }
    /// Set one of this thread's breakpoints. Overwrites any existing breakpoint.
    ///
    /// `bp_num` is the breakpoint number to set. Must be >= 0 and < seL4_NumHWBreakpoints.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    fn set_breakpoint(&self, bp_num: u16, bp: Breakpoint) -> sel4::Result {
        self.get_tcb().set_breakpoint(bp_num, bp)
    }
    /// Disable hardware breakpoint and clear underlying hardware registers.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    fn unset_breakpoint(&self, bp_num: u16) -> sel4::Result {
        self.get_tcb().unset_breakpoint(bp_num)
    }
    /// Sets the VCPU for this thread
    ///
    /// Only available when KernelVTX is set
    #[cfg(KernelVTX)]
    #[inline(always)]
    fn set_ept_root(&self, vcpu: VCPU) -> sel4::Result {
        self.get_tcb().set_ept_root(vcpu);
    }
    /// Set this thread's domain.
    #[inline(always)]
    fn set_domain(&self, domain: u8, domain_control: DomainSet) -> sel4::Result {
        self.get_tcb().set_domain(domain, domain_control)
    }
    /// Set this thread's TLS base address.
    #[inline(always)]
    fn set_tls_base(&self, base: usize) -> sel4::Result {
        self.get_tcb().set_tls_base(base)
    } 
}

pub struct BaseThread {
    tcb: Thread,
    config: Option<CommonThreadConfig>,
    sched_params: Option<SchedParams>,
    sched_context: Option<SchedContext>,
    ipc_buffer: Option<(seL4_CPtr, usize)>,
    reply: Option<Reply>,
    bound_notification: Option<Notification>,
    name: Option<String>,
}

impl BaseThread {
    ///Creates a new `BaseThread`, allocating a new TCB.
    #[cfg(feature = "kobj_alloc")]
    pub fn new<A: AllocatorBundle>(alloc: &A) -> Result<Self, ThreadError>{
        let null_tcb = Thread::from_cap(0);
        let mut ret = Self::new_from_tcb(null_tcb);
        if let Err(err) = ret.new_tcb(alloc){
            return Err(err);
        }
        Ok(ret)
    }
    ///Creates a new `BaseThread` from a pre-existing TCB.
    pub fn new_from_tcb(tcb: Thread) -> Self {
        BaseThread {
            tcb,
            config: None,
            sched_params: None,
            sched_context: None,
            ipc_buffer: None,
            reply: None,
            bound_notification: None,
            name: None,
        }
    }
    ///Allocates a new TCB. Fails if this thread already has a non-null TCB.
    pub fn new_tcb<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        if self.tcb.to_cap() != 0 {
            return Err(ThreadError::AlreadySet);
        }
        let tcb = alloc.cspace().allocate_slot_with_object_fixed::<Thread, _>(alloc);
        if tcb.is_err(){
            return Err(ThreadError::CSpaceAllocationError { details: tcb.unwrap_err() });
        }
        thread_debug_println!("LocalThread::new_tcb: {:x}", tcb.unwrap().to_cap());
        self.tcb = tcb.unwrap();
        Ok(())
    }
    ///Deallocates all objects related to this thread. Must be called before the
    ///thread is dropped (otherwise a panic will occur).
    pub fn deallocate_objects<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        if self.tcb.to_cap() == 0 {
            warn!("attempted to free thread with null TCB");
            return Err(ThreadError::Unset)
        }
        if self.reply.is_some(){ 
            if let Err(err) = self.deallocate_reply(alloc) {
                return Err(err);
            }
        }
        if self.sched_context.is_some(){ 
            if let Err(err) = self.deallocate_sched_context(alloc) {
                return Err(err);
            }
        }
        if let Err(err) = alloc.cspace().free_and_delete_slot_with_object_fixed(&self.tcb, alloc){
            return Err(ThreadError::CSpaceAllocationError { details: err })
        }
        self.tcb = Thread::from_cap(0);
        Ok(())
    }
}

impl WrappedThread for BaseThread {
    #[inline(always)]
    fn get_base_thread(&self) -> &BaseThread {
        unimplemented!();
    }
    fn get_base_thread_mut(&mut self) -> &mut BaseThread {
        unimplemented!();
    }
    fn get_tcb(&self) -> Thread {
        self.tcb
    }
    fn bind_notification(&mut self, notification: Notification) -> Result<(), ThreadError> {
        if self.bound_notification.is_some(){
            return Err(ThreadError::AlreadySet);
        }
        if let Err(err) = self.tcb.bind_notification(notification){
            Err(ThreadError::SyscallError { details: err })
        }else{
            self.bound_notification = Some(notification);
            Ok(())
        }
    }
    fn unbind_notification(&mut self) -> Result<Notification, ThreadError> {
        if self.bound_notification.is_none(){
            return Err(ThreadError::Unset);
        }
        if let Err(err) = self.tcb.unbind_notification(){
            Err(ThreadError::SyscallError { details: err })
        }else{
            let ret = Ok(self.bound_notification.unwrap());
            self.bound_notification = None;
            ret
        }
    }
    #[inline(always)]
    fn get_bound_notification(&self) -> Option<Notification>{
        self.bound_notification
    }
    fn set_space(&mut self, config: CommonThreadConfig) -> Result<(), ThreadError>{
        if let Err(err) = self.tcb.set_space(
            config.fault_endpoint.to_cap(),
            config.cspace_root,
            config.cspace_root_data,
            config.vspace_root,
            config.vspace_root_data,
        ){
            Err(ThreadError::SyscallError { details: err })
        }else{
            self.config = Some(config);
            Ok(())
        }
    }
    #[inline(always)]
    fn get_space(&self) -> Option<CommonThreadConfig> {
        self.config
    }
    fn set_ipc_buffer(&mut self, address: seL4_Word, frame: seL4_CPtr) -> Result<(), ThreadError>{
        if address == 0 {
            self.ipc_buffer = None;
            Ok(())
        }else{
            if let Err(err) = self.tcb.set_ipc_buffer(address, frame){
                Err(ThreadError::SyscallError { details: err })
            }else{
                self.ipc_buffer = Some((frame, address));
                Ok(())
            }
        }
    }
    fn get_ipc_buffer(&self) -> Option<(seL4_Word, seL4_CPtr)> {
        self.ipc_buffer
    }
    fn configure(&mut self, config: CommonThreadConfig, ipc_buffer_addr: usize, ipc_buffer_frame: seL4_CPtr) -> Result<(), ThreadError>{
        if let Err(err) = self.set_space(config){
            return Err(err)
        }
        if let Err(err) = self.set_ipc_buffer(ipc_buffer_addr, ipc_buffer_frame){
            return Err(err);
        }
        Ok(())
    }
    fn set_sched_params<A: AllocatorBundle>(&mut self, params: SchedParams, alloc: &A) -> Result<(), ThreadError>{
        if let Err(err) = self.tcb.set_mc_priority(params.mcp) {
            return Err(ThreadError::SyscallError{ details: err } );
        }
        if let Err(err) = self.tcb.set_priority(params.priority) {
            return Err(ThreadError::SyscallError{ details: err } );
        }
        #[cfg(KernelEnableSMPSupport)]
        if let Err(err) = self.tcb.set_affinity(params.core) {
            return Err(ThreadError::SyscallError{ details: err } );
        }
        self.sched_params = Some(params);
        let res;
        if self.sched_context.is_some(){
            res = params.configure_context(self.sched_context.unwrap());
        }else{
            #[cfg(not(feature = "kobj_alloc"))]
            return Err(ThreadError::Unset);
            #[cfg(feature = "kobj_alloc")]
            {
                res = self.new_sched_context(alloc);
            }
        }
        if let Err(err) = res {
            return Err(err);
        }
        Ok(())
    }
    #[inline(always)]
    fn get_sched_params(&self) -> Option<SchedParams> {
        self.sched_params
    }
    #[cfg(feature = "kobj_alloc")]
    fn new_sched_context<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        if self.sched_context.is_some(){
            return Err(ThreadError::AlreadySet)
        }
        if self.sched_params.is_none(){
            return Err(ThreadError::Unset)
        }
        let res = self.sched_params.unwrap().new_context(alloc);
        if let Err(err) = res {
            return Err(err);
        }
        let context = res.unwrap();
        if let Err(err) = context.bind_thread(self.tcb){
            let _ = self.sched_params.unwrap().free_context(context, alloc);
            Err(ThreadError::SyscallError { details: err })
        }else{
            self.sched_context = Some(context);
            Ok(())
        }
    }
    fn deallocate_sched_context<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        if self.sched_params.is_none() && self.sched_context.is_some(){
            warn!("attempted to free scheduling context of a thread with no scheduling parameters");
            return Err(ThreadError::Unset);
        }
        if self.sched_context.is_some() {
            if let Err(err) = self.sched_params.unwrap().free_context(self.sched_context.unwrap(), alloc) {
                return Err(err);
            }
        }
        self.sched_context = None;
        Ok(())
    }

    fn bind_sched_context(&mut self, context: SchedContext) -> Result<(), ThreadError>{
        if let Err(err) = context.bind_thread(self.tcb){
            Err(ThreadError::SyscallError { details: err })
        }else{
            self.sched_params = None;
            self.sched_context = Some(context);
            Ok(())
        }
    }
    fn unbind_sched_context(&mut self) -> Result<SchedContext, ThreadError>{
        if self.sched_context.is_none(){
            return Err(ThreadError::Unset);
        }
        if let Err(err) = self.sched_context.unwrap().unbind(){
            Err(ThreadError::SyscallError{ details: err })
        }else{
            self.sched_params = None;
            let ret = Ok(self.sched_context.unwrap());
            self.sched_context = None;
            ret
        }
    }
    #[inline(always)]
    fn get_sched_context(&self) -> Option<SchedContext>{
        self.sched_context
    }
    #[cfg(feature = "kobj_alloc")]
    fn allocate_reply<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<Reply, ThreadError> {
        if self.config.is_none(){
            return Err(ThreadError::Unset);
        }
        let reply = alloc.cspace().allocate_slot_with_object_fixed::<Reply, _>(alloc);
        if reply.is_err(){
            return Err(ThreadError::CSpaceAllocationError { details: reply.unwrap_err() });
        }
        self.reply = Some(reply.unwrap());
        Ok(reply.unwrap())
    }
    #[cfg(feature = "kobj_alloc")]
    fn deallocate_reply<A: AllocatorBundle>(&mut self, alloc: &A) -> Result<(), ThreadError>{
        if self.reply.is_none() || self.config.is_none(){
            return Err(ThreadError::Unset);
        }
        if let Err(err) = alloc.cspace().free_and_delete_slot_with_object_fixed(&self.reply.unwrap(), alloc){
            Err(ThreadError::CSpaceAllocationError { details: err })
        }else{
            self.reply = None;
            Ok(())
        }
    }
    #[inline(always)]
    fn get_reply(&self) -> Option<Reply> {
        self.reply
    }
    fn set_name(&mut self, name: &str) {
        let name_copy = String::from(name);
        #[cfg(KernelDebugBuild)]
        if self.tcb.to_cap() != 0 {
           let mut c_name = name_copy.clone();
           c_name.push('\0');
           self.tcb.set_debug_name(c_name.as_bytes());
        }
        self.name = Some(name_copy);
    }
    fn get_name(&self) -> Option<String> {
        self.name.clone()
    }
}

impl Drop for BaseThread {
    fn drop(&mut self) {
        let cptr = self.tcb.to_cap();
        if cptr != 0 {
            panic!("attempted to drop BaseThread at {:p} with non-null TCB {:x}", self, cptr);
        }
    }
}
