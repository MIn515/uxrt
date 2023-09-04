// Copyright (c) 2018-2022 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright (c) 2015 The Robigalia Project Developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

use sel4_sys::{seL4_CPtr, seL4_DomainSet_Set, seL4_CapInitThreadTCB,
               seL4_TCBObject, seL4_TCB_BindNotification,
               seL4_TCB_Configure, seL4_TCB_CopyRegisters,
               seL4_TCB_ReadRegisters, seL4_TCB_Resume, seL4_TCB_SetIPCBuffer,
               seL4_TCB_SetPriority, seL4_TCB_SetSpace, seL4_TCB_SetTLSBase,
               seL4_TCB_Suspend, seL4_TCB_UnbindNotification, 
               seL4_TCB_WriteRegisters, seL4_UserContext, seL4_Word, 
               seL4_SchedContextObject, seL4_TCB_SetMCPriority, seL4_Time, 
               seL4_SchedControl_ConfigureFlags, seL4_SchedContext_Bind,
               seL4_SchedContext_Unbind, seL4_SchedContext_UnbindObject, 
               seL4_TCBBits, seL4_Bool, seL4_NumHWBreakpoints, 
               seL4_DataBreakpoint, seL4_InstructionBreakpoint, 
               seL4_BreakOnRead, seL4_BreakOnWrite, seL4_BreakOnReadWrite, 
               seL4_Error};

#[cfg(KernelEnableSMPSupport)]
use sel4_sys::seL4_TCB_SetAffinity;

#[cfg(HardwareDebugAPI)]
use sel4_sys::{seL4_TCB_GetBreakpoint, seL4_TCB_SetBreakpoint, seL4_TCB_UnsetBreakpoint,
               seL4_TCB_ConfigureSingleStepping};

#[cfg(KernelVTX)]
use sel4_sys::seL4_TCB_SetEPTRoot;

#[cfg(KernelBenchmarksTrackUtilisation)]
use sel4_sys::{seL4_BenchmarkGetThreadUtilization, seL4_BenchmarkResetThreadUtilization,
               benchmark_track_util};

#[cfg(KernelDebugBuild)]
use sel4_sys::seL4_DebugNameThread;

use {CNode, Notification, ToCap};

#[cfg(KernelVTX)]
use VCPU;

cap_wrapper!{ ()
    /// A thread control block
    Thread = seL4_TCBObject |_| 1 << seL4_TCBBits,
    /// A schedule context
    SchedContext = seL4_SchedContextObject |i| 2u32.pow(i as u32),
    /// Authority to configure SchedContexts for a specific cpu node
    SchedControl,
}

/// Thread configuration.
///
/// Set `Thread::set_space` and `Thread::set_ipc_buffer` for details about those portions of this
/// structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadConfiguration {
    pub fault_handler: seL4_Word,
    pub sched_context: SchedContext,
    pub cspace_root: CNode,
    pub cspace_root_data: seL4_Word,
    pub vspace_root: seL4_CPtr,
    pub vspace_root_data: seL4_Word,
    pub buffer: seL4_Word,
    pub buffer_frame: seL4_Word,
}

/// Breakpoint.
/// Can be either an Instruction breakpoint or Data breakpoint.
///
/// Instruction: Break when vaddr gets executed.
///
/// Data: Break when memory at [vaddr, vaddr + size] is accessed in the specified way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breakpoint {
    Instruction {
        vaddr: seL4_Word,
    },
    Data {
        vaddr: seL4_Word,
        size: seL4_Word,
        access: BreakpointAccess,
    },
}

/// Virtual memory access type that causes Data Breakpoints to be triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointAccess {
    Read,
    Write,
    ReadOrWrite,
}

impl Thread {
    /// Bind a notification object to this thread.
    #[inline(always)]
    pub fn bind_notification(&self, notification: Notification) -> ::Result {
        unsafe_as_result!(seL4_TCB_BindNotification(self.cptr, notification.to_cap()))
    }

    /// Unbind any notification object from this thread.
    #[inline(always)]
    pub fn unbind_notification(&self) -> ::Result {
        unsafe_as_result!(seL4_TCB_UnbindNotification(self.cptr))
    }

    /// Configure this thread with new parameters.
    #[inline(always)]
    pub fn configure(&self, config: ThreadConfiguration) -> ::Result {
        unsafe_as_result!(seL4_TCB_Configure(
            self.cptr,
            config.cspace_root.to_cap(),
            config.cspace_root_data,
            config.vspace_root.to_cap(),
            config.vspace_root_data,
            config.buffer,
            config.buffer_frame,
        ))
    }

    /// Configure single stepping for this thread.
    ///
    /// `bp_num`: Hardware breakpoint number to use. May or may not be used depending on
    /// hardware architecture.
    ///
    /// `num_instructions`: Number of instructions to step over before triggering breakpoint.
    /// Set to 0 to disable single stepping.
    ///
    /// Result contains an optional value. If optional value is Some(()), the hardware breakpoint
    /// was consumed and should not be used again until single stepping is disabled.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    pub fn configure_single_stepping(&self, bp_num: u16, num_instructions: seL4_Word)
                                     -> Result<Option<()>, ::Error> {
        debug_assert!(bp_num > 0 && (bp_num as usize) < seL4_NumHWBreakpoints as usize);
        let res = unsafe { seL4_TCB_ConfigureSingleStepping(self.cptr, bp_num, num_instructions) };
        if res.error == 0 {
            if res.bp_was_consumed != 0 {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        } else {
            Err(::Error::from_ipcbuf(res.error as seL4_Error))
        }
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
    pub fn copy_registers(&self, dest: Thread, suspend_source: bool, resume_dest: bool,
                          transfer_frame: bool, transfer_integer: bool, arch_flags: u8)
                          -> ::Result {
        unsafe_as_result!(seL4_TCB_CopyRegisters(
            dest.cptr,
            self.cptr,
            suspend_source as seL4_Bool,
            resume_dest as seL4_Bool,
            transfer_frame as seL4_Bool,
            transfer_integer as seL4_Bool,
            arch_flags,
        ))
    }

    /// Returns the breakpoint previously set on this thread for `bp_num`.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    pub fn get_breakpoint(&self, bp_num: u16) -> Result<Option<Breakpoint>, ::Error> {
        debug_assert!(bp_num > 0 && (bp_num as usize) < seL4_NumHWBreakpoints as usize);
        let bp = unsafe { seL4_TCB_GetBreakpoint(self.cptr, bp_num) };

        if bp.error == 0 {
            if bp.is_enabled != 0 {
                if bp.type_ == seL4_InstructionBreakpoint {
                    Ok(Some(Breakpoint::Instruction {
                        vaddr: bp.vaddr,
                    }))
                } else if bp.type_ == seL4_DataBreakpoint {
                    let access = if bp.rw == seL4_BreakOnRead {
                        BreakpointAccess::Read
                    } else if bp.rw == seL4_BreakOnWrite {
                        BreakpointAccess::Write
                    } else if bp.rw == seL4_BreakOnReadWrite {
                        BreakpointAccess::ReadOrWrite
                    } else {
                        panic!("Unknown breakpoint access type {}", bp.rw);
                    };
                    Ok(Some(Breakpoint::Data {
                        vaddr: bp.vaddr,
                        size: bp.size,
                        access,
                    }))
                } else {
                    panic!("Unknown breakpoint type {}", bp.type_);
                }
            } else {
                Ok(None)
            }
        } else {
            Err(::Error::from_ipcbuf(bp.error as seL4_Error))
        }
    }

    /// Returns this thread's utilization counters.
    ///
    /// Only available when KernelBenchmarksTrackUtilisation is set.
    #[cfg(KernelBenchmarksTrackUtilisation)]
    #[inline(always)]
    pub fn get_utilization(&self) -> benchmark_track_util {
        unsafe { seL4_BenchmarkGetThreadUtilization(self.cptr) }
    }

    /// Read this thread's registers.
    ///
    /// If `suspend`, suspend this thread before copying.
    #[inline(always)]
    pub fn read_registers(&self, suspend: bool, arch_flags: u8)
                          -> Result<seL4_UserContext, ::Error> {
        // unsafe: mem: maybe use a Default::default() ?
        let mut regs = unsafe { ::core::mem::zeroed() };

        unsafe_as_result!(seL4_TCB_ReadRegisters(
            self.cptr,
            suspend as seL4_Bool,
            arch_flags,
            (::core::mem::size_of::<seL4_UserContext>() /
                ::core::mem::size_of::<usize>()) as seL4_Word,
            &mut regs,
        )).map(|()| regs)
    }

    /// Resets this thread's utilization counters.
    ///
    /// Only available when KernelBenchmarksTrackUtilisation is set.
    #[cfg(KernelBenchmarksTrackUtilisation)]
    #[inline(always)]
    pub fn reset_utilization(&self) {
        unsafe { seL4_BenchmarkResetThreadUtilization(self.cptr) };
    }

    /// Resume this thread
    #[inline(always)]
    pub fn resume(&self) -> ::Result {
        unsafe_as_result!(seL4_TCB_Resume(self.cptr))
    }

    /// Set the CPU core that this thread will run on.
    ///
    /// Only available when CONFIG_MAX_NUM_NODES > 1.
    #[cfg(KernelEnableSMPSupport)]
    #[inline(always)]
    pub fn set_affinity(&self, affinity: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_TCB_SetAffinity(self.cptr, affinity))
    }

    /// Set one of this thread's breakpoints. Overwrites any existing breakpoint.
    ///
    /// `bp_num` is the breakpoint number to set. Must be >= 0 and < seL4_NumHWBreakpoints.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    pub fn set_breakpoint(&self, bp_num: u16, bp: Breakpoint) -> ::Result {
        debug_assert!(bp_num > 0 && (bp_num as usize) < seL4_NumHWBreakpoints as usize);
        match bp {
            Breakpoint::Instruction { vaddr } =>
                unsafe_as_result!(seL4_TCB_SetBreakpoint(self.cptr,
                                                         bp_num,
                                                         vaddr,
                                                         seL4_InstructionBreakpoint,
                                                         0,
                                                         0)),
            Breakpoint::Data { vaddr, size, access } => {
                let rw;
                match access {
                    BreakpointAccess::Read => rw = seL4_BreakOnRead,
                    BreakpointAccess::Write => rw = seL4_BreakOnWrite,
                    BreakpointAccess::ReadOrWrite => rw = seL4_BreakOnReadWrite,
                }
                unsafe_as_result!(seL4_TCB_SetBreakpoint(self.cptr,
                                                         bp_num,
                                                         vaddr,
                                                         seL4_DataBreakpoint,
                                                         size,
                                                         rw))
            },
        }
    }

    /// Sets the name for this thread used by the kernel when printing debug output.
    ///
    /// Only available when KernelDebugBuild is set.
    #[cfg(KernelDebugBuild)]
    #[inline(always)]
    pub fn set_debug_name(&self, name: &[u8]) {
        unsafe { seL4_DebugNameThread(self.cptr, name.as_ptr() as *const i8) };
    }

    /// Sets the VCPU for this thread
    ///
    /// Only available when KernelVTX is set
    #[cfg(KernelVTX)]
    #[inline(always)]
    pub fn set_ept_root(&self, vcpu: VCPU) -> ::Result {
        unsafe_as_result!(seL4_TCB_SetEPTRoot(self.cptr, vcpu.to_cap()))
    }

    /// Set this thread's IPC buffer.
    ///
    /// `address` is where in the virtual address space the IPC buffer will be located, and `frame`
    /// is a capability to the physical memory that will back that page.  `address` must be
    /// naturally aligned to 512-bytes.
    #[inline(always)]
    pub fn set_ipc_buffer(&self, address: seL4_Word, frame: seL4_CPtr) -> ::Result {
        unsafe_as_result!(seL4_TCB_SetIPCBuffer(self.cptr, address, frame))
    }

    /// Set this thread's maximum controlled priority.
    ///
    /// This can only set the MCPriority to lower or equal to the MCPrority of the thread that
    /// makes this request.
    #[inline(always)]
    pub fn set_mc_priority(&self, priority: u8) -> ::Result {
        unsafe_as_result!(seL4_TCB_SetMCPriority(self.cptr, seL4_CapInitThreadTCB.into(), priority.into()))
    }

    /// Set this thread's priority.
    ///
    /// This can only set the priority to lower or equal to the maximum controlled priority
    /// of the thread that makes this request.
    #[inline(always)]
    pub fn set_priority(&self, priority: u8) -> ::Result {
        unsafe_as_result!(seL4_TCB_SetPriority(self.cptr, seL4_CapInitThreadTCB.into(), priority.into()))
    }

    /// Set this thread's fault endpoint, CSpace, and VSpace.
    ///
    /// The fault endpoint is a CPtr interpreted in the new CSpace.
    ///
    /// The CSpace root data is the new guard and guard size of the new root CNode, though if it's
    /// zero it is ignored.
    ///
    /// The VSpace root data is ignored on x86 and ARM.
    #[inline(always)]
    pub fn set_space(&self, fault_endpoint: seL4_CPtr, cspace_root: CNode,
                     cspace_root_data: seL4_Word, vspace_root: seL4_CPtr,
                     vspace_root_data: seL4_Word)
                     -> ::Result {
        unsafe_as_result!(seL4_TCB_SetSpace(
            self.cptr,
            fault_endpoint,
            cspace_root.to_cap(),
            cspace_root_data,
            vspace_root,
            vspace_root_data,
        ))
    }

    /// Suspend this thread.
    #[inline(always)]
    pub fn suspend(&self) -> ::Result {
        unsafe_as_result!(seL4_TCB_Suspend(self.cptr))
    }

    /// Disable hardware breakpoint and clear underlying hardware registers.
    ///
    /// Only available when HardwareDebugAPI is set.
    #[cfg(HardwareDebugAPI)]
    #[inline(always)]
    pub fn unset_breakpoint(&self, bp_num: u16) -> ::Result {
        debug_assert!(bp_num > 0 && (bp_num as usize) < seL4_NumHWBreakpoints as usize);
        unsafe_as_result!(seL4_TCB_UnsetBreakpoint(self.cptr, bp_num))
    }

    /// Set this thread's registers from the provided context.
    ///
    /// If `resume`, resume this thread after writing.
    #[inline(always)]
    pub fn write_registers(&self, resume: bool, arch_flags: u8, regs: &seL4_UserContext)
                           -> ::Result {
        unsafe_as_result!(seL4_TCB_WriteRegisters(
            self.cptr,
            resume as seL4_Bool,
            arch_flags,
            (::core::mem::size_of::<seL4_UserContext>() /
                ::core::mem::size_of::<usize>()) as seL4_Word,
            regs as *const seL4_UserContext as *mut _,
        ))
    }

    /// Set this thread's domain.
    #[inline(always)]
    pub fn set_domain(&self, domain: u8, domain_control: ::DomainSet) -> ::Result {
        unsafe_as_result!(seL4_DomainSet_Set(domain_control.to_cap(), domain, self.cptr))
    }
    /// Set this thread's TLS base address.
    #[inline(always)]
    pub fn set_tls_base(&self, base: usize) -> ::Result{
        unsafe_as_result!(seL4_TCB_SetTLSBase(self.cptr, base))
    }
}

impl SchedControl {
    /// Sets the parameters of a scheduling context.
    ///
    /// If `sched_context` is bound to an active thread the changes take effect immediately.
    /// This could result in active threads being postponed or released.
    ///
    /// If `sched_context` was previously empty but bound to a runnable thread, this could
    /// result in a thread running for the first time.
    ///
    /// Will fail with InvalidArgument if parameters are too large or too small to fit in
    /// the kernel WCET for this platform.
    #[inline(always)]
    pub fn configure(&self, sched_context: SchedContext, budget: seL4_Time, period: seL4_Time,
                     extra_refills: seL4_Word, badge: seL4_Word, flags: seL4_Word) -> ::Result {
        unsafe_as_result!(seL4_SchedControl_ConfigureFlags(self.cptr,
                                                      sched_context.to_cap(),
                                                      budget,
                                                      period,
                                                      extra_refills,
                                                      badge,
                                                      flags))
    }
}

impl SchedContext {
    #[inline(always)]
    /// Binds the scheduling context to a thread.
    ///
    /// May cause the thread to start running if it is in a runnable state and
    /// the scheduling context has available budget.
    ///
    /// Results in an error if the scheduling context is already bound.
    pub fn bind_thread(&self, thread: Thread) -> ::Result {
        unsafe_as_result!(seL4_SchedContext_Bind(self.cptr, thread.to_cap()))
    }

    /// Binds the scheduling context to a notification.
    ///
    /// A passive thread will obtain the scheduling context when signaled by the
    /// notification and return the scheduling context when waiting on the notification.
    #[inline(always)]
    pub fn bind_notification(&self, ntfn: Notification) -> ::Result {
        unsafe_as_result!(seL4_SchedContext_Bind(self.cptr, ntfn.to_cap()))
    }

    /// Unbinds all objects from the scheduling context.
    ///
    /// If bound to a thread it becomes a passive thread.
    #[inline(always)]
    pub fn unbind(&self) -> ::Result {
        unsafe_as_result!(seL4_SchedContext_Unbind(self.cptr))
    }

    /// Unbinds the thread from the scheduling context.
    ///
    /// If the thread is bound to the scheduling context, the given thread
    /// becomes a passive thread.
    ///
    /// If the thread received the scheduling context via donation over IPC, the
    /// scheduling context will be returned to the thread that it was originally
    /// bound to.
    #[inline(always)]
    pub fn unbind_thread(&self, thread: Thread) -> ::Result {
        unsafe_as_result!(seL4_SchedContext_UnbindObject(self.cptr, thread.to_cap()))
    }

    /// Unbinds the notification from the scheduling context.
    #[inline(always)]
    pub fn unbind_notification(&self, ntfn: Notification) -> ::Result {
        unsafe_as_result!(seL4_SchedContext_UnbindObject(self.cptr, ntfn.to_cap()))
    }
}
