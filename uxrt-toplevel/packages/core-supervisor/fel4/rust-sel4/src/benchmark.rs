// Copyright (c) 2018-2022 Andrew Warkentin
//
// Based on code from Robigalia:
//
// Copyright (c) 2017 The Robigalia Project Developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

#[cfg(any(KernelBenchmarksTracepoints,
          KernelBenchmarksTrackKernelEntries))]
use core::slice;

use sel4_sys::{seL4_BenchmarkResetLog, seL4_BenchmarkFinalizeLog,
               seL4_BenchmarkNullSyscall, seL4_BenchmarkFlushCaches};

#[cfg(KernelBenchmarksTracepoints)]
use sel4_sys::benchmark_tracepoint_log_entry;

#[cfg(KernelBenchmarksTrackKernelEntries)]
use sel4_sys::benchmark_syscall_log_entry;

#[cfg(any(KernelBenchmarksTracepoints,
          KernelBenchmarksTrackKernelEntries))]
use sel4_sys::seL4_BenchmarkSetLogBuffer;

#[cfg(any(KernelBenchmarksTracepoints,
          KernelBenchmarksTrackKernelEntries))]
use {FromCap, LargePage, ToCap};

/// Provides access to the kernel tracepoint log.
///
/// Note: For this feature to be useful the kernel must be modified to contain tracepoints.
///
/// Only available if KernelBenchmarksTracepoints is set.
#[cfg(KernelBenchmarksTracepoints)]
pub struct TracepointLog {
    addr: usize,
}

#[cfg(KernelBenchmarksTracepoints)]
impl TracepointLog {
    /// Registers `buffer` with the kernel for the tracepoint log.
    ///
    /// `buffer` must be mapped at `addr` and allocated from non-device untyped memory.
    pub fn new(addr: usize, buffer: LargePage) -> Result<Self, ::Error> {
        let res = unsafe { seL4_BenchmarkSetLogBuffer(buffer.to_cap()) };
        if res == 0 {
            Ok(TracepointLog {
                addr,
            })
        } else {
            Err(::Error::from_ipcbuf(res))
        }
    }

    /// Starts kernel logging at the beginning of the buffer.
    pub fn start(&self) -> ::Result {
        unsafe_as_result!(seL4_BenchmarkResetLog())
    }

    /// Stops kernel logging and returns the log entries.
    pub fn stop(&self) -> Option<&[benchmark_tracepoint_log_entry]> {
        let index = unsafe { seL4_BenchmarkFinalizeLog() };
        if index > 0 {
            Some(unsafe { slice::from_raw_parts(self.addr as *mut benchmark_tracepoint_log_entry,
                                                index + 1)
            })
        } else {
            None
        }
    }
}

/// Provides access to the kernel syscall log.
///
/// Only available if KernelBenchmarksTrackKernelEntries is set.
#[cfg(KernelBenchmarksTrackKernelEntries)]
pub struct SyscallLog {
    addr: usize,
}

#[cfg(KernelBenchmarksTrackKernelEntries)]
impl SyscallLog {
    /// Registers `buffer` with the kernel for the syscall log.
    ///
    /// `buffer` must be mapped at `addr` and allocated from non-device untyped memory.
    pub fn new(addr: usize, buffer: LargePage) -> Result<Self, ::Error> {
        let res = unsafe { seL4_BenchmarkSetLogBuffer(buffer.to_cap()) };
        if res == 0 {
            Ok(SyscallLog {
                addr,
            })
        } else {
            Err(::Error::from_ipcbuf(res))
        }
    }

    /// Starts kernel logging at the beginning of the buffer.
    pub fn start(&self) -> ::Result {
        unsafe_as_result!(seL4_BenchmarkResetLog())
    }

    /// Stops kernel logging and returns the log entries.
    pub fn stop(&self) -> Option<&[benchmark_syscall_log_entry]> {
        let index = unsafe { seL4_BenchmarkFinalizeLog() };
        if index > 0 {
            Some(unsafe { slice::from_raw_parts(self.addr as *mut benchmark_syscall_log_entry,
                                                index + 1)
            })
        } else {
            None
        }
    }
}

/// Provides access to kernel thread utilization tracking.
///
/// Only available if KernelBenchmarksTrackUtilisation is set.
#[cfg(KernelBenchmarksTrackUtilisation)]
pub struct UtilizationLog {
}

#[cfg(KernelBenchmarksTrackUtilisation)]
impl UtilizationLog {
    /// Resets benchmark and current thread start time, resets idle thread utilization, and
    /// starts tracking utilization.
    ///
    /// DOES NOT reset individual thread utilization. Call Thread::reset_utilization
    /// on tracked threads first before calling this function.
    pub fn start() -> ::Result {
        unsafe_as_result!(seL4_BenchmarkResetLog() as isize)
    }

    /// Set benchmark end time to current type and stops tracking thread utilization.
    /// Does not reset any counters.
    pub fn stop() {
        unsafe { seL4_BenchmarkFinalizeLog(); }
    }
}

pub fn null_syscall() {
    unsafe { seL4_BenchmarkNullSyscall() };
}

pub fn flush_caches() {
    unsafe { seL4_BenchmarkFlushCaches() };
}
