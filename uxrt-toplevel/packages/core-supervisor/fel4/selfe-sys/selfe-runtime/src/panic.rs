use core::fmt::Write;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let _res = writeln!(crate::debug::DebugOutHandle, "*** Panic: {:#?}", info);
    #[cfg(KernelDebugBuild)]
    unsafe { sel4_sys::seL4_DebugHalt(); }
    abort()
}

/// This is a separate function so there's a clean place to set an abort
/// breakpoint, for debug builds.
fn abort() -> ! {
    core::intrinsics::abort();
}
