/* Copyright (c) 2022 Andrew Warkentin
 *
 * Based on code from Robigalia:
 * Copyright (c) 2015 The Robigalia Project Developers
 *
 * Licensed under the Apache License, Version 2.0
 * <LICENSE-APACHE or
 * http://www.apache.org/licenses/LICENSE-2.0> or the MIT
 * license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
 * at your option. All files in the project carrying such
 * notice may not be copied, modified, or distributed except
 * according to those terms.
 */

#![no_std]
#![feature(lang_items, core_intrinsics, naked_functions, asm_sym, asm_const)]
extern crate selfe_runtime;
extern crate sel4_sys;

pub use selfe_runtime::debug::DebugOutHandle;

use core::fmt::Write;
use core::panic::PanicInfo;
use sel4_sys::*;
use sel4_sys::tls;

pub static mut BOOTINFO: *mut seL4_BootInfo = 0 as *mut seL4_BootInfo;
static mut RUN_ONCE: bool = false;

#[lang = "termination"]
#[cfg(not(test))]
pub trait Termination {
    fn report(self) -> i32;
}

#[cfg(not(test))]
impl Termination for () {
    fn report(self) -> i32 {
        0
    }
}

#[doc(hidden)]
#[no_mangle]
/// Internal function which sets up the global `BOOTINFO`. Can only be called
/// once - it sets a private flag when it is called and will not modify
/// `BOOTINFO` if that flag is set.
pub unsafe extern "C" fn __sel4_start_init_boot_info(bootinfo: *mut seL4_BootInfo) {
    if !RUN_ONCE {
        BOOTINFO = bootinfo;
        RUN_ONCE = true;
        tls::init_root(bootinfo);
    }
}

#[lang = "start"]
#[cfg(not(test))]
pub fn lang_start<T: Termination + 'static>(
    main: fn() -> T,
    _argc: isize,
    _argv: *const *const u8,
) -> isize {
    main();
    0
}

#[allow(unused)]
pub fn debug_panic_handler(info: &PanicInfo) -> ! {
    let _res = writeln!(DebugOutHandle, "*** Panic: {:#?}", info);

    unsafe {
        core::intrinsics::abort();
    }
}

#[lang = "eh_personality"]
#[cfg(not(test))]
pub fn eh_personality() {
    core::intrinsics::abort();
}

/// Returns the address of the bottom of the stack for the initial root task
/// thread.
pub fn get_stack_bottom_addr() -> usize {
    unsafe { (&(STACK.stack)).as_ptr() as usize }
}

#[cfg(target_arch = "x86")]
include!("x86.rs");

#[cfg(target_arch = "x86_64")]
include!("x86_64.rs");

#[cfg(all(target_arch = "arm", target_pointer_width = "32"))]
include!("arm.rs");

#[cfg(target_arch = "aarch64")]
include!("arm64.rs");

#[used]
#[doc(hidden)]
/// The stack for our initial root task thread.
/// Located in the root task image data section.
///
/// The stack structure is defined in the platform-specific file since its
/// alignment is platform-dependent.
static mut STACK: Stack = Stack {
    stack: [0u8; CONFIG_SELFE_ROOT_STACK as usize],
};
