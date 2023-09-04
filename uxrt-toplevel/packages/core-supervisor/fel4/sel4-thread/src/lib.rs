// Copyright 2022 Andrew Warkentin
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//#![doc(html_root_url = "https://doc.robigalia.org/")]
#![no_std]
#![feature(naked_functions)]
#![feature(thread_local)]
extern crate alloc;
extern crate sel4_alloc;
extern crate sel4;
extern crate sel4_sys;
extern crate sel4_thread_park;

use sel4::Notification;
use sel4_alloc::{
    AllocatorBundle,
    cspace::CSpaceManager,
};

use sel4_thread_park::Parker;

#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;
mod base_thread;
#[cfg(feature = "kobj_alloc")]
mod local_thread;
mod arch;

#[macro_export]
macro_rules! thread_debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug_thread")]
        debug!($($toks)*);
    })
}

pub use base_thread::*;
#[cfg(feature = "kobj_alloc")]
pub use local_thread::*;

#[cfg(feature = "kobj_alloc")]
pub unsafe fn init_root<A: AllocatorBundle>(alloc: &A) {
    let unpark_notification = alloc.cspace().allocate_slot_with_object_fixed::<Notification, _>(alloc).expect("could not allocate unpark notification for root thread");
    sel4_thread_park::init(Parker::new(unpark_notification));
}
