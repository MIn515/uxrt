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


///A library for parking and unparking threads.

extern crate sel4;
extern crate sel4_sys;

//#[macro_use]
extern crate log;

extern crate alloc;
use core::sync::atomic::{
    AtomicI8,
    Ordering::{
        Acquire,
        Relaxed,
        Release,
    },
};
use core::time::Duration;
use alloc::sync::Arc;
use sel4::Notification;

/*macro_rules! debug_println {
    ($($toks:tt)*) => ({
        #[cfg(feature = "debug")]
        info!($($toks)*);
    })
}*/

//static PARK_COUNT: AtomicUsize = AtomicUsize::new(0);

#[thread_local]
static mut PARKER: Option<Arc<Parker>> = None;

pub unsafe fn init(parker: Arc<Parker>){
    PARKER = Some(parker);
}

pub fn park(){
    unsafe {
        if let Some(parker) = PARKER.clone(){
            parker.park();
        }else{
            panic!("no parker for thread; address {:p}", &PARKER);
        }
    }
}

const EMPTY: i8 = 0;
const PARKED: i8 = -1;
const NOTIFIED: i8 = 1;

// This is based on the wait flag thread parker from the standard library.

pub struct Parker {
    state: AtomicI8,
    notification: Notification,
}

impl Parker {
    pub fn new(notification: Notification) -> Arc<Parker> {
        Arc::new(Parker {
            state: AtomicI8::new(EMPTY),
            notification
        })
    }

    pub unsafe fn park(&self) {
        /*if PARK_COUNT.fetch_add(1, Relaxed) > 500{
            panic!("attempted to park thread; remove this when no longer needed");
        }*/
        match self.state.fetch_sub(1, Acquire) {
            // NOTIFIED => EMPTY
            NOTIFIED => return,
            // EMPTY => PARKED
            EMPTY => (),
            _ => panic!("inconsistent park state"),
        }

        // Avoid waking up from spurious wakeups (these are quite likely, see below).
        loop {
            self.notification.wait();

            match self.state.compare_exchange(NOTIFIED, EMPTY, Acquire, Relaxed) {
                Ok(_) => return,
                Err(PARKED) => (),
                Err(_) => panic!("inconsistent park state"),
            }
        }
    }

    pub unsafe fn park_timeout(&self, _dur: Duration) {
        unimplemented!();
/*        match self.state.fetch_sub(1, Acquire) {
            NOTIFIED => return,
            EMPTY => (),
            _ => panic!("inconsistent park state"),
        }

        self.wait_flag.wait_timeout(dur);

        // Either a wakeup or a timeout occurred. Wakeups may be spurious, as there can be
        // a race condition when `unpark` is performed between receiving the timeout and
        // resetting the state, resulting in the eventflag being set unnecessarily. `park`
        // is protected against this by looping until the token is actually given, but
        // here we cannot easily tell.

        // Use `swap` to provide acquire ordering.
        match self.state.swap(EMPTY, Acquire) {
            NOTIFIED => (),
            PARKED => (),
            _ => panic!("inconsistent park state"),
        }
*/
    }

    pub fn unpark(&self) {
        let state = self.state.swap(NOTIFIED, Release);

        if state == PARKED {
            self.notification.signal();
        }
    }
}

pub struct UnparkHandle {
    parker: Arc<Parker>
}

impl UnparkHandle {
    pub fn current() -> UnparkHandle {
        if let Some(parker) = unsafe { PARKER.clone() }{
            UnparkHandle {
                parker
            }
        }else{
            panic!("no parker for thread; address {:p}", unsafe {&PARKER});
        }
    }
    pub fn unpark(&self) {
        self.parker.unpark();
    }
}
