// Copyright 2022 Andrew Warkentin
//
// Thread entry point based on that of Tifflin (licensed under the 2-clause
// BSD license):
//
// Copyright (c) 2014, John Hodge (thePowersGang)
//
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//TODO: add documentation comments

use sel4_sys::seL4_UserContext;
use crate::{
    LocalThread,
    ThreadError,
    thread_debug_println,
};

const STACK_ALIGN: usize = 16;

impl LocalThread {
    pub(crate) fn get_stack_align(&self) -> usize {
        STACK_ALIGN
    }
    pub(crate) fn setup_local_user_context<F: FnMut() + Send + 'static>(&mut self, f: F) -> Result<seL4_UserContext, ThreadError>{
        self.initial_stack_pointer = self.initial_stack_pointer & !(STACK_ALIGN - 1);
        self.initial_stack_pointer -= ::core::mem::size_of::<F>();
        thread_debug_println!("initial stack pointer after closure: {:x}", self.initial_stack_pointer);
        let f_ptr = self.initial_stack_pointer;

        // SAFE: Pointer is valid
        unsafe {
            ::core::ptr::write(f_ptr as *mut F, f);
        }

        self.initial_stack_pointer = self.initial_stack_pointer & !(STACK_ALIGN - 1);
        self.initial_stack_pointer -= core::mem::size_of::<usize>();

        extern "C" fn thread_root<F: FnMut() + Send + 'static>(code_ptr: &mut F) {
            code_ptr();
            panic!("thread_root: shouldn't get here");
        }

        thread_debug_println!("initial stack pointer at end of setup: {:x}", self.initial_stack_pointer);

        Ok(seL4_UserContext {
            rip: thread_root::<F> as usize,
            rsp: self.initial_stack_pointer,
            rflags: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: f_ptr as usize,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            fs_base: 0,
            gs_base: 0,
        })
    }
}
