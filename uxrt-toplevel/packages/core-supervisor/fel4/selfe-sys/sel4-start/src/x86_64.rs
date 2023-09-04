/* Copyright (c) 2022 Andrew Warkentin
 *
 * Based on code from Robigalia:
 * Copyright (c) 2017 The Robigalia Project Developers
 *
 * Licensed under the Apache License, Version 2.0
 * <LICENSE-APACHE or
 * http://www.apache.org/licenses/LICENSE-2.0> or the MIT
 * license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
 * at your option. All files in the project carrying such
 * notice may not be copied, modified, or distributed except
 * according to those terms.
 */

use core::arch::{asm, global_asm};

static STACK_BOTTOM: &[u8; CONFIG_SELFE_ROOT_STACK as usize] = unsafe { &(STACK.stack) };

#[doc(hidden)]
#[naked]
#[no_mangle]
#[cfg(not(test))]
pub unsafe extern "C" fn _setup_stack() -> () {
    // setup stack pointer
    // don't mess up rdi which we need next
    asm!(
        "movq {0}, %rsp",
        "addq ${1}, %rsp",
        "movq $0xdeadbeef, %rbp",
        "jmp _sel4_start",
        sym STACK_BOTTOM,
        const CONFIG_SELFE_ROOT_STACK as usize,
        options(noreturn, att_syntax)
    );
}

#[cfg(not(test))]
global_asm!(r###"
.global _sel4_start
.global _start
.text

_start:
    jmp _setup_stack
_sel4_start:
    /* Setup the global "bootinfo" structure. */
    call    __sel4_start_init_boot_info

    /* N.B. rsp MUST be aligned to a 16-byte boundary when main is called.
     * Insert or remove padding here to make that happen.
     */
    pushq $0
    /* Null terminate auxv */
    pushq $0
    pushq $0
    /* Null terminate envp */
    pushq $0
    /* add at least one environment string (why?) */
    leaq environment_string, %rax
    pushq %rax
    /* Null terminate argv */
    pushq $0
    /* Give an argv[0] (why?) */
    leaq prog_name, %rax
    pushq %rax
    /* Give argc */
    pushq $1
    /* No atexit */
    movq $0, %rdx

    /* Now go to the "main" stub that rustc generates */
    call main

    /* if main returns, die a loud and painful death. */
    ud2

    .data
    .align 4

environment_string:
    .asciz "seL4=1"
prog_name:
    .asciz "rootserver"

    .bss
    .align  4096
"###, options(att_syntax));

#[repr(align(4096))]
#[doc(hidden)]
/// A wrapper around our stack so that we can specify its alignment requirement.
struct Stack {
    stack: [u8; CONFIG_SELFE_ROOT_STACK as usize],
}

