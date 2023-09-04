/*
 * This file is part of the libpayload project.
 *
 * Copyright (C) 2008 Advanced Micro Devices, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

	.code32
	.global _entry, _leave
	.text
	.align 4

#include <libpayload-config.h>

/*
 * Our entry point - assume that the CPU is in 32 bit protected mode and
 * all segments are in a flat model. That's our operating mode, so we won't
 * change anything.
 */
_entry:
	jmp _init

	.align 4

#ifdef MULTIBOOT_INCLUDE_HEADER
#include <multiboot2_tables.h>
#define MB1_MAGIC 0x1BADB002
#define MB1_FLAGS 0x00010003

mb1_header:
	.long MB1_MAGIC
	.long MB1_FLAGS
	.long -(MB1_MAGIC + MB1_FLAGS)
	.long mb_header
	.long _start
	.long _edata
	.long _end
	.long _init

mb2_header:
	.align  8
	__mbh_start:
	/* magic multi-boot 2 header */
	.long   MULTIBOOT2_HEADER_MAGIC
	.long   MULTIBOOT_ARCHITECTURE_I386
	.long   (__mbh_end - __mbh_start)
	.long  -(MULTIBOOT2_HEADER_MAGIC + (__mbh_end - __mbh_start))
	__addr_tag_start:
	/* address tag */
	.short MULTIBOOT_HEADER_TAG_ADDRESS
	/* flags */
	.word 0
	/* size */
	.long __addr_tag_end - __addr_tag_start
	/* the next three will be filled in by updatembh */
	/* header address */
	.long 0
	/* load start address */
	_img_start:
	.long 0
	/* load end address */
	_img_end:
	.long 0
	/* bss address (not used) */
	.long 0
	__addr_tag_end:
	__entry_tag_start:
	/* address tag */
	.short MULTIBOOT_HEADER_TAG_ADDRESS
	/* flags */
	.word 0
	/* size */
	.long __entry_tag_end - __entry_tag_start
	/* entry address */
	.long _entry
	/* load address */
	__entry_tag_end:
	/* end tag - type, flags, size */
	.word   MULTIBOOT_HEADER_TAG_END
	.word   0x0
	.long   0x8
	__mbh_end:
#endif
/*
 * This function saves off the previous stack and switches us to our
 * own execution environment.
 */
_init:
	/* No interrupts, please. */
	cli

	/* There is a bunch of stuff missing here to take arguments on the stack
	 * See http://www.coreboot.org/Payload_API and exec.S.
	 */
	/* Store current stack pointer. */
	movl %esp, %esi

	/* Store EAX and EBX */
	movl %eax,loader_eax
	movl %ebx,loader_ebx
	movl %ecx,loader_ecx
	movl %edx,loader_edx

	/* Clear the bss */
	cld
	movl $.bss, %edi
	movl $_end, %ecx
	subl %edi, %ecx
	xor %ax, %ax
	rep stosb

	/* Setup new stack. */
	movl $_stack, %ebx

	movl %ebx, %esp

	/* Save old stack pointer. */
	pushl %esi

	/* Let's rock. */
	call start_main

	/* %eax has the return value - pass it on unmolested */
_leave:
	/* Get old stack pointer. */
	popl %ebx

	/* Restore old stack. */
	movl %ebx, %esp

	/* Return to the original context. */
	ret
