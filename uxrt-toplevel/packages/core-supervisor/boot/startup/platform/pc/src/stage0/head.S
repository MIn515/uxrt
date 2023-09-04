/*
 * Platform-dependent part of startup0
 * 
 * Copyright (C) 2022 Andrew Warkentin
 *
 * Derived from libpayload's arch/x86/head.S 
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
	.global _entry, _img_start, _img_end, hang, start_stage1, stage0_putchar, stage0_main
	.text
	.align 4

/*
 * Our entry point - assume that the CPU is in 32 bit protected mode and
 * all segments are in a flat model. That's our operating mode, so we won't
 * change anything.
 */
_entry:
	jmp _init

#include <multiboot2.h>

mb_header:
	.align  8
	__mbh_start:
	/* magic multi-boot 2 header */
	.long   MULTIBOOT2_HEADER_MAGIC
	.long   MULTIBOOT_ARCHITECTURE_I386
	.long   (__mbi_end - __mbh_start)
	.long  -(MULTIBOOT2_HEADER_MAGIC + (__mbi_end - __mbh_start))

	__addr_tag_start:
	/* address tag */
	.word MULTIBOOT_HEADER_TAG_ADDRESS
	/* flags */
	.word 0
	/* size */
	.long __addr_tag_end - __addr_tag_start
	/* header address */
	.long __mbh_start
	/* the next two will be filled in by updatembh */
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
	/* entry address tag */
	.word MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS
	/* flags */
	.word 0
	/* size */
	.long __entry_tag_end - __entry_tag_start
	/* entry address */
	.long _entry
	/* padding */
	.long 0
	__entry_tag_end:
	/* end tag - type, flags, size */
	.word   MULTIBOOT_HEADER_TAG_END
	.word   0x0
	.long   0x8
	__mbi_end:  

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

	movl %eax,%edx

	/* Clear the bss */
	cld
	movl $.bss, %edi
	movl $_end, %ecx
	subl %edi, %ecx
	xor %ax, %ax
	rep stosb

        /* Store EAX and EBX */
        movl %edx,loader_eax
        movl %ebx,loader_ebx

	/* Setup new stack. */
	movl $_stack, %ebx

	movl %ebx, %esp

	/* Save old stack pointer. */
	pushl %esi

	/* Let's rock. */
	call stage0_main
	/* main should never return */
hang:
        hlt
	jmp hang
start_stage1:
	movl loader_eax,%eax
	movl loader_ebx,%ebx
	movl $MULTIBOOT2_XRFS_HEADER_MAGIC0, %ecx
	movl $_img_start, %edi
	movl (%edi), %edx
	jmp *entry
stage0_putchar:
	movw 4(%esp), %dx
	movw $0x3f8, %dx
	outb %al, %dx
	ret
