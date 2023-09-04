/*
 * Assembler support functions for the loader on x86
 *
 * RT/XH
 *
 * Copyright (c) 2010-2011 Andrew Warkentin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
*/
.globl cpuid
.globl init_paging_32
.globl init_paging_64
.globl jump_to_kernel_paged_32
.globl jump_to_kernel_unpaged_32
.globl jump_to_kernel_64
.globl loader_halt
	.code32

#define BOOT_CS64 0x0008 /*TODO: move this somewhere else*/
#define BOOT_DS64 0x0010 /*TODO: move this somewhere else*/

#include <multiboot2.h>
#include <cpu/processor.h>
#include <cpu/msr-index.h>

/* void cpuid() 
 * 
 **/
cpuid:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%ebx
	movl	12(%ebp), %eax
	movl	8(%ebp), %edx
	movl	%edx, (%eax)
	movl	12(%ebp), %eax
	movl	(%eax), %eax
	cpuid
	movl	12(%ebp), %esi
	movl	%eax, (%esi)
	movl	16(%ebp), %eax
	movl	%ebx, (%eax)
	movl	20(%ebp), %eax
	movl	%ecx, (%eax)
	movl	24(%ebp), %eax
	movl	%edx, (%eax)
	popl	%ebx
	popl	%esi
	popl	%ebp
	ret
/* void init_paging_32(char *page_dir)
 * 
 * Sets up paging for x86-32, but does not activate it. */
init_paging_32:
	/* enable PSE */
	movl  %cr4, %eax
	orl   $0x10, %eax
	movl  %eax, %cr4
	/*load page table*/
	movl  0x4(%esp), %eax
	movl  %eax, %cr3
	ret

/* void init_paging_64(char *pml4t)
 * 
 * Sets up paging for x86-64, but does not activate it. */
init_paging_64:
	/*load page table*/
	movl  0x4(%esp), %eax
	movl  %eax, %cr3
	/*enable PAE*/
	movl %cr4, %eax
	orl  $X86_CR4_PAE, %eax
	movl %eax, %cr4

	ret

/* void loader_halt(void)
 *
 * Hangs the system. */
loader_halt:
	jmp hang32

/* void jump_to_kernel_32(uint32_t entry_addr, char *multiboot_info)
 * 
 * Activates x86-32 paging and jumps to an x86-32 kernel. */
jump_to_kernel_paged_32:
	/*enable paging (the page table has already been loaded by 
	 * init_paging_32)*/
	/*TODO: load a GDT (it should be passed as an argument)*/

	movl %cr0, %eax
	orl  $X86_CR0_PG, %eax
	movl %eax, %cr0

jump_to_kernel_unpaged_32:
	/*place magic number in EAX*/
	movl $MULTIBOOT2_BOOTLOADER_MAGIC, %eax
	
	/*place MBI address in EBX*/
	movl 0x8(%esp), %ebx
	/*jump to the entry point*/
	call *0x4(%esp)
	/*this shouldn't happen*/
hang32:
	hlt
	jmp hang32 /*this function never returns*/

/* void init_paging_x86_64(uint64_t entry_addr, char *multiboot_info)
 * 
 * Activates x86-64 paging and jumps to an x86-64 kernel. */
jump_to_kernel_64:
	movl 0x4(%esp), %esi
	movl 0x8(%esp), %edi
	movl 0xc(%esp), %ebx

	movl 0x14(%esp), %eax
	movw %ax, gdt64_descr
	movl 0x10(%esp), %eax
	movl %eax, gdt64_descr + 2;

	lgdt gdt64_descr

	movl $MSR_EFER, %ecx
	rdmsr
	orl  $EFER_LME, %eax
	wrmsr

	movl %cr0, %eax
	orl  $X86_CR0_PG, %eax
	movl %eax, %cr0

	ljmp $(BOOT_CS64),$call_kernel_64
	.code64
call_kernel_64:
	mov $(BOOT_DS64), %ecx
	mov %ecx, %ds
	mov %ecx, %es
	mov %ecx, %fs
	mov %ecx, %gs
	mov %ecx, %ss

	movq %rsi, %rbp
	shlq $32, %rdi
	orq  %rdi, %rbp
	movq $MULTIBOOT2_BOOTLOADER_MAGIC, %rax
	jmp *%rbp
hang64:
	hlt
	jmp hang64

gdt64_descr:
	.word 0
	.quad 0
