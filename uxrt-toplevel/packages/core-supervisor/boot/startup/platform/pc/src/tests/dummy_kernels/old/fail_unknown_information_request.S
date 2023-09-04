/*
 * Copyright 2014, General Dynamics C4 Systems
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(GD_GPL)
 */

#include <multiboot2.h>

	.code32
	.global _start
.section .mbh
    /* MultiBoot header */
    .align  8
	/* magic */
	.long	MULTIBOOT2_HEADER_MAGIC
	/* architecture */
	.long MULTIBOOT_ARCHITECTURE_I386
	/* checksum */
	.long	-(MULTIBOOT2_BOOTLOADER_MAGIC + MULTIBOOT_ARCHITECTURE_I386)
	/* Information request tag (required tag types) */
	.short MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST
	/* flags */
	.short 0
	/* size */
	.long 20
	/* tag types */
	.long MULTIBOOT_TAG_TYPE_XHI_MODULE_MAPPED
	.long MULTIBOOT_TAG_TYPE_XHI_MODULE_IMAGE
	.long 0xdeadbeef

	/* Address size */
	.short MULTIBOOT_HEADER_TAG_XHI_ADDRESS_SIZE
	/* flags */
	.short 0
	/* size*/
	.long 12
	/* address size */
	.long 8

	/* Compatible environments */
	.short MULTIBOOT_HEADER_TAG_XHI_COMPATIBILITY
	/* flags */
	.short 0
	/* size*/
	.long 12
	/* environments supported */
	.long MULTIBOOT_XHI_ENV_TYPE_BAREMETAL

	/* Console flags */
	.short MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS
	/* flags */
	.short 0
	/* size*/
	.long 12
	/* console flags */
	.long MULTIBOOT_CONSOLE_FLAGS_CONSOLE_REQUIRED

	/* Use pre-mapped paging for kernel sections */
	.short MULTIBOOT_HEADER_TAG_XHI_MAP_KERNEL_SECTIONS
	/* flags */
	.short 0
	/* size*/
	.long 8

	/* Require modules to be aligned (this will always be true if booted from a 
	   single filesystem image, but specify it anyways) 
	*/
	.short MULTIBOOT_HEADER_TAG_MODULE_ALIGN
	/* flags */
	.short 0
	/* size*/
	.long 8

	.short MULTIBOOT_HEADER_TAG_END
	/* flags */
	.short 0
	/* size */
	.long 8

_start:
	jmp _start
