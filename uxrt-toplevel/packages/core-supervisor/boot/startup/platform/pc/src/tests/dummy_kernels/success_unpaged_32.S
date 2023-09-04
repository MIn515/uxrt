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
mbh_start:
	/* magic */
	.long	MULTIBOOT2_HEADER_MAGIC
	/* architecture */
	.long MULTIBOOT_ARCHITECTURE_I386
	/* header size */
	.long mbh_end - mbh_start
	/* checksum */
	.long	-(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT_ARCHITECTURE_I386 + (mbh_end - mbh_start))
	/* Information request tag (required tag types) */
	.short MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST
	/* flags */
	.short 0
	/* size */
	.long 20
	/* tag types */
	.long MULTIBOOT_TAG_TYPE_XHI_MODULE_EXEC
	.long MULTIBOOT_TAG_TYPE_XHI_MODULE_IMAGE
	.long MULTIBOOT_TAG_TYPE_XHI_CMDLINE_ARGV

	/* Address size */
	.short MULTIBOOT_HEADER_TAG_XHI_ADDRESS_SIZE
	/* flags */
	.short 0
	/* size*/
	.long 12
	/* address size */
	.long 4

	/* Compatible environments */
	.short MULTIBOOT_HEADER_TAG_XHI_COMPATIBILITY
	/* flags */
	.short 0
	/* size*/
	.long 20
	/* hypervisor interface version */
	.long 0
	/* minimum hypervisor interface version */
	.long 0
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

	/* Require modules to be aligned (this will always be true if booted from a 
	   single filesystem image, but specify it anyways) 
	*/
	.short MULTIBOOT_HEADER_TAG_MODULE_ALIGN
	/* flags */
	.short 0
	/* size*/
	.long 8

	/* Bogus optional tag (should be ignored) */
	.short 0xbeef
	/* flags */
	.short MULTIBOOT_HEADER_TAG_OPTIONAL
	/* size*/
	.long 8

	.short MULTIBOOT_HEADER_TAG_END
	/* flags */
	.short 0
	/* size */
	.long 8
mbh_end:

.section .text
_start:
	jmp _start
