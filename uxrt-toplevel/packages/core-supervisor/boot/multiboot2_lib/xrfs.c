/*  xrfs.c - load and boot an XRFS image
 *
 *  UX/RT
 *  Copyright (C) 2011-2022  Andrew Warkentin
 *
 *  Originally based on stage2/boot.c from GRUB 0.96
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This library provides the generic architecture-independent part of an XHI
 * Multiboot loader. Architecture-dependent functions and file handling must be
 * provided by the loader with which this library is linked.
 *
 * See include/common/multiboot/arch.h for information on the functions
 * that are required.
 */

#include "stdint.h"
#include "string.h"
#include "stdio.h"
#include "sys/types.h"
#include "multiboot2.h"
#include "multiboot_archdep.h"
#include "multiboot2_lib/generic.h"
#include "multiboot2_lib/arch.h"
#include "multiboot2_lib/internal.h"

static int handle_info_offset_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_info_offset *tag)
{
	struct multiboot_header_tag_fs_info_offset *mbi_tag = (struct multiboot_header_tag_fs_info_offset *)multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_XHI_INFO_OFFSET, sizeof (struct multiboot_tag_xhi_info_offset));
	mbi_tag->offset = tag->offset;
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_address_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_address *tag)
{
	params->fs_image_addr = tag->phys_addr;
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_page_size_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_page_size *tag)
{
	params->fs_image_page_size = tag->page_size;
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_os_name_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_string *tag)
{
	params->os_name = tag->string;
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_os_version_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_string *tag)
{
	params->os_ver = tag->string;
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_kernel_tag_initial(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag)
{
	params->kernel_mem_len = tag->padding_end - tag->mod_start;
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_module_tag_initial(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag)
{
	params->last_fs_module_tag = tag;
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_kernel_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag)
{
	unsigned len = tag->mod_end - tag->mod_start;
	unsigned mem_len = tag->padding_end - tag->mod_start;
	if (!multiboot_load_kernel_override_name(params, params->fs_image_argv, params->fs_image_argc, tag->cmdline, params->fs_image + tag->mod_start, len, mem_len, 0)){
		return (0);
	}
	if (params->fs_image_page_size != params->page_size){
		mb_err_printf("FS image page size (%d) does not match architectural page size (%d)\n", params->fs_image_page_size, params->page_size);
		return (0);
	}


	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_module_exec_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag)
{
	unsigned len = tag->mod_end - tag->mod_start;
	unsigned mem_len = tag->padding_end - tag->mod_start;
	char *argv[1];

	argv[0] = tag->cmdline;
	if (!params->kernel){
		multiboot_errno = MBERR_EXEC_FORMAT;
		mb_err_printf("module loaded before kernel\n");
		return (0);
	}
	if (!multiboot_load_module_exec(params, params->fs_image + tag->mod_start, len, mem_len, argv, 0)){
		mb_err_printf("cannot load module: %s\n", multiboot_strerror(multiboot_errno));
		return (0);
	}
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_module_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag)
{
	char *argv[1];
	argv[0] = tag->cmdline; 
	if (!params->kernel){
		multiboot_errno = MBERR_EXEC_FORMAT;
		mb_err_printf("module loaded before kernel\n");
		return (0);
	}
	if (!multiboot_load_module(params, params->fs_image + tag->mod_start, tag->mod_end - tag->mod_start, argv, 0)){
		mb_err_printf("cannot load module: %s\n", multiboot_strerror(multiboot_errno));
		return (0);
	}
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER handle_fs_module_special_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag)
{
	if (!params->kernel){
		multiboot_errno = MBERR_EXEC_FORMAT;
		mb_err_printf("module loaded before kernel\n");
		return (0);
	}
	if (!multiboot_load_module_special(params, params->fs_image + tag->mod_start, tag->mod_end - tag->mod_start, tag->cmdline)){
		mb_err_printf("cannot load module: %s\n", multiboot_strerror(multiboot_errno));
		return (0);
	}
	return (1);
}

static int num_fs_header_tag_handlers = 10;
static struct multiboot_tag_handler fs_header_tag_handlers_1[MAX_MULTIBOOT_HANDLERS] = {
	{
		.tag_type = MULTIBOOT_HEADER_TAG_END,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_ADDRESS,
		.func = handle_fs_address_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_PAGE_SIZE,
		.func = handle_fs_page_size_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_OS_NAME,
		.func = handle_fs_os_name_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_OS_VERSION,
		.func = handle_fs_os_version_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_KERNEL,
		.func = handle_fs_kernel_tag_initial,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_MODULE_EXEC,
		.func = handle_tag_null,
		.flags = MB_TAG_HANDLER_MULTIPLE,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_MODULE,
		.func = handle_fs_module_tag_initial,
		.flags = MB_TAG_HANDLER_MULTIPLE,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_MODULE_SPECIAL,
		.func = handle_tag_null,
		.flags = MB_TAG_HANDLER_MULTIPLE,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_INFO_OFFSET,
		.func = handle_info_offset_tag,
		.flags = 0,
	}
};

static struct multiboot_tag_handler fs_header_tag_handlers_2[MAX_MULTIBOOT_HANDLERS] = {
	{
		.tag_type = MULTIBOOT_HEADER_TAG_END,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_ADDRESS,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_PAGE_SIZE,
		.func = handle_fs_page_size_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_OS_NAME,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_OS_VERSION,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_KERNEL,
		.func = handle_fs_kernel_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_MODULE_EXEC,
		.func = handle_fs_module_exec_tag,
		.flags = MB_TAG_HANDLER_MULTIPLE,

	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_MODULE,
		.func = handle_fs_module_tag,
		.flags = MB_TAG_HANDLER_MULTIPLE,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_MODULE_SPECIAL,
		.func = handle_fs_module_special_tag,
		.flags = MB_TAG_HANDLER_MULTIPLE,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_FS_INFO_OFFSET,
		.func = handle_tag_null,
		.flags = 0,
	}
};

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_fs_image(struct multiboot_exec_params *params, void *image, size_t len, char *const argv[], int argc, unsigned flags)
{
	int i = 0;
	struct multiboot_xrfs_header *mbh;
	unsigned long mbh_offset;

	if (len < 32){
		mb_err_printf("image too short\n");
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
	}

	multiboot_errno = MBERR_EXEC_FORMAT;
	for (mbh = (struct multiboot_xrfs_header *) image;
			((char *) mbh <= (char *) image + len - 12) || (mbh = 0);
			mbh = (struct multiboot_xrfs_header *) ((multiboot_uint32_t *) mbh + MULTIBOOT_HEADER_ALIGN / 4)){

		if (mbh->magic0 == MULTIBOOT2_XRFS_HEADER_MAGIC0 &&
				mbh->magic1 == MULTIBOOT2_XRFS_HEADER_MAGIC1
				&& !(mbh->magic0 + mbh->magic1 + mbh->header_length + mbh->total_length + mbh->checksum)){
			multiboot_errno = 0;
			break;
		}
 	}

	if (multiboot_errno == MBERR_EXEC_FORMAT){
		mb_err_printf("no valid Multiboot2 XRFS header found\n");
	}

	/* no header found */
	if (multiboot_errno){
		return (0);
	}

	if (!params->compressed){
		for (i = 0; i < argc; i++){
			printf("%s ", argv[i]);
		}
		printf("\n   [boot FS image @ %p]\n", image);
	}

	params->kernel_flags = flags;
	params->fs_image = image;
	params->fs_image_len = params->_cur_fs_image_len = len;
	params->fs_image_mbh = mbh;
	params->fs_image_argv = argv;
	params->fs_image_argc = argc;
	/* process the tags in two stages to allow for relocation */

	/* in the first stage, get image parameters - currently:
	 *
	 * - presence of a compressed inner image 
	 * - OS name string
	 * - OS version string 
	 * - load address and page size */
	if (!multiboot_process_header(params,
				(char *)(params->fs_image_mbh) + sizeof (struct multiboot_xrfs_header), 
				(char *)params->fs_image_mbh + mbh->header_length,
				fs_header_tag_handlers_1,
				num_fs_header_tag_handlers)){
		return (0);
	}

	/* if no kernel was found, try to find an inner compressed image and
	 * restart with that */
	if (!params->kernel_mem_len){
		if (!params->last_fs_module_tag){
			mb_err_printf("FS image contains neither a kernel nor an inner compressed image");
			return (0);
		}
		size_t len;
		printf("\nUncompressing %s... ", params->os_name);
		void *decompressed = multiboot_decompress_image(params, params->last_fs_module_tag, &len);
		printf("done\n");
		params->compressed = 1;
		return (multiboot_load_fs_image(params, decompressed, len, params->fs_image_argv, params->fs_image_argc, flags));
	}

	if (!params->compressed){
		printf("\nLoading %s...\n\n", params->os_name);
	}

	if (params->os_ver){
		printf("Version: %s\n\n", params->os_ver);
	}

	if (!params->fs_image_page_size){
		mb_err_printf("FS image does not include a page size tag (or specifies a zero page size)\n");
		return (0);
	}

	if (!multiboot_check_image_addr(params)){
		return (0);
	}

	/* if the image has a fixed physical address, relocate it */
	if (params->fs_image_addr){

		mbh_offset = (char *)params->fs_image_mbh - (char *)image;
		memmove((char *)params->fs_image_addr, image, len);
		params->fs_image = (char *)params->fs_image_addr;
		params->fs_image_mbh = (struct multiboot_xrfs_header *)((char *)params->fs_image + mbh_offset);
	}

	/* in the second stage, actually load the kernel and modules (which can
	 * only be done after relocation) */
	if (!multiboot_process_header(params,
				(char *)(params->fs_image_mbh) + sizeof (struct multiboot_xrfs_header), 
				(char *)params->fs_image_mbh + params->fs_image_mbh->header_length,
				fs_header_tag_handlers_2,
				num_fs_header_tag_handlers)){
		return (0);
	}

	return multiboot_load_module_image(params, params->fs_image, params->fs_image_len, argv, argc);
}
