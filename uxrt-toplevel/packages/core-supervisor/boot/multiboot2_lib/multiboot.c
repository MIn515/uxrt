/*  multiboot.c - load and bootstrap a Multiboot kernel with UX/RT extensions
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

/*FIXME: paged loading seems to have broken at some point (the end-of-image overlap check fails with a ridiculously large size for the end region of the image, and disabling that "hangs" in memset, presumably trying to zero the entire region), although that's not particularly critical, since seL4 doesn't use it*/
/*TODO: add macros that can be redefined by architecture code for converting between physical and virtual addresses, rather than assuming identity mapping*/

#define __BIG_ENDIAN 4321
#define __LITTLE_ENDIAN 1234

#include "stdint.h"
#include "string.h"
#include "stdio.h"
#include "sys/types.h"
#include "multiboot2.h"
#include "multiboot_archdep.h"
#include "multiboot2_lib/generic.h"
#include "multiboot2_lib/arch.h"
#include "multiboot2_lib/elf.h"
#include "multiboot2_lib/internal.h"

#define mb_err_printf printf

#define PAGE_ALIGN(addr)(((unsigned long)addr + params->page_size - 1) & ~(params->page_size - 1))
#define IS_UNALIGNED(address) ((unsigned long)(address) & (params->page_size - 1))

#define CHECK_OVERLAP(kernel, kernel_size, map_addr, map_size) do{ \
		multiboot_uint64_t file_end = (multiboot_uint64_t)(kernel + kernel_size); \
		multiboot_uint64_t map_end = (multiboot_uint64_t)map_addr + map_size; \
		if ((file_end > (multiboot_uint64_t)map_addr && file_end < map_end) || \
				(map_end > (multiboot_uint64_t)kernel && map_end < file_end)){ \
				multiboot_errno = MBERR_OVERLAPPING_SECTION; \
				return (0); \
		} \
	}while (0)

#define ELF_HDR_FIELD(field) (pu.elf32->e_ident[EI_CLASS] == ELFCLASS64 ? pu.elf64->field : pu.elf32->field)
#define ELF_PHDR_FIELD(field) (pu.elf32->e_ident[EI_CLASS] == ELFCLASS64 ? phdr.ph64->field : phdr.ph32->field)

int MULTIBOOT_DATA_QUALIFIER multiboot_errno = 0;

static char MULTIBOOT_DATA_QUALIFIER *multiboot_errlist[] = {
	"No error (this shouldn't happen)",
	"Internal error",
	"Invalid or unsupported executable format",
	"Section not page-aligned",
	"Section load address overlaps kernel image",
	"Unsupported boot features",
	"Out of memory",
	"Out of Multiboot info space"
};

static int num_kernel_header_tag_handlers;
static struct multiboot_tag_handler kernel_header_tag_handlers[];
static int num_mbi_tag_handlers;
static struct multiboot_tag_handler mbi_tag_handlers[];


#define MULTIBOOT_CHECK_ERRNO() if (!multiboot_errno) multiboot_errno = MBERR_INTERNAL

#ifndef USE_MULTIBOOT_ALLOCATE_MBI
void MULTIBOOT_TEXT_QUALIFIER *multiboot_allocate_mbi(struct multiboot_exec_params *params, size_t minsize, multiboot_uint64_t *size)
{
	multiboot_errno = MBERR_INTERNAL;
	return (NULL);
}
#endif

int multiboot_tag_requested(struct multiboot_exec_params *params, multiboot_uint16_t type)
{
	int tag_index = 0, request_index;
	struct multiboot_header_tag_information_request *tag;

	while ((tag = (struct multiboot_header_tag_information_request *)multiboot_get_header_tag(params, MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST, tag_index))){
		for (request_index = 0; request_index < (tag->size - sizeof (struct multiboot_header_tag)) / sizeof (multiboot_uint16_t); request_index++){
			if (tag->requests[request_index] == type) return (1);
		}
		tag_index++;
	}
	return (0);
}


struct multiboot_header_tag *multiboot_get_header_tag_raw(char *tags, char *end, multiboot_uint16_t type, int index)
{
	int cur_index = 0;
	struct multiboot_header_tag *tag = (struct multiboot_header_tag *)tags;
	while ((char *)tag < end){
		if (tag->type == type){
			if (cur_index == index){
				return (tag);
			}
			cur_index++;
		}
		tag = (struct multiboot_header_tag *)(((char *)tag) + tag->size);
	}
	return (NULL);
}

struct multiboot_header_tag *multiboot_get_header_tag(struct multiboot_exec_params *params, multiboot_uint16_t type, int index)
{
	return multiboot_get_header_tag_raw((char *)(params->mbh) + sizeof (struct multiboot_header), (char *)params->mbh + params->mbh->header_length, type, index);
}

/* multiboot_allocate_mbi_tag() allocates a tag. */

struct multiboot_tag MULTIBOOT_TEXT_QUALIFIER *multiboot_allocate_mbi_tag(struct multiboot_exec_params *params, multiboot_uint16_t type, size_t size)
{
	struct multiboot_tag *tag = (struct multiboot_tag *)(ALIGN_UP((unsigned long)params->_mb_alloc_start, MULTIBOOT_TAG_ALIGN));

	if (!params->mbi){
		mb_err_printf("multiboot_allocate_mbi_tag called with params->mbi unset\n");
		multiboot_errno = MBERR_INTERNAL;
		return (NULL);
	}

	if ((char *)tag + size > (char *)params->mbi + params->max_mbi_size){
		mb_err_printf("multiboot_allocate_mbi_tag: out of memory\n");
		multiboot_errno = MBERR_MBI_EXHAUSTED;
		return (NULL);
	}

	memset(tag, '\0', size);
	params->_mb_alloc_start = (char *)tag + size;
	tag->type = type;
	tag->size = size;

	return (tag);
}

void MULTIBOOT_TEXT_QUALIFIER *multiboot_reallocate_mbi_tag(struct multiboot_exec_params *params, void *tag, size_t extra_size)
{
	char *new_start = (char *)tag + ((struct multiboot_tag *)tag)->size;
	size_t size = (((struct multiboot_tag *)tag)->size) + extra_size;

	if (!params->mbi){
		mb_err_printf("multiboot_reallocate_mbi_tag called with params->mbi unset\n");
		multiboot_errno = MBERR_INTERNAL;
		return (NULL);
	}

	if (new_start != params->_mb_alloc_start){
		mb_err_printf("multiboot_reallocate_mbi_tag called with a tag other than the most recently allocated (tag type: %hx)\n", ((struct multiboot_tag *)tag)->type);
		multiboot_errno = MBERR_INTERNAL;
		return (NULL);
	}

	memset(new_start, '\0', extra_size);

	if ((char *)tag + size > (char *)params->mbi + params->max_mbi_size){
		multiboot_errno = MBERR_MBI_EXHAUSTED;
		return (NULL);
	}

	params->_mb_alloc_start = (char *)tag + size;
	((struct multiboot_tag *)tag)->size = size;
	return (new_start);
}

void MULTIBOOT_TEXT_QUALIFIER *multiboot_reallocate_mbi_tag_aligned(struct multiboot_exec_params *params, void *tag, size_t size)
{
	size_t padding_size = PAGE_ALIGN((unsigned long)tag + ((struct multiboot_tag *)tag)->size) - ((unsigned long)tag + ((struct multiboot_tag *)tag)->size);
	/* allocate the padding separately so the returned pointer is aligned */
	multiboot_reallocate_mbi_tag(params, tag, padding_size);

	return (multiboot_reallocate_mbi_tag(params, tag, size));
}

void MULTIBOOT_TEXT_QUALIFIER *multiboot_copy_mbi_tag(struct multiboot_exec_params *params, const struct multiboot_tag *orig_tag){
        struct multiboot_tag *tag;                
        if (!(tag = (struct multiboot_tag *)multiboot_allocate_mbi_tag(params, orig_tag->type, orig_tag->size))){
		return 0;
        }                                         
        memcpy(tag, orig_tag, orig_tag->size);    
	return tag;
} 

/* multiboot_strerror() returns a descriptive message for a Multiboot error
 * number.*/

const char MULTIBOOT_TEXT_QUALIFIER *multiboot_strerror(int mb_errnum)
{
	if (mb_errnum >= MBERR_NUM){
		return ("Invalid error number");
	}else{
		return (multiboot_errlist[mb_errnum]);
	}
}

static int handle_information_request_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_information_request *tag)
{
	if (!(tag->flags & MULTIBOOT_HEADER_TAG_OPTIONAL)){
		int num_requests = (tag->size - sizeof (struct multiboot_header_tag)) / sizeof (multiboot_uint32_t);
		int request, handler;
		int found;
		for (request = 0; request < num_requests; request++){
			found = 0;
			for (handler = 0; handler < num_mbi_tag_handlers; handler++){
				if (tag->requests[request] == mbi_tag_handlers[handler].tag_type){
					found = 1;
					break;
				}
			}
			if (!found){
				mb_err_printf("kernel requires tag with unknown type 0x%x\n", tag->requests[request]);
				multiboot_errno = MBERR_BOOT_FEATURES;
				return (0);
			}
		}
	}
	return (1);
}

static int handle_address_size_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_xhi_address_size *tag)
{
	if (tag){
		params->address_size = tag->address_size;
		if (params->address_size != 4 && params->address_size != 8){
			mb_err_printf("invalid address size %d\n", params->address_size);
			multiboot_errno = MBERR_EXEC_FORMAT;
			return (0);
		}
	}else{
		/*TODO: this should be a symbolic constant*/
		params->address_size = 4;
	}
	return (1);
}

static int handle_address_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_address *tag)
{
	if (tag){
		mb_err_printf("TODO: implement a.out kludge support\n");
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
#if 0
		multiboot_uint64_t cur_addr;
		multiboot_uint64_t data_end_addr;

		cur_addr = params->address_tag->load_addr;

		/* first offset into file */
		params->virt_kstart = i - (params->address_tag->header_addr - cur_addr);
		params->entry = params->address_tag->entry_addr;
		if (params->address_tag->bss_end_addr){
			params->virt_kend = params->address_tag->bss_end_addr;
		}else if (params->address_tag->data_end_addr){
			params->virt_kend = params->address_tag->data_end_addr;
		}else if (params->address_tag->text_end_addr){
			params->virt_kend = params->address_tag->text_end_addr;
		}else{
			params->virt_kend = cur_addr + (params->kernel_len - params->virt_kstart);
		}

		if (params->address_tag->data_end_addr){
			data_end_addr = params->address_tag->data_end_addr;
		}else{
			multiboot_info_addr_t start_addr = params->header_offset - (params->address_tag->header_addr) - params->address_tag->load_addr;
			if (params->address_tag->text_end_addr){
				data_end_addr = params->address_tag->text_end_addr;
			}else{
				data_end_addr = params->address_tag->load_addr + (params->kernel_len - start_addr);
			}
		}

		params->exec_type = MB_EXEC_KLUDGE;
#endif
	}else if (params->kernel_len > sizeof (Elf32_Ehdr)
			&& BOOTABLE_ELF32((*((Elf32_Ehdr *)(params->kernel))))){
		params->exec_type = MB_EXEC_ELF32;
	}else if (params->kernel_len > sizeof (Elf64_Ehdr)
			&& BOOTABLE_ELF64((*((Elf64_Ehdr *)(params->kernel))))){
		params->exec_type = MB_EXEC_ELF64;
	}else{
		/* no recognizable format */
		mb_err_printf("kernel is neither a bootable ELF executable nor does it have an address tag\n");
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
	}

	return (1);
}

static int handle_entry_address_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_entry_address *tag)
{
	params->entry = tag->entry_addr;
	return (1);
}

static int handle_map_kernel_sections_tag(struct multiboot_exec_params *params, struct multiboot_header_tag_entry_address *tag)
{
	params->paged = 1;
	return (1);
}

int handle_tag_null(struct multiboot_exec_params *params, struct multiboot_tag *tag)
{
	return (1);
}

#define MAX_MULTIBOOT_HANDLERS 32
static int num_kernel_header_tag_handlers = 10;
static struct multiboot_tag_handler kernel_header_tag_handlers[MAX_MULTIBOOT_HANDLERS] = {
	{
		.tag_type = MULTIBOOT_HEADER_TAG_END,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST,
		.func = handle_information_request_tag,
		.flags = MB_TAG_HANDLER_MULTIPLE,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_ADDRESS,
		.func = handle_address_tag,
		.flags = MB_TAG_HANDLER_RUN_NULL,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS,
		.func = handle_entry_address_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_XHI_MAP_KERNEL_SECTIONS,
		.func = handle_map_kernel_sections_tag,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_MODULE_ALIGN,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_XHI_COMPATIBILITY,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_XHI_ADDRESS_SIZE,
		.func = handle_address_size_tag,
		.flags = MB_TAG_HANDLER_RUN_NULL,
	},
	{
		.tag_type = MULTIBOOT_HEADER_TAG_XHI_MAP_KERNEL_SECTIONS,
		.func = handle_map_kernel_sections_tag,
		.flags = 0,
	}
};

static int num_mbi_tag_handlers = 7;
static struct multiboot_tag_handler mbi_tag_handlers[MAX_MULTIBOOT_HANDLERS] = {
	{
		.tag_type = MULTIBOOT_TAG_TYPE_END,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_TAG_TYPE_CMDLINE,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_TAG_TYPE_MMAP,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_TAG_TYPE_XHI_MODULE_EXEC,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_TAG_TYPE_XHI_MODULE_IMAGE,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_TAG_TYPE_XHI_GDT,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_TAG_TYPE_XHI_MODULE_SECTIONS,
		.func = handle_tag_null,
		.flags = 0,
	},
	{
		.tag_type = MULTIBOOT_TAG_TYPE_XHI_KERNEL_SECTIONS,
		.func = handle_tag_null,
		.flags = 0,
	},
};

int MULTIBOOT_TEXT_QUALIFIER multiboot_add_tag_handler(struct multiboot_tag_handler *handlers, int *num_handlers, multiboot_uint16_t tag_type, int flags, void *new_handler)
{
	int i;
	for (i = 0; i < *num_handlers; i++)
	{
		if (handlers[i].tag_type == tag_type){
			handlers[i].func = new_handler;
			return (1);
		}
	}

	if (*num_handlers > MAX_MULTIBOOT_HANDLERS){
		return (0);
	}

	handlers[*num_handlers].tag_type = tag_type;
	handlers[*num_handlers].func = new_handler;
	handlers[*num_handlers].flags = flags;
	(*num_handlers)++;
	return (1);
}

int multiboot_set_mbi_address(struct multiboot_exec_params *params, void *addr, size_t size)
{
	params->mbi = addr;
	params->max_mbi_size = size;
	params->_mb_alloc_start = (char *)params->mbi + sizeof (struct multiboot_info);
	return (1);

}

int multiboot_move_mbi(struct multiboot_exec_params *params, void *addr, size_t size)
{
	size_t cur_size = params->_mb_alloc_start - (char *)params->mbi;

	memcpy(addr, params->mbi, cur_size);

	params->mbi = addr;
	params->_mb_alloc_start = (char *)params->mbi + cur_size;
	params->max_mbi_size = size;
	return (1);

}

static int multiboot_add_segment(struct multiboot_exec_params *params, struct multiboot_tag_xhi_sections *sections_tag, multiboot_uint64_t file_start, multiboot_uint64_t mem_start, size_t file_size, size_t mem_size, int flags)
{
	struct multiboot_exec_section *section;

	if (!(section = multiboot_reallocate_mbi_tag(params, sections_tag, sizeof (struct multiboot_exec_section)))){
		printf("\ncannot extend section list\n");
		return (0);
	}

	section->flags = flags;

	sections_tag->num_sections++;

	MULTIBOOT_SET_SECTION_FIELD(section, file_start, file_start);
	MULTIBOOT_SET_SECTION_FIELD(section, mem_start, mem_start);
	MULTIBOOT_SET_SECTION_FIELD(section, file_end, file_start + file_size);
	MULTIBOOT_SET_SECTION_FIELD(section, mem_end, mem_start + mem_size);

	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER multiboot_get_kernel_entry(struct multiboot_exec_params *params)
{
	union {
		Elf32_Ehdr *elf32;
		Elf64_Ehdr *elf64;
	}pu;
	pu.elf32 = (Elf32_Ehdr *)params->kernel;

	if (params->exec_type == MB_EXEC_ELF32){
		params->entry = pu.elf32->e_entry;
		return (1);
	}else if (params->exec_type == MB_EXEC_ELF64){
		params->entry = pu.elf64->e_entry;
		return (1);
	}else{
		if (!multiboot_get_header_tag(params, MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS, 0)){
			/* don't bother to set the entry address here because it will be set
			 * by handle_entry_address_tag() later on*/
			mb_err_printf("non-ELF kernel lacks an entry address tag\n");
			return (0);
		}else{
			return (1);
		}
	}
}

static int MULTIBOOT_TEXT_QUALIFIER multiboot_load_kludge(struct multiboot_exec_params *params, struct multiboot_tag_xhi_sections *tag, const char *exec, size_t len, int paged)
{
	/*TODO: implement this (the old code below is from the old abandoned
	 * Multiboot1-like protocol)*/
	mb_err_printf("\nTODO: implement a.out kludge support\n");
	multiboot_errno = MBERR_EXEC_FORMAT;
	return (0);
#if 0
	int text_flags = MB_SEC_R | MB_SEC_X;
	multiboot_info_addr_t text_len = 0, data_len = 0, bss_len = 0, data_and_bss_len = 0;
	multiboot_info_addr_t cur_addr = 0, cur_kernel_off = 0;


	multiboot_info_addr_t text_end_addr = 0, data_end_addr = 0, bss_end_addr = 0;

	cur_addr = MB_HDR_FIELD(load_addr);

	/* first offset into file */
	cur_kernel_off = params->header_offset - (MB_HDR_FIELD(header_addr) - cur_addr);

	text_end_addr = MB_HDR_FIELD(text_end_addr);
	data_end_addr = MB_HDR_FIELD(data_end_addr);

	/* If the data end address is zero, assume that the data area is part
	 * of the text area (this means no execute-in-place, so this should
	 * be avoided if possible) */
	if (!data_end_addr){
		text_flags |= MB_SEC_W;
		data_end_addr = text_end_addr;
	}

	/* If the text end address is zero, load the whole contents and ignore
	 * the data end address, treating the data area as part of the text area
	 * (this also means no XIP). */
	if (!text_end_addr){
		text_flags |= MB_SEC_W;
		text_end_addr = cur_addr + (params->kernel_len - cur_kernel_off);
		data_end_addr = text_end_addr;
	}

	text_len = text_end_addr - cur_addr;
	data_len = data_end_addr - text_end_addr;

	bss_end_addr = MB_HDR_FIELD(bss_end_addr);
	/* If the bss end address is zero, assume that there is no bss
	 * area.  */
	if (!bss_end_addr){
		bss_end_addr = data_end_addr;
	}

	bss_len = bss_end_addr - data_end_addr;
	data_and_bss_len = data_len + bss_len;

	if (MB_HDR_FIELD(header_addr) < MB_HDR_FIELD(load_addr)
			|| text_end_addr <= MB_HDR_FIELD(load_addr)
			|| data_end_addr < text_end_addr
			|| bss_end_addr < data_end_addr
			|| (MB_HDR_FIELD(header_addr) - MB_HDR_FIELD(load_addr)) > params->header_offset){
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
	}

	printf (", loadaddr=0x%llx, ", (unsigned long long)cur_addr);
	if (data_len){
		printf("text=0x%llx, data=0x%llx", (unsigned long long)text_len, (unsigned long long)data_len);
	}else{
		printf("text-and-data=0x%llx", (unsigned long long)text_len);
	}
	if (bss_len){
		printf(", bss=0x%llx", (unsigned long long)bss_len);
	}
	/* map text, then map data */
	CHECK_OVERLAP((size_t)params->kernel, params->kernel_len, cur_addr, text_len);
	if (multiboot_add_segment(params, kernel_sections_tag, (unsigned long)(params->kernel + cur_kernel_off), cur_addr, text_len, text_len, text_flags)){
		cur_addr += text_len;
		if (data_and_bss_len){
			CHECK_OVERLAP((size_t)params->kernel, params->kernel_len, cur_addr, data_and_bss_len);
			if (!multiboot_add_segment(params, kernel_sections_tag, (unsigned long)(params->kernel + cur_kernel_off + text_len), cur_addr, data_len, data_and_bss_len, MB_SEC_R | MB_SEC_W)){
				MULTIBOOT_CHECK_ERRNO();
				goto error;
			}
			cur_addr += data_len;

		}
	}else if (!multiboot_errno){
		multiboot_errno = MBERR_EXEC_FORMAT;
	}
#endif
}

static int MULTIBOOT_TEXT_QUALIFIER multiboot_load_elf(struct multiboot_exec_params *params, struct multiboot_tag_xhi_sections *tag, const char *exec, size_t len, int paged)
{
	union {
		Elf32_Ehdr *elf32;
		Elf64_Ehdr *elf64;
	}pu;
	unsigned loaded = 0, memsiz, filesiz;
	multiboot_uint64_t memaddr;
	union {
		Elf32_Phdr *ph32;
		Elf64_Phdr *ph64;
	}phdr;

	int i;
	size_t cur_addr = 0;
	size_t cur_exec_off;

	pu.elf32 = (Elf32_Ehdr *)exec;

	if (len < sizeof (Elf64_Ehdr)){
		mb_err_printf("executable is smaller than an ELF header\n");
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
	}

	if (!(BOOTABLE_ELF32((*((Elf32_Ehdr *)(exec)))) || BOOTABLE_ELF64((*((Elf64_Ehdr *)(exec)))))){
		mb_err_printf("\nmultiboot_load_elf called on executable with invalid type %d (this shouldn't happen)\n", params->exec_type);
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
	}

	/* don't want to deal with ELF program header at some random
	 * place in the file -- this generally won't happen */
	if (ELF_HDR_FIELD(e_phoff) == 0
			|| ELF_HDR_FIELD(e_phnum) == 0
			|| ((ELF_HDR_FIELD(e_phoff) + (ELF_HDR_FIELD(e_phentsize) * ELF_HDR_FIELD(e_phnum)))
				>= len)){
		mb_err_printf("\nELF header at invalid location\n");
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
	}

	tag->entry = ELF_HDR_FIELD(e_entry);

	/* scan for program segments */
	for (i = 0; i < ELF_HDR_FIELD(e_phnum); i++){
		int flags = 0;
		phdr.ph32 = (Elf32_Phdr *)
			(exec + ELF_HDR_FIELD(e_phoff)
			+ (ELF_HDR_FIELD(e_phentsize) * i));
		if (ELF_PHDR_FIELD(p_type) == PT_LOAD){
			/* offset into file */
			cur_exec_off = ELF_PHDR_FIELD(p_offset);
			filesiz = ELF_PHDR_FIELD(p_filesz);


			if (paged){
				memaddr = ELF_PHDR_FIELD(p_vaddr);
				/* only check alignment on read-only sections, because writable
				 * sections should be copied rather than mapped in place */
				if (!(ELF_PHDR_FIELD(p_flags) & PF_W || 
							params->writable_section_uip) &&
						(IS_UNALIGNED(memaddr) ||
						 IS_UNALIGNED(cur_exec_off))){
					multiboot_errno = MBERR_UNALIGNED_SECTION;
					return (0);
				}
				printf("      (virt)");
			}else{
				printf("      (phys)");
				memaddr = ELF_PHDR_FIELD(p_paddr);
			}

			memsiz = ELF_PHDR_FIELD(p_memsz);

			/* make sure we only load what we're supposed to! */
			if (filesiz > memsiz){
				filesiz = memsiz;
			}
			/* mark memory as used */
			if (cur_addr < memaddr + memsiz){
				cur_addr = memaddr + memsiz;
			}
			printf(" <0x%lx:0x%llx:0x%x:0x%x:", (unsigned long)exec + cur_exec_off,
					(unsigned long long)memaddr, filesiz, memsiz - filesiz);

			if (ELF_PHDR_FIELD(p_flags) & PF_R){
				printf("r");
				flags |= MB_SEC_R;
			}
			if (ELF_PHDR_FIELD(p_flags) & PF_W){
				printf("w");
				flags |= MB_SEC_W;
			}
			if (ELF_PHDR_FIELD(p_flags) & PF_X){
				printf("x");
				flags |= MB_SEC_X;
			}
			printf(">\n");
			/* increment number of segments */
			loaded++;

			/* add the segment to the list */
			if (!multiboot_add_segment(params, tag, (unsigned long)exec + cur_exec_off, memaddr, filesiz, memsiz, flags)){
				MULTIBOOT_CHECK_ERRNO();
				return (0);
			}
		}
	}
	return (1);
}

static int MULTIBOOT_TEXT_QUALIFIER multiboot_copy_cmdline_string(struct multiboot_exec_params *params, struct multiboot_tag *tag, char *const argv[], int argc, char *override_name)
{
	int i;
	char *arg;
	char *src_arg;
	size_t arg_len;
	for (i = 0; i < argc; i++){
		/* override_name allows the kernel to receive the arguments of
		 * the FS image without having the name replaced by that of the 
		 * FS image */
		if (override_name && !i){
			src_arg = override_name;
		}else{
			src_arg = argv[i];
		}
		arg_len = strlen(src_arg);
		if ((arg = multiboot_reallocate_mbi_tag(params, tag, arg_len + 1))){
			if (i < argc - 1){
				strncpy(arg, src_arg, arg_len + 1);
				arg[arg_len] = ' ';
			}else{
				strncpy(arg, src_arg, arg_len + 1);
			}
		}else{
			return (0);
		}
	}
	return (1);
}

int MULTIBOOT_TEXT_QUALIFIER multiboot_process_header(struct multiboot_exec_params *params, char *tags, char *end, struct multiboot_tag_handler *handlers, int num_handlers)
{
	int i;
	struct multiboot_header_tag *tag = (struct multiboot_header_tag *)tags;

	for (i = 0; i < num_handlers; i++)
	{
		handlers[i].num_found = 0;
	}

	tag = (struct multiboot_header_tag *)tags;
	while ((char *)tag < end){
		int known;
		known = 0;
		if (tag->type == MULTIBOOT_HEADER_TAG_END){
			break;
		}
		for (i = 0; i < num_handlers; i++)
		{

			if (tag->type == handlers[i].tag_type){
				known = 1;
				if (handlers[i].num_found && !(handlers[i].flags & MB_TAG_HANDLER_MULTIPLE)){
					mb_err_printf("multiple instances of single-instance-only tag type 0x%x\n", handlers[i].tag_type);

					multiboot_errno = MBERR_EXEC_FORMAT;
					return (0);
				}
				handlers[i].num_found++;
				if (!((multiboot_header_tag_handler_func)handlers[i].func)(params, tag)){
					if (!multiboot_errno){
						mb_err_printf("warning: multiboot header tag handler at %p not setting multiboot_errno\n", handlers[i].func);
						multiboot_errno = MBERR_INTERNAL;
					}
					return (0);
				}
				break;
			}
		}
		if (!known && !(tag->flags & MULTIBOOT_HEADER_TAG_OPTIONAL)){
			mb_err_printf("required header tag with unknown type 0x%hx\n", tag->type);
			multiboot_errno = MBERR_BOOT_FEATURES;
			return (0);
		}
		tag = (struct multiboot_header_tag *)(((char *)tag) + ALIGN_UP(tag->size, MULTIBOOT_TAG_ALIGN));
	}

	for (i = 0; i < num_handlers; i++)
	{
		if (!handlers[i].num_found && (handlers[i].flags & MB_TAG_HANDLER_RUN_NULL)){
			if (!((multiboot_header_tag_handler_func)handlers[i].func)(params, NULL)){
				if (!multiboot_errno){
					mb_err_printf("warning: multiboot header tag handler at %p not setting multiboot_errno\n", handlers[i].func);
					multiboot_errno = MBERR_INTERNAL;
				}
				return (0);
			}
		}
	}
	return (1);
}

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_kernel_override_name(struct multiboot_exec_params *params, char *const argv[], int argc, char *override_name, const void *kernel, size_t len, size_t mem_len, unsigned flags)
{
	int i = 0;
	struct multiboot_tag_xhi_sections *kernel_sections_tag;
	struct multiboot_tag *cmdline_tag;
	char *str = NULL;

	params->mbh = NULL;
	params->paged = 0;


	if (flags & MB_NO_WRITABLE_SECTION_UIP){
		params->writable_section_uip = 0;
	}else{
		params->writable_section_uip = 1;
	}

	for (i = 0; i < argc; i++){
		char *arg;
		if (override_name && !i){
			arg = override_name;
		}else{
			arg = argv[i];
		}
		printf("%s ", arg);
	}
	printf("\n");

	if (len < 32){
		mb_err_printf("kernel too short\n");
		multiboot_errno = MBERR_EXEC_FORMAT;
		return (0);
	}

	multiboot_errno = MBERR_EXEC_FORMAT;
	/*TODO: support a list of compatible architectures rather than only a single one*/
	for (params->mbh = (struct multiboot_header *) kernel;
			((char *) params->mbh <= (char *) kernel + len - 12) || (params->mbh = 0);
			params->mbh = (struct multiboot_header *) ((multiboot_uint32_t *) params->mbh + MULTIBOOT_HEADER_ALIGN / 4)){
		if (params->mbh->magic == MULTIBOOT2_HEADER_MAGIC
				&& !(params->mbh->magic + params->mbh->architecture
				+ params->mbh->header_length + params->mbh->checksum)){
			multiboot_errno = 0;
			break;
		}
	}

	params->header_offset = (unsigned long)params->mbh - (unsigned long)kernel;
	if (multiboot_errno == MBERR_EXEC_FORMAT){
		mb_err_printf("no valid Multiboot2 kernel header found\n");
	}else if (!params->mbh->architecture == MULTIBOOT_ARCHITECTURE_CURRENT){
		mb_err_printf("unsupported kernel architecture 0x%x\n", params->mbh->architecture);
		multiboot_errno = MBERR_EXEC_FORMAT;
	}

	/* no header found */
	if (multiboot_errno){
		return (0);
	}
	params->kernel = kernel;
	params->kernel_len = len;
	params->kernel_mem_len = mem_len;

	if (!multiboot_process_header(params,
				(char *)(params->mbh) + sizeof (struct multiboot_header), 
				(char *)params->mbh + params->mbh->header_length,
				kernel_header_tag_handlers,
				num_kernel_header_tag_handlers)){
		return (0);
	}

	if (!multiboot_arch_init(params)){
		if (!multiboot_errno){
			mb_err_printf("warning: multiboot_arch_init not setting multiboot_errno\n");
			multiboot_errno = MBERR_INTERNAL;
		}
		return (0);
	}

	if (!multiboot_reserve_range((uint64_t)(unsigned long)params->_mb_alloc_start, ((uint64_t)(unsigned long)params->_mb_alloc_start) + params->max_mbi_size, "Multiboot info")){
		mb_err_printf("failed to reserve range for Multiboot info");
		return (0);
	}

	params->page_size = multiboot_get_page_size(params);

	if (params->max_mbi_size < MBI_MINSIZE){
		multiboot_errno = MBERR_MBI_EXHAUSTED;
		return (0);
	}

	if (IS_UNALIGNED((char *)params->kernel)){
		multiboot_errno = MBERR_UNALIGNED_SECTION;
		return (0);
	}

	switch (params->exec_type){
		case MB_EXEC_KLUDGE:
			str = "kludge";
			break;
		case MB_EXEC_ELF32:
			str = "elf32";
			break;
		case MB_EXEC_ELF64:
			str = "elf64";
			break;
		default:
			/* no recognizable format */
			mb_err_printf("multiboot_load_kernel called with params->exec_type set to an invalid value\n");
			multiboot_errno = MBERR_INTERNAL;
			return (0);
	}


	if (!(cmdline_tag = multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_CMDLINE, sizeof (struct multiboot_tag_string)))){
		mb_err_printf("cannot allocate tag for command line: %s\n", multiboot_strerror(multiboot_errno));
		return (0);
	}
	if (!multiboot_copy_cmdline_string(params, cmdline_tag, argv, argc, override_name)){
		mb_err_printf("cannot copy tag for command line: %s\n", multiboot_strerror(multiboot_errno));
		return (0);
	}

	if (!(kernel_sections_tag = (struct multiboot_tag_xhi_sections *)multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_XHI_KERNEL_SECTIONS, sizeof (struct multiboot_tag_xhi_sections)))){
		mb_err_printf("cannot allocate tag for kernel sections: %s\n", multiboot_strerror(multiboot_errno));
		return (0);
	}
	kernel_sections_tag->num_sections = 0;
	kernel_sections_tag->load_type = MULTIBOOT_LOAD_RELOC;
	kernel_sections_tag->address_size = params->address_size;

	printf("   [%s kernel @ %p]\n", str, params->kernel);

	if (params->exec_type == MB_EXEC_KLUDGE){
		if (!multiboot_load_kludge(params, kernel_sections_tag, params->kernel, params->kernel_len, params->paged)){
			goto error;
		}
	}else{
		if (!multiboot_load_elf(params, kernel_sections_tag, params->kernel, params->kernel_len, params->paged)){
			goto error;
		}
	}

	multiboot_get_kernel_entry(params);
	kernel_sections_tag->entry = params->entry;

	for (i = 0; i < num_mbi_tag_handlers; i++)
	{
		if (!((multiboot_info_tag_handler_func)mbi_tag_handlers[i].func)(params, multiboot_tag_requested(params, mbi_tag_handlers[i].tag_type))){
			return (0);
		}
	}

	printf("      [entry=0x%llx]\n", (unsigned long long)params->entry);

	return multiboot_kernel_loaded(params);
error:
	printf("\n");
	return (0);
}

/*
 *  The next two functions, 'multiboot_load_kernel' and 'multiboot_load_module',
 *  are the building blocks of the multiboot loader component.  They handle
 *  all of the platform-independent parts of loading a kernel and modules.
 */

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_kernel(struct multiboot_exec_params *params, char *const argv[], int argc, const void *kernel, size_t len, size_t mem_len, unsigned flags)
{
	return (multiboot_load_kernel_override_name(params, argv, argc, NULL, kernel, len, mem_len, flags));
}

static struct multiboot_tag_module *MULTIBOOT_TEXT_QUALIFIER multiboot_load_module_common(struct multiboot_exec_params *params, const void *module, size_t len, multiboot_uint16_t type, size_t size, char *const argv[], int argc)
{
	struct multiboot_tag_module *module_tag;
	int ret;
	multiboot_errno = 0;

	module_tag = (struct multiboot_tag_module *)multiboot_allocate_mbi_tag(params, type, size);

	if (!(module_tag->mod_start = multiboot_map_module(params, module, len))){
		MULTIBOOT_CHECK_ERRNO();
		return (NULL);
	}
	module_tag->mod_end = module_tag->mod_start + len;

	if (!argc){
		argc = 1;
	}
	ret = multiboot_copy_cmdline_string(params, (struct multiboot_tag *)module_tag, argv, argc, NULL);
	if (!ret){
		return (NULL);
	}

	return (module_tag);
}

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_module(struct multiboot_exec_params *params, const void *module, size_t len, char *const argv[], int argc)
{
	struct multiboot_tag_module *module_tag;
	int i;

	if (argc){
		for (i = 0; i < argc; i++){
			printf("%s ", argv[i]);
		}

		printf("\n");
	}else{
		printf("%s\n", argv[0]);
	}

	if (!(module_tag = multiboot_load_module_common(params, module, len, MULTIBOOT_TAG_TYPE_MODULE, sizeof (struct multiboot_tag_module), argv, argc))){
		return (0);
	}

	printf("   [module @ 0x%llx, %u bytes]\n", (unsigned long long)module_tag->mod_start, (unsigned int)len);
	return (1);
}

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_module_special(struct multiboot_exec_params *params, const void *module, size_t len, char *const name)
{
	struct multiboot_tag_module *module_tag;
	char *argv[1];
	argv[0] = name;

	printf("%s\n", argv[0]);

	if (!(module_tag = multiboot_load_module_common(params, module, len, MULTIBOOT_TAG_TYPE_XHI_MODULE_SPECIAL, sizeof (struct multiboot_tag_module), argv, 0))){
		return (0);
	}

	printf("   [special module @ 0x%llx, %u bytes]\n", (unsigned long long)module_tag->mod_start, (unsigned int)len);
	return (1);
}

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_module_image(struct multiboot_exec_params *params, void *module, size_t len, char *const argv[], int argc)
{
	struct multiboot_tag_module *module_tag;

	if (!(module_tag = multiboot_load_module_common(params, module, len, MULTIBOOT_TAG_TYPE_XHI_MODULE_IMAGE, sizeof (struct multiboot_tag_module), argv, argc))){
		return (0);
	}

	printf("\n[boot FS image dest: 0x%llx, %u bytes]\n", (unsigned long long)module_tag->mod_start, (unsigned int)len);

	params->fs_image = module;
	params->fs_image_len = len;

	return (1);
}

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_module_exec(struct multiboot_exec_params *params, const void *module, size_t len, size_t mem_len, char *const argv[], int argc)
{
	struct multiboot_tag_xhi_module_exec *module_tag;
	struct multiboot_tag_xhi_sections *sections_tag;
	char *elf_class;
	int i;
	union {
		Elf32_Ehdr *elf32;
		Elf64_Ehdr *elf64;
	}pu;
	pu.elf32 = (Elf32_Ehdr *)module;

	if (argc){
		for (i = 0; i < argc; i++){
			printf("%s ", argv[i]);
		}

		printf("\n");
	}else{
		printf("%s\n", argv[0]);
	}


	if (!multiboot_tag_requested(params, MULTIBOOT_TAG_TYPE_XHI_MODULE_EXEC)){
		mb_err_printf("kernel does not support pre-mapped executable modules\n");
		multiboot_errno = MBERR_BOOT_FEATURES;
		return (0);
	}
	if (!(module_tag = (struct multiboot_tag_xhi_module_exec *)multiboot_load_module_common(params, module, len, MULTIBOOT_TAG_TYPE_XHI_MODULE_EXEC, sizeof (struct multiboot_tag_xhi_module_exec), argv, argc))){
		return (0);
	}

	sections_tag = (struct multiboot_tag_xhi_sections *)multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_XHI_MODULE_SECTIONS, sizeof (struct multiboot_tag_xhi_sections));
	if (!sections_tag){
		return (0);
	}
	sections_tag->address_size = 0;

	switch (((Elf32_Ehdr *)(module))->e_ident[EI_CLASS]){
		case ELFCLASS32:
			elf_class = "32";
			sections_tag->entry = pu.elf32->e_entry;
			sections_tag->address_size = 4;
			break;
		case ELFCLASS64:
			elf_class = "64";
			sections_tag->entry = pu.elf64->e_entry;
			sections_tag->address_size = 8;
			break;
		default:
			multiboot_errno = MBERR_EXEC_FORMAT;
			return (0);
	}

	printf("   [elf%s module @ 0x%llx, %u bytes, %u with padding]\n", elf_class, (unsigned long long)module_tag->mod_start, (unsigned int)len, (unsigned int)mem_len);

	module_tag->padding_end = module_tag->mod_start + mem_len;
	module_tag->sections = (unsigned long)sections_tag;
	/*TODO: make this an option that can be set on a per-module basis rather than always preloading when paged loading is enabled and never preloading when it isn't*/
	if (params->paged){
		sections_tag->load_type = MULTIBOOT_LOAD_RELOC;
	}else{
		sections_tag->load_type = MULTIBOOT_LOAD_LAYOUT;
	}

	if (!multiboot_load_elf(params, sections_tag, module, len, 1)){
		return (0);
	}



	/* if a section extends off the end of the executable, adjust the module end
	 * to account for it */
	for (i = 0; i < sections_tag->num_sections; i++){
		struct multiboot_exec_section *section = &sections_tag->sections[i];
		unsigned long mem_size = MULTIBOOT_SECTION_FIELD(section, mem_end) - MULTIBOOT_SECTION_FIELD(section, mem_start);
		unsigned long file_size = MULTIBOOT_SECTION_FIELD(section, file_end) - MULTIBOOT_SECTION_FIELD(section, file_start);

		if (mem_size > file_size){
			unsigned long real_file_end = MULTIBOOT_SECTION_FIELD(section, file_end) + mem_size - file_size;
			if (real_file_end > module_tag->mod_end){
				module_tag->mod_end = real_file_end;
			}
		}
	}

	return (1);
}

int multiboot_relocate_section(struct multiboot_exec_params *params, const struct multiboot_tag_xhi_sections *sections_tag, struct multiboot_exec_section *section, struct multiboot_exec_section *prev_section){
	unsigned long max_phys_addr = multiboot_get_max_phys_addr(params);
	char *file_start = (char *)(unsigned long)MULTIBOOT_SECTION_FIELD(section, file_start);
	char *mem_start = (char *)(unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_start);
	char *mem_end = (char *)(unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_end);
	size_t file_size = MULTIBOOT_SECTION_FIELD(section, file_end) - MULTIBOOT_SECTION_FIELD(section, file_start);
	size_t mem_size = MULTIBOOT_SECTION_FIELD(section, mem_end) - MULTIBOOT_SECTION_FIELD(section, mem_start);

	if (sections_tag->load_type == MULTIBOOT_LOAD_LAYOUT){
		unsigned long offset;
		if (!prev_section){
			/*if this is the first section, don't move it*/
			return (1);
		}
		if (MULTIBOOT_SECTION_FIELD(section, mem_start) < MULTIBOOT_SECTION_FIELD(prev_section, mem_end) ||
				(file_size != 0 && MULTIBOOT_SECTION_FIELD(section, file_start) < MULTIBOOT_SECTION_FIELD(prev_section, file_end))){
			mb_err_printf("section at 0x%lx:0x%lx is lower than previous section at 0x%lx:0x%lx\n", (unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_start), (unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_end), (unsigned long)MULTIBOOT_SECTION_FIELD(prev_section, mem_start), (unsigned long)MULTIBOOT_SECTION_FIELD(prev_section, mem_end));
			mb_err_printf("current section file range: 0x%lx:0x%lx, previous section file range: 0x%lx:0x%lx\n", (unsigned long)MULTIBOOT_SECTION_FIELD(section, file_start), (unsigned long)MULTIBOOT_SECTION_FIELD(section, file_end), (unsigned long)MULTIBOOT_SECTION_FIELD(prev_section, file_start), (unsigned long)MULTIBOOT_SECTION_FIELD(prev_section, file_end));

			multiboot_errno = MBERR_BOOT_FEATURES;
			return (0);
		}
		offset = (((unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_start) - (unsigned long)MULTIBOOT_SECTION_FIELD(prev_section, mem_end)) - ((unsigned long)MULTIBOOT_SECTION_FIELD(section, file_start) - (unsigned long)MULTIBOOT_SECTION_FIELD(prev_section, file_end)));
		mem_start = file_start + offset;
		mem_end = mem_start + file_size;
	}

	if ((unsigned long)mem_start > (unsigned long)max_phys_addr || (unsigned long)mem_end > (unsigned long)max_phys_addr){
		mb_err_printf("section at 0x%lx:0x%lx extends above maximum available physical address (0x%lx) (destination: 0x%lx:0x%lx)\n", (unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_start), (unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_end), max_phys_addr, (unsigned long)mem_start, (unsigned long)mem_end);
		multiboot_errno = MBERR_BOOT_FEATURES;
		return (0);
	}

	memmove(mem_start, file_start, mem_size);
	MULTIBOOT_SET_SECTION_FIELD(section, file_start, (unsigned long)mem_start);
	MULTIBOOT_SET_SECTION_FIELD(section, file_end, (unsigned long)mem_end);

	if (mem_size > file_size){
		memset(mem_start + file_size, '\0', mem_size - file_size);
	}

	return (1);
}

#define MULTIBOOT_MAX_RESERVED_RANGES 16
struct multiboot_reserved_range {
	multiboot_uint64_t start;
	multiboot_uint64_t end;
	const char *description;
};

struct multiboot_reserved_range *reserved_ranges[MULTIBOOT_MAX_RESERVED_RANGES];
unsigned int num_reserved_ranges = 0;

int multiboot_reserve_range(unsigned long start, unsigned long end, const char *description)
{
	if (num_reserved_ranges > MULTIBOOT_MAX_RESERVED_RANGES){
		mb_err_printf("internal error: maximum number of reserved address ranges exceeded\n");
		multiboot_errno = MBERR_INTERNAL;
		return (0);
	}
	reserved_ranges[num_reserved_ranges]->start = start;
	reserved_ranges[num_reserved_ranges]->end = end;
	reserved_ranges[num_reserved_ranges]->description = description;
	return (1);
}

static inline int ranges_overlap(uint64_t start1, uint64_t end1, uint64_t start2, uint64_t end2)
{
	return ((start1 > start2 && start1 < end2) ||
			(end1 > start2 && end1 < end2));
}

void MULTIBOOT_TEXT_QUALIFIER multiboot_start_kernel(struct multiboot_exec_params *params)
{
	const struct multiboot_tag *tag = (const struct multiboot_tag *)((const char *)params->mbi + sizeof (struct multiboot_info));
	const struct multiboot_tag_xhi_sections *sections_tag = NULL; 

	multiboot_errno = 0;

	while ((const char *)tag < params->_mb_alloc_start && tag->type != MULTIBOOT_TAG_TYPE_END){
		int section_index, range_index;
		const struct multiboot_tag_xhi_module_exec *module_tag;
		uint64_t exec_start;
		uint64_t padding_end;

		switch (tag->type){
			case MULTIBOOT_TAG_TYPE_XHI_MODULE_EXEC:
				module_tag = (const struct multiboot_tag_xhi_module_exec *)tag;
				sections_tag = 	(const struct multiboot_tag_xhi_sections *)((unsigned long)(module_tag->sections));
				exec_start = (uint64_t)(unsigned long)module_tag->mod_start;
				padding_end = (uint64_t)(unsigned long)module_tag->padding_end;
				break;
			case MULTIBOOT_TAG_TYPE_XHI_KERNEL_SECTIONS:
				sections_tag = 	(struct multiboot_tag_xhi_sections *)tag;
				exec_start = (uint64_t)(unsigned long)params->kernel;
				padding_end = (uint64_t)(unsigned long)(params->kernel + params->kernel_mem_len);
				break;
			default:
				sections_tag = NULL;
		}
		if (sections_tag){
			for (section_index = sections_tag->num_sections - 1; section_index >= 0; section_index--){
				struct multiboot_exec_section *section = &(((struct multiboot_tag_xhi_sections *)sections_tag)->sections[section_index]);
				struct multiboot_exec_section *prev_section = NULL;
				if (section_index > 0){
					prev_section = &(((struct multiboot_tag_xhi_sections *)sections_tag)->sections[section_index - 1]);
				}
				multiboot_uint64_t image_start = (multiboot_uint64_t)(unsigned long)params->fs_image;
				multiboot_uint64_t section_start = MULTIBOOT_SECTION_FIELD(section, mem_start);
				multiboot_uint64_t section_file_end = MULTIBOOT_SECTION_FIELD(section, file_end);
				multiboot_uint64_t section_mem_end = MULTIBOOT_SECTION_FIELD(section, mem_end);
				multiboot_uint64_t image_end;
				{
					multiboot_uint64_t mem_size = section_mem_end - section_start;
					multiboot_uint64_t file_size = MULTIBOOT_SECTION_FIELD(section, mem_end) - MULTIBOOT_SECTION_FIELD(section, mem_start);
					if (mem_size > file_size && !(section->flags & MB_SEC_W)){
						/* Are there any cases where this might occur? Probably not.
						 * Check for it anyways though.*/
						mb_err_printf("read-only executable section at 0x%llx contains a bss area\n", MULTIBOOT_SECTION_FIELD(section, mem_start));
						multiboot_errno = MBERR_EXEC_FORMAT;
						return;
					}
				}

				if (!params->paged && sections_tag->load_type == MULTIBOOT_LOAD_RELOC){
					if (image_start){
						image_end = (multiboot_uint64_t)(unsigned long)params->fs_image + params->fs_image_len;
						/* these have to be handled specially because the reserved
						 * ranges are different for each section */
						if (exec_start >= image_start && padding_end <= image_end){
							if (ranges_overlap(section_start, section_mem_end, image_start, exec_start)){
								mb_err_printf("executable section address range (0x%llx-0x%llx) overlaps beginning of boot image (0x%llx-0x%llx)\n", section_start, section_mem_end, image_start, exec_start);
								multiboot_errno = MBERR_OVERLAPPING_SECTION;
								return;
							}else if (ranges_overlap(section_start, section_mem_end, padding_end, image_end)) {
								mb_err_printf("executable section address range (0x%llx-0x%llx) overlaps end of boot image (0x%llx-0x%llx)\n", section_start, section_mem_end, padding_end, image_end);
								multiboot_errno = MBERR_OVERLAPPING_SECTION;
								return;
							}
						}else{
							if (ranges_overlap(section_start, section_mem_end, image_start, image_end)){
								printf("executable section address range (0x%llx-0x%llx) overlaps boot image (0x%llx-0x%llx)\n", section_start, section_mem_end, padding_end, image_end);
								multiboot_errno = MBERR_OVERLAPPING_SECTION;
								return;
							}
						}
					}
					for (range_index = 0; range_index < num_reserved_ranges; range_index++){
						struct multiboot_reserved_range *range = reserved_ranges[range_index];
						if (ranges_overlap(section_start, section_mem_end, range->start, range->end)){
							mb_err_printf("executable section address range (0x%llx-0x%llx) overlaps %s (0x%llx-0x%llx)\n", section_start, section_mem_end, range->description, range->start, range->end);
							multiboot_errno = MBERR_OVERLAPPING_SECTION;
							return;
						}
					}
				}
				if (!multiboot_check_section(params, sections_tag, section)){
					if (!multiboot_errno){
						multiboot_errno = MBERR_INTERNAL;
						mb_err_printf("warning: multiboot_check_section not setting multiboot_errno");
					}
					return;
				}

				if (params->paged || sections_tag->load_type == MULTIBOOT_LOAD_CLEAR){
					/*TODO: support copying writable sections if it is requested*/

					if (!params->writable_section_uip && params->paged){
						printf("TODO: implement auto-copying of writable image sections\n");
						multiboot_errno = MBERR_INTERNAL;
						return;
					}

					if (section_mem_end > section_file_end){
						size_t extra_len = section_mem_end - section_file_end;
						/* TODO: support BSS sections in the middle of the
						 * executable when loading with paging enabled (although
						 * there would usually be less need for them since such
						 * kernels don't need separate identity-mapped sections
						 */
						if (section_index != sections_tag->num_sections - 1){
							mb_err_printf("section at virtual address %llx contains a BSS area but is not the last in the file\n", section_start);
							multiboot_errno = MBERR_EXEC_FORMAT;
							return;
						}
						if (image_start && ranges_overlap(section_file_end, section_file_end + extra_len, padding_end, image_end)){
							printf("executable section address range (0x%llx-0x%llx) overlaps end of boot image (0x%llx-0x%llx)\n", section_start, section_mem_end, padding_end, image_end);
							multiboot_errno = MBERR_OVERLAPPING_SECTION;
							return;

						}
						memset((char *)(unsigned long)section_file_end, '\0', extra_len);
						/* add the extra length to the file end field because
						 * the length is the same in both places*/
						MULTIBOOT_SET_SECTION_FIELD(section, file_end, section_file_end + extra_len);
					}

					if (params->paged && !multiboot_map_section(params, sections_tag, section)){
						mb_err_printf("cannot map Multiboot section: %s\n", multiboot_strerror(multiboot_errno));
						return;
					}
				}else if (sections_tag->load_type == MULTIBOOT_LOAD_LAYOUT || sections_tag->load_type == MULTIBOOT_LOAD_RELOC){
					if (!multiboot_relocate_section(params, sections_tag, section, prev_section)){
						mb_err_printf("cannot relocate Multiboot section: %s\n", multiboot_strerror(multiboot_errno));
						return;
					}
				}
			}
		}

		tag = (struct multiboot_tag *)(((unsigned long)tag + tag->size + 7) & (~7));
	}
	if (!multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_END, sizeof (struct multiboot_tag))){
		mb_err_printf("cannot allocate Multiboot info end tag: %s\n", multiboot_strerror(multiboot_errno));
		return;
	}
	params->mbi->total_size = (char *)params->_mb_alloc_start - (char *)params->mbi;

	printf("Booting the kernel...\n\n");
	multiboot_boot_kernel(params);
}

int MULTIBOOT_TEXT_QUALIFIER multiboot_init(struct multiboot_exec_params *params, struct multiboot_arch_params *arch_params)
{
	memset(params, '\0', sizeof (struct multiboot_exec_params));
	params->arch_params = arch_params;
	params->os_name = "OS";

	return (1);
}

/*int multiboot_load_fs_image_internal(struct multiboot_exec_params *params, void *image, size_t len, char *const argv[], int argc, unsigned flags);

int MULTIBOOT_TEXT_QUALIFIER multiboot_load_fs_image(struct multiboot_exec_params *params, void *image, size_t len, char *const argv[], int argc, unsigned flags)
{
	return (multiboot_load_fs_image_internal(params, image, len, argv, argc, flags));
}*/
