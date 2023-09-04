/*
 * UX/RT
 *
 * Header for the platform-independent part of the Multiboot loader
 *
 * Copyright (c) 2011-2022 Andrew Warkentin
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
#ifndef __MULTIBOOT_GENERIC_H
#define __MULTIBOOT_GENERIC_H

#include "multiboot2.h"
#include "multiboot_archdep.h"

/* Error numbers returned by functions in this library */

#define MBERR_NOERROR 0
#define MBERR_INTERNAL 1
#define MBERR_EXEC_FORMAT 2
#define MBERR_UNALIGNED_SECTION 3
#define MBERR_OVERLAPPING_SECTION 4
#define MBERR_BOOT_FEATURES 5
#define MBERR_MEM_EXHAUSTED 6
#define MBERR_MBI_EXHAUSTED 7
#define MBERR_NUM 8

#define MB_NO_WRITABLE_SECTION_UIP 1

#define MB_TAG_HANDLER_MULTIPLE 1
#define MB_TAG_HANDLER_RUN_NULL 2

/* Section permissions (passed to multiboot_map_section) */

#define MB_SEC_R 4
#define MB_SEC_W 2
#define MB_SEC_X 1

#define MBI_MINSIZE 1048576

/* Executable types detected by multiboot_init */
#define MB_EXEC_ELF32 0
#define MB_EXEC_ELF64 1
#define MB_EXEC_KLUDGE 2

struct multiboot_exec_params {
	const char *kernel;
	size_t kernel_len;
	size_t kernel_mem_len;
	const struct multiboot_header *mbh;
	size_t header_offset;
	char *fs_image;
	char * const *fs_image_argv;
	int fs_image_argc;
	long fs_image_addr;
	size_t fs_image_len;
	size_t fs_image_page_size;
	const struct multiboot_xrfs_header *fs_image_mbh;
	int fs_module_found;
	int fs_mbh_above_modules;
	unsigned long fs_last_mod_end;
	size_t _cur_fs_image_len;
	int kernel_flags;
	struct multiboot_info *mbi;
	int exec_type;
	multiboot_uint64_t entry;
	size_t address_size;
	size_t page_size;
	size_t max_mbi_size;
	int writable_section_uip;
	char *_mb_alloc_start;
	const struct multiboot_header_tag_address *address_tag;
	struct multiboot_arch_params *arch_params;
	int paged;
	struct multiboot_header_tag_fs_module *last_fs_module_tag;
	char *os_name;
	char *os_ver;
	int compressed;
};

extern int multiboot_errno;

typedef int (*multiboot_header_tag_handler_func)(struct multiboot_exec_params *, void *);
typedef int (*multiboot_info_tag_handler_func)(struct multiboot_exec_params *, int);

#define MBI_ALLOC_PAGE_ALIGNED 1

const char *multiboot_strerror(int mb_errnum);

int multiboot_init(struct multiboot_exec_params *params, struct multiboot_arch_params *arch_params);

struct multiboot_tag *multiboot_allocate_mbi_tag(struct multiboot_exec_params *params, multiboot_uint16_t type, size_t size);
void *multiboot_reallocate_mbi_tag(struct multiboot_exec_params *params, void *tag, size_t extra_size);
void *multiboot_reallocate_mbi_tag_aligned(struct multiboot_exec_params *params, void *tag, size_t size);
void *multiboot_copy_mbi_tag(struct multiboot_exec_params *params, const struct multiboot_tag *orig_tag);
int multiboot_tag_requested(struct multiboot_exec_params *params, multiboot_uint16_t type);
struct multiboot_header_tag *multiboot_get_header_tag(struct multiboot_exec_params *params, multiboot_uint16_t type, int index);

int multiboot_load_fs_image(struct multiboot_exec_params *params, void *image, size_t len, char *const argv[], int argc, unsigned flags);

int multiboot_load_kernel(struct multiboot_exec_params *params, char *const argv[], int argc, const void *kernel, size_t len, size_t mem_len, unsigned flags);
int multiboot_load_module(struct multiboot_exec_params *params, const void *module, size_t len, char *const argv[], int argc);
int multiboot_load_module_exec(struct multiboot_exec_params *params, const void *module, size_t len, size_t mem_len, char *const argv[], int argc);
int multiboot_load_module_image(struct multiboot_exec_params *params, void *module, size_t len, char *const argv[], int argc);
int multiboot_load_module_special(struct multiboot_exec_params *params, const void *module, size_t len, char *const name);

void multiboot_start_kernel(struct multiboot_exec_params *params);

int multiboot_set_mbi_address(struct multiboot_exec_params *params, void *addr, size_t size);
int multiboot_move_mbi(struct multiboot_exec_params *params, void *addr, size_t size);

int multiboot_reserve_range(unsigned long start, unsigned long end, const char *description);

int handle_tag_null(struct multiboot_exec_params *params, struct multiboot_tag *tag);

#define MULTIBOOT_SECTION_FIELD(section, field) (sections_tag->address_size == 8 ? section->regions.r64.field : (uint64_t)section->regions.r32.field)
#define MULTIBOOT_SET_SECTION_FIELD(section, field, value) do { if (sections_tag->address_size == 8) section->regions.r64.field = value; else section->regions.r32.field = value; } while(0);

#define DIV_ROUNDUP(a, b) (((a) + ((b) - 1)) / (b))

#define ALIGN_UP(x, a) ({ \
    typeof(x) value = x; \
    typeof(a) align = a; \
    value = DIV_ROUNDUP(value, align) * align; \
    value; \
})

#endif /* __MULTIBOOT_GENERIC_H */
