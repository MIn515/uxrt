/*
 * Main function of the platform-independent part of the loader
 *
 * UX/RT
 *
 * Copyright (c) 2010-2022 Andrew Warkentin
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

/* Architecture-specific functions required:
 *
 * void loader_halt()    Should halt the system; should be provided by
 *                include/loader/halt.h in either the CPU or platform includes*/

#include <loader_stdlib/stdint.h>
#include <loader_stdlib/string.h>
#include <loader_stdlib/stdlib.h>
#include <loader_stdlib/stdio.h>
#include <loader_stdlib/stdarg.h>
#include <loader_stdlib/ctype.h>
#include <lzma.h>
#include "cpu/support.h"
#include "multiboot2.h"
#include "multiboot2_lib/multiboot.h"
#include "boot.h"
#include "load.h"
#include "panic.h"
#include "halt.h"
#include "util.h"

unsigned long find_mem_region(struct multiboot_exec_params *params, unsigned long start, unsigned long end)
{
	int i = 0;
	struct multiboot_tag_mmap *mmap = params->arch_params->mmap;
	struct multiboot_mmap_entry *entry = mmap->entries;

	/* first, check if the requested address can accommodate the requested
	 * size*/
	while ((char *)entry < (char *)mmap + mmap->size){
		multiboot_uint64_t entry_end = entry->addr + entry->len;
		//printf("addr: %llx end: %llx\n", entry->addr, entry->addr + entry->len);
		if (start >= entry->addr && start <= entry_end && end <= entry_end && entry->type == MULTIBOOT_MEMORY_AVAILABLE){
			return start;
		}
		i++;
		entry = &mmap->entries[i];
		
	}
	i = 0;
	entry = mmap->entries;
	/* otherwise, try to find one above it that can */
	while ((char *)entry < (char *)mmap + mmap->size){
		if (start >= entry->addr && entry->len >= end - start && entry->type == MULTIBOOT_MEMORY_AVAILABLE){
			return (unsigned long)entry->addr;
		}
		i++;
		entry = &mmap->entries[i];
	}
	return (0);
}

void panic(char *format, ...){
	/* This function prints an error message and halts the system. */
	va_list args;
	va_start(args, format);
	printf("panic: ");
	vprintf(format, args);
	printf("\n");
	loader_halt();
}

void *multiboot_decompress_image(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag, size_t *len)
{
	unsigned char *src = (unsigned char *)params->fs_image + tag->mod_start;
	unsigned char *dst = (unsigned char *)params->fs_image + tag->padding_end;

	*len = lzma_size(src);

	if (*len == (unsigned long)-1){
		panic("image size unspecified");
	}

	if (!(dst = (unsigned char *)find_mem_region(params, (unsigned long)dst, (unsigned long)dst + *len))){
		panic("insufficient memory for image decompression");
	}

	size_t total_argv_size = params->fs_image_argc * sizeof (char *);
	for (int i = 0; i < params->fs_image_argc; i++){
		total_argv_size += strlen(params->fs_image_argv[i]) + 1;
	}
	unsigned long new_argv_start = ALIGN_UP((unsigned long)dst + *len, sizeof (char *));
	if (!(new_argv_start = find_mem_region(params, new_argv_start, new_argv_start + total_argv_size))){
		panic("insufficient temporary memory for image command line");
	}
	char **new_argv = (char **)new_argv_start;
	char *arg = (char *)new_argv_start + params->fs_image_argc * sizeof (char *);
	for (int i = 0; i < params->fs_image_argc; i++){
		strcpy(arg, params->fs_image_argv[i]);
		new_argv[i] = arg;
		arg += strlen(arg) + 1;
	}
	params->fs_image_argv = new_argv;

	*len = ulzma(src, dst);
	if (*len == 0){
		panic("failed to uncompress image");
	}
	return dst;
}

#define MAX_ARGC_COUNT 256

int loader_get_argv(const char *string, size_t length, int *argc, char ***argv)
{
	/* This function parses a string into an array of arguments and an array
	 * length. */
	char *command;
	const char *start, *end = string + length;
	*argc = 0;
	for (start = string; start != end; start++){
		if (!isspace(*start)){
			break;
		}
	}
	if (start == end){
		*argv = malloc(1);
		(*argv)[0] = '\0';
		return (1);
	}
	*argv = malloc(MAX_ARGC_COUNT * sizeof (unsigned long));
	command = malloc(end - start + 1);
	command[end - start] = '\0';
	memcpy(command, start, end - start);
	{
		char *c = command;
		while(*c != '\0' && *argc < MAX_ARGC_COUNT) {
			(*argv)[(*argc)++] = c;
			for( ; *c != '\0' && !isspace(*c); c++){
				if (!isgraph(*c) && !isspace(*c)){
					return (0);
				}
			}

			if (*c) {
				*c = 0;
				c++;
			}
		}
	}
	/*realloc(*argv, (*argc) * (sizeof (size_t)));*/
	return (1);
}

void loader_boot_image(struct multiboot_arch_params *arch_params, void *image, size_t len, char *const argv[], int argc)
{
	struct multiboot_exec_params params;
	if (!multiboot_init(&params, arch_params)){
		panic("cannot initialize Multiboot state: %s", multiboot_strerror(multiboot_errno));
	}

	if (!init_mbi(&params)){
		panic("cannot initialize MBI");
	}

	if (!multiboot_load_fs_image(&params, image, len, argv, argc, 0)){
		panic("cannot load boot FS image: %s", multiboot_strerror(multiboot_errno));
	}

	multiboot_start_kernel(&params);
	if (multiboot_errno){
		panic("cannot start kernel: %s", multiboot_strerror(multiboot_errno));
	}else{
		panic("multiboot_start_kernel returned without setting multiboot_errno - this should never happen");
	}
}
