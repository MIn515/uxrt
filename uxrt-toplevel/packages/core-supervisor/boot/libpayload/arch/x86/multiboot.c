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

#include <libpayload-config.h>
#include <libpayload.h>
#include <multiboot_tables.h>

extern unsigned long loader_eax;
extern unsigned long loader_ebx;
extern unsigned long loader_ecx;
extern unsigned long loader_edx;

static void mb_parse_mmap(unsigned long mmap_addr, unsigned long mmap_end,
			struct sysinfo_t *info, size_t entry_size)
{
	u8 *start = (u8 *) phys_to_virt(mmap_addr);
	u8 *ptr = start;

	info->n_memranges = 0;

	while((unsigned long)ptr < mmap_end) {
		struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) ptr;

#ifdef CONFIG_MEMMAP_RAM_ONLY
		/* 1 == normal RAM.  Ignore everything else for now */

		if (mmap->type == 1) {
#endif
			info->memrange[info->n_memranges].base = mmap->addr;
			info->memrange[info->n_memranges].size = mmap->len;
			info->memrange[info->n_memranges].type = mmap->type;

			if (++info->n_memranges == SYSINFO_MAX_MEM_RANGES)
				return;
#ifdef CONFIG_MEMMAP_RAM_ONLY
		}
#endif

#ifdef CONFIG_MULTIBOOT1
		ptr += (mmap->size + sizeof(mmap->size));
#elif defined (CONFIG_MULTIBOOT2)
		ptr += sizeof (struct multiboot_mmap_entry);
#endif
	}
}

static void mb_parse_cmdline(unsigned long cmdline)
{
	extern int main_argc;
	extern char *main_argv[];
	char *c = phys_to_virt(cmdline);

	while(*c != '\0' && main_argc < MAX_ARGC_COUNT) {
		main_argv[main_argc++] = c;

		for( ; *c != '\0' && !isspace(*c); c++);

		if (*c) {
			*c = 0;
			c++;
		}
	}
}

int get_multiboot_info(struct sysinfo_t *info)
{
	struct multiboot_info *table;

	if (loader_eax != MULTIBOOT_MAGIC)
		return -1;

	table = (struct multiboot_info *) phys_to_virt(loader_ebx);

	info->mbtable = phys_to_virt(loader_ebx);

#ifdef CONFIG_MULTIBOOT1
	if (table->flags & MULTIBOOT_FLAGS_MMAP)
		mb_parse_mmap(table->mmap_addr, table->mmap_addr + table->mmap_length, info, 0);

	if (table->flags & MULTIBOOT_FLAGS_CMDLINE)
		mb_parse_cmdline(table->cmdline);
#elif defined (CONFIG_MULTIBOOT2)
	struct multiboot_tag const *tag = (struct multiboot_tag *)(table + 1);
	struct multiboot_tag const *end = (struct multiboot_tag *)((unsigned long)table + table->total_size);
	while (tag < end && tag->type != MULTIBOOT_TAG_TYPE_END){
		if (tag->type == MULTIBOOT_TAG_TYPE_CMDLINE){
			mb_parse_cmdline((unsigned long)((struct multiboot_tag_string *)tag)->string);
		}else if (tag->type == MULTIBOOT_TAG_TYPE_MMAP){
			struct multiboot_tag_mmap* mmap_tag = (struct multiboot_tag_mmap *)tag;
			mb_parse_mmap((unsigned long)mmap_tag->entries, (unsigned long)((char *)tag + tag->size), info, mmap_tag->entry_size);
		}
		tag = (struct multiboot_tag const *)((unsigned long)tag + tag->size);
	}
	if (loader_ecx == MULTIBOOT2_XRFS_HEADER_MAGIC0){
		info->xrfsimg = phys_to_virt(loader_edx);
	}else{
		info->xrfsimg = NULL;
	}

#endif

	

	return 0;
}
