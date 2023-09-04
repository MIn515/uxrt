/*
 *
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

#include "loader_stdlib/stdio.h"
#include "loader_stdlib/stdlib.h"
#include "loader_stdlib/sys/types.h"
#include "loader_stdlib/string.h"
#include "loader_stdlib/stddef.h"
#include <libpayload.h>
#include "multiboot2.h"
#include "multiboot2_lib/multiboot.h"
#include "load.h"
#include "panic.h"
#include "boot.h"
#include "cpu/support.h"
#include "cpu/load.h"

#define SCRATCH_MBI_SIZE 65536

char scratch_mbi[SCRATCH_MBI_SIZE];

extern char *_start, *_end;

unsigned long loader_exec_start = (unsigned long)&_start;
unsigned long loader_exec_end = (unsigned long)&_end;

/*TODO: make sure that actual RAM is present when allocating after the end of the Multiboot info */
/*TODO: if there is any I/O memory outside the first 4G, identity map it*/

/*TODO: base this on the actual memory map from e820*/

#define MULTIBOOT_INFO_SIZE 10485760

int init_mbi(struct multiboot_exec_params *params)
{
	multiboot_set_mbi_address(params, (char *)&scratch_mbi, SCRATCH_MBI_SIZE);

	struct multiboot_tag const *tag = (struct multiboot_tag *)(params->arch_params->orig_mbi + 1);
        struct multiboot_tag const *end = (struct multiboot_tag *)((unsigned long)params->arch_params->orig_mbi + params->arch_params->orig_mbi->total_size);

	while (tag < end && tag->type != MULTIBOOT_TAG_TYPE_END){
		int copy = 0;
		switch(tag->type){
			case MULTIBOOT_TAG_TYPE_MODULE:
				panic("external modules passed to boot image");
				break;
			case MULTIBOOT_TAG_TYPE_MMAP:	
			case MULTIBOOT_TAG_TYPE_ACPI_NEW:
			case MULTIBOOT_TAG_TYPE_ACPI_OLD:
			case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
			case MULTIBOOT_TAG_TYPE_VBE:
				copy = 1;
		}
		if (copy){
			void *new_tag;
			if (!(new_tag = multiboot_copy_mbi_tag(params, tag))){
				panic("failed to copy Multiboot tag");
			}
			if (tag->type == MULTIBOOT_TAG_TYPE_MMAP){
				params->arch_params->mmap = (struct multiboot_tag_mmap *)new_tag;
			}
		}
		unsigned long size = tag->size;
		tag = (struct multiboot_tag const *)((unsigned long)tag + ALIGN_UP(size, MULTIBOOT_TAG_ALIGN));
        }

	if (!params->arch_params->mmap){
		panic("bootloader failed to pass a memory map");
	}
	return (1);
}

int move_mbi(struct multiboot_exec_params *params)
{
	unsigned long info_addr = (unsigned long)PAGE_ALIGN((char *)params->fs_image + params->fs_image_len);
	struct multiboot_info *mbi = (struct multiboot_info *)find_mem_region(params, info_addr, MULTIBOOT_INFO_SIZE);
	if (!mbi){
		panic("no free memory for Multiboot info");
	}
	multiboot_move_mbi(params, mbi, MULTIBOOT_INFO_SIZE);

	return (1);
}


int multiboot_arch_init(struct multiboot_exec_params *params)
{
#if 0
	printf("multiboot_arch_init:\n");
	printf("flags: %x\n", mbh->flags);
	printf("addrsize: %d\n", mbh->addrsize);
	printf("arch: %x\n", mbh->arch);
	printf("checksum: %x\n", mbh->checksum);
#endif
	/*TODO: call init_gdt_32 so that the GDT value is defined for both 32-bit and 64-bit architectures*/
	/*TODO: the pointer for the reserved area for the GDT and page tables should be passed to the OS as a tag; there should be free space in this area so that e.g. an IDT can be created in it*/

	multiboot_reserve_range(virt_to_phys(_start), virt_to_phys(_end), "loader");

	struct multiboot_header_tag_xhi_compatibility *compatibility_tag = (struct multiboot_header_tag_xhi_compatibility *)multiboot_get_header_tag(params, MULTIBOOT_HEADER_TAG_XHI_COMPATIBILITY, 0);

	move_mbi(params);

	if (compatibility_tag && !(compatibility_tag->environments & MULTIBOOT_XHI_ENV_TYPE_BAREMETAL)){
		panic("kernel does not support running directly on hardware");
	}

	if (params->address_size == 8 && !params->arch_params->x86_64_supported){
		panic("cannot boot an x86-64 kernel on an x86-32 processor");
	}
#if 0
	if ((mbh->flags & MULTIBOOT_AOUT_KLUDGE)){
		if ((mbh->addrsize == MULTIBOOT_ADDR32)){
			printf("header_addr: %x\n", mbh->header_addr);
			printf("load_addr: %x\n", mbh->load_addr);
			printf("text_end_addr: %x\n", mbh->text_end_addr);
			printf("data_end_addr: %x\n", mbh->data_end_addr);
			printf("bss_end_addr: %x\n", mbh->bss_end_addr);
			printf("entry_addr: %x\n", mbh->entry_addr);
		}else if ((mbh->addrsize == MULTIBOOT_ADDR64)){
			struct multiboot_header_64 *mbh64 = (struct multiboot_header_64 *)mbh;
			printf("header_addr: %llx\n", mbh64->header_addr);
			printf("load_addr: %llx\n", mbh64->load_addr);
			printf("text_end_addr: %llx\n", mbh64->text_end_addr);
			printf("data_end_addr: %llx\n", mbh64->data_end_addr);
			printf("bss_end_addr: %llx\n", mbh64->bss_end_addr);
			printf("entry_addr: %llx\n", mbh64->entry_addr);
		}
	}
	printf("\n");
#endif
	return (1);
}

int multiboot_get_page_size(struct multiboot_exec_params *params)
{
	return (PAGE_SIZE);
}

#define IDENTITY_MAP_SIZE 0xFFFFF000

void create_initial_mapping_64(struct multiboot_exec_params *params)
{
	map_section_64(params, 0, 0, IDENTITY_MAP_SIZE, PAGE_2M, 1);
}

unsigned long multiboot_get_max_phys_addr(const struct multiboot_exec_params *params){
	/*TODO: return the actual maximum usable address based on the memory map*/
	return (0xffffffff);
}

int multiboot_check_section(struct multiboot_exec_params *params, const struct multiboot_tag_xhi_sections *sections_tag, const struct multiboot_exec_section *section)
{
	uint64_t aligned_mem_start = MULTIBOOT_SECTION_FIELD(section, mem_start) & ~(PAGE_SIZE - 1);

	if (aligned_mem_start < 0x100000 && sections_tag->load_type == MULTIBOOT_LOAD_RELOC){
		panic("relocated executable section load address (0x%llx) below 1MB", aligned_mem_start);
	}

	if (find_mem_region(params, MULTIBOOT_SECTION_FIELD(section, mem_start), MULTIBOOT_SECTION_FIELD(section, mem_end)) != MULTIBOOT_SECTION_FIELD(section, mem_start)){
		panic("section with start at %lx and end at %lx not in a usable memory region", (unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_start), (unsigned long)MULTIBOOT_SECTION_FIELD(section, mem_end));
	}

	return (1);
}

int multiboot_map_section(struct multiboot_exec_params *params, const struct multiboot_tag_xhi_sections *sections_tag, const struct multiboot_exec_section *section)
{
	uint64_t aligned_mem_start = MULTIBOOT_SECTION_FIELD(section, mem_start) & ~(PAGE_SIZE -1);
	size_t mem_size = MULTIBOOT_SECTION_FIELD(section, mem_end) - MULTIBOOT_SECTION_FIELD(section, mem_start);

	if (params->address_size == 8 && !params->arch_params->pml4t){
		params->arch_params->gdt = init_gdt_64(params);
		params->arch_params->pml4t = init_page_tables_64(params);
		create_initial_mapping_64(params);
	}else if (params->address_size != 8 && !params->arch_params->page_dir){
		params->arch_params->page_dir = init_page_tables_32(params);
	}

	/*FIXME: make sure that sections that are shorter in the file than in memory don't overlap with the next section (since the part of the file after the section will get cleared and overwritten)*/
	if (params->address_size == 8){
		map_section_64(params, MULTIBOOT_SECTION_FIELD(section, file_start), aligned_mem_start, mem_size, PAGE_4K, section->flags & MB_SEC_W);
	}else{
		map_section_32(params, MULTIBOOT_SECTION_FIELD(section, file_start), aligned_mem_start, mem_size, section->flags & MB_SEC_W);
	}
	return (1);
}


int multiboot_check_image_addr(struct multiboot_exec_params *params)
{
	if (!params->fs_image_addr){
		params->fs_image_addr = (unsigned long)params->fs_image;
		if (params->fs_image_addr & (LARGE_PAGE_SIZE_32 - 1)){
			params->fs_image_addr = PAGE_ALIGN_LARGE_32(params->fs_image);
		}
	}else if (params->fs_image_addr & (PAGE_SIZE - 1)){
		panic("boot image specifies unaligned physical address 0x%lx", params->fs_image_addr);
	}else if (params->fs_image_addr < 0x100000){
		panic("boot image load address (0x%lx) below 1MB", params->fs_image_addr);
	}

	if ((params->fs_image_addr >= loader_exec_start && params->fs_image_addr <= loader_exec_end) ||
			(params->fs_image_addr + params->fs_image_len >= loader_exec_start && params->fs_image_addr + params->fs_image_len <= loader_exec_end) ||
			(params->fs_image_addr <= loader_exec_start && params->fs_image_addr + params->fs_image_len >= loader_exec_end)){
		panic("boot image overlaps bootloader");
	}

	if (find_mem_region(params, params->fs_image_addr, params->fs_image_addr + params->fs_image_len) != params->fs_image_addr){
		panic("boot image destination region not available");
	}

	return (1);
}

int multiboot_kernel_loaded(struct multiboot_exec_params *params)
{	
	return (1);
}

#define PAGETABLE_ORDER         9
#define L1_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L2_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L3_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
#define L4_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)

#define L1_PAGETABLE_SHIFT      12
#define L2_PAGETABLE_SHIFT      21
#define L3_PAGETABLE_SHIFT      30
#define L4_PAGETABLE_SHIFT      39

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(a)         \
    (((a) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1))
#define l2_table_offset(a)         \
    (((a) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1))
#define l3_table_offset(a)         \
    (((a) >> L3_PAGETABLE_SHIFT) & (L3_PAGETABLE_ENTRIES - 1))
#define l4_table_offset(a)         \
    (((a) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1))

#define PADDR_MASK              ((1UL << PADDR_BITS)-1)
#define PADDR_BITS              52

void multiboot_boot_kernel(struct multiboot_exec_params *params){
	/*Initialize paging and jump to the kernel.*/
	if (params->address_size == 8){
		if (!params->paged){
			panic("64-bit kernel does not support paged loading");
		}
		if (!params->arch_params->pml4t){
			panic("PML4T not initialized (no sections were mapped)?");
		}
		init_paging_64((char *)params->arch_params->pml4t);
		jump_to_kernel_64(params->entry, params->mbi, params->arch_params->gdt, params->arch_params->gdt_size);
	}else{
		if (params->paged){
			if (!params->arch_params->page_dir){
				panic("page directory not initialized (no sections were mapped)?");
			}
			init_paging_32((char *)params->arch_params->page_dir);
			jump_to_kernel_paged_32((uint32_t)params->entry, params->mbi);
		}else{
			jump_to_kernel_unpaged_32((uint32_t)params->entry, params->mbi);
		}
	}

	/* We should never get here. */
	panic("end of multiboot_boot_kernel reached (this should never happen!)");
}
