/*
 * C support functions for the loader on x86
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

#include <stdio.h>

#include "loader_config.h"
#include "loader_stdlib/stdlib.h"
#include "loader_stdlib/sys/types.h"
#include "loader_stdlib/string.h"
#include "cpu/cpuid.h"
#include "cpu/cpufeature.h"
#include "panic.h"
#include "cpu/support.h"
#include "multiboot2_lib/multiboot.h"
/*TODO: don't create identity mappings for address ranges that don't contain any memory or I/O*/
/*TODO: move this over to x86_common (there may be a need for a 64-bit loader, e.g. on UEFI systems)*/

/*XXX: make sure this is packed (define a macro that expands to a compiler-specific directive)*/
struct gdt_entry {
		uint16_t limit_low;
		uint16_t base_low;
		uint8_t base_middle;
		uint8_t access;
		uint8_t granularity;
		uint8_t base_high;
};

#define GDT64_SIZE 3
static struct gdt_entry default_gdt64[GDT64_SIZE] = {
	{
		.limit_low = 0,
		.base_low = 0,
		.base_middle = 0,
		.access = 0,
		.granularity = 0,
		.base_high = 0
	},
	{
		.limit_low = 0,
		.base_low = 0,
		.base_middle = 0,
		.access = 0x9a,
		.granularity = 0x20,
		.base_high = 0
	},
	{
		.limit_low = 0,
		.base_low = 0,
		.base_middle = 0,
		.access = 0x92,
		.granularity = 0x20,
		.base_high = 0
	},
};

#if 0
uint32_t *init_gdt_32(uint32_t **addr)
{
	/*TODO: finish this function (create a GDT, but don't load it)*/
}
#endif
uint32_t *init_page_tables_32(struct multiboot_exec_params *params)
{
	uint32_t *page_dir;
	uint32_t page_dir_index, phys_addr = 0;

	if (!(params->arch_params->page_tables_tag = (struct multiboot_tag_xhi_page_tables *)multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_XHI_PAGE_TABLES, sizeof (struct multiboot_tag_xhi_page_tables)))){
		panic("cannot allocate initial page directory: %s", multiboot_strerror(multiboot_errno));
	}

	if (!(page_dir = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_SIZE))){
		panic("cannot allocate initial page directory: %s", multiboot_strerror(multiboot_errno));
	}

	/* PSE is required because large pages are used to map identity-mapped
	 * regions. Most x86 processors support it (the original Pentium was the
	 * first with PSE, and most x86 processors later than that support it), so
	 * this shouldn't usually be a problem.*/
	if (!cpuid_check_features(CPUID_LEVEL_PROCESSOR_INFO, CPUID_REG_EDX, bitmaskof(X86_FEATURE_PSE))){
		panic("processor does not support PSE");
	}

	/* allocate the initial page directory out of the Multiboot info area (the
	 * kernel will have to set up its own when it modifies page mappings)*/
	for (page_dir_index = 0; page_dir_index < 1024; page_dir_index++){
		page_dir[page_dir_index] = phys_addr | DEFAULT_PAGE_FLAGS_32 | PAGE_LARGE;
		phys_addr += LARGE_PAGE_SIZE_32;
	}
	
	return (page_dir);
}

void *init_gdt_64(struct multiboot_exec_params *params, size_t *size)
{
	params->arch_params->gdt_size = sizeof (struct gdt_entry) * GDT64_SIZE;
	if (!cpuid_check_features(CPUID_LEVEL_AMD_EXT_PROCESSOR_INFO, CPUID_REG_EDX, bitmaskof(X86_FEATURE_LM))){
		panic("processor does not support x86-64");
	}

	if (!(params->arch_params->gdt_tag = (struct multiboot_tag_xhi_gdt *)multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_XHI_PAGE_TABLES, sizeof (struct multiboot_tag_xhi_gdt) + params->arch_params->gdt_size))){
		panic("cannot allocate initial GDT: %s", multiboot_strerror(multiboot_errno));
	}

	memcpy(params->arch_params->gdt_tag->gdt, default_gdt64, params->arch_params->gdt_size);
	return (params->arch_params->gdt_tag->gdt);
}

/*FIXME: these should be in a platform-specific header*/
#define NUM_IDENTITY_PML4E 1
#define MAX_IDENTITY_MAP_ADDR 0xfffff000

uint64_t *init_page_tables_64(struct multiboot_exec_params *params)
{
	uint64_t pml4t_index, pdpt_index, page_dir_index;
	uint64_t *pml4t;
	uint64_t phys_addr = 0;

	if (!cpuid_check_features(CPUID_LEVEL_AMD_EXT_PROCESSOR_INFO, CPUID_REG_EDX, bitmaskof(X86_FEATURE_LM))){
		panic("processor does not support x86-64");
	}


	if (!(params->arch_params->page_tables_tag = (struct multiboot_tag_xhi_page_tables *)multiboot_allocate_mbi_tag(params, MULTIBOOT_TAG_TYPE_XHI_PAGE_TABLES, sizeof (struct multiboot_tag_xhi_page_tables)))){
		panic("cannot allocate initial PML4T: %s", multiboot_strerror(multiboot_errno));
	}

	if (!(pml4t = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_SIZE))){
		panic("cannot allocate initial PML4T: %s", multiboot_strerror(multiboot_errno));
	}

	memset(pml4t, 0, PAGE_SIZE);
	for (pml4t_index = 0; pml4t_index < NUM_IDENTITY_PML4E; pml4t_index++){
		uint64_t *pdpt;
		unsigned long pdpt_phys_addr;
		if (!(pdpt = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_TABLE_SIZE))){
			panic("cannot allocate initial PDPT: %s", multiboot_strerror(multiboot_errno));
		}
		pdpt_phys_addr = (unsigned long)pdpt;
		pml4t[pml4t_index] = (uint64_t)pdpt_phys_addr | DEFAULT_PAGE_FLAGS_64;
		for (pdpt_index = 0; pdpt_index < 512; pdpt_index++){
			uint64_t *page_dir;
			unsigned long page_dir_phys_addr;
			if (!(page_dir = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_TABLE_SIZE))){
				panic("cannot allocate initial page directory: %s", multiboot_strerror(multiboot_errno));
			}
		
			page_dir_phys_addr = (unsigned long)page_dir;
			pdpt[pdpt_index] = page_dir_phys_addr | DEFAULT_PAGE_FLAGS_64;
			for (page_dir_index = 0; page_dir_index < 1024; page_dir_index++){
				page_dir[page_dir_index] = phys_addr | DEFAULT_PAGE_FLAGS_32 | PAGE_LARGE;
				phys_addr += L2_LARGE_PAGE_SIZE_64;
				if (phys_addr > MAX_IDENTITY_MAP_ADDR){
					goto out;
				}
			}
		}
	}
out:
	return (pml4t);
}

void map_section_32(struct multiboot_exec_params *params, uint32_t section, uint32_t addr, size_t len, int writable)
{
	uint32_t *page_table;
	uint32_t orig_page = section;
	uint32_t page = addr;
	uint64_t end = addr + len;
	uint32_t page_flags = PAGE_PRESENT;
	if (writable){
		page_flags |= PAGE_WRITABLE;
	}

	while (page < end){
		if (params->arch_params->page_dir[PDE_INDEX_32(page)] & PAGE_LARGE){
			/* if the region in which the page exists is a large page, replace
			 * it with a page table */
			size_t phys_addr = (size_t)page & PDE_MASK_32;
			int i;

			if (!(page_table = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_TABLE_SIZE))){
				panic("cannot allocate initial page table: %s", multiboot_strerror(multiboot_errno));
			}
			params->arch_params->page_dir[PDE_INDEX_32(page)] = (size_t)page_table | page_flags;
			for (i = 0; i < 1024; i++){
				page_table[i] = phys_addr | DEFAULT_PAGE_FLAGS_32;
				phys_addr += PAGE_SIZE;
			}
		}else{
			page_table = (uint32_t *)(params->arch_params->page_dir[PDE_INDEX_32(page)] & ADDR_MASK_32);
		}
		page_table[PTE_INDEX_32(page)] = orig_page | page_flags;
		page += PAGE_SIZE;
		orig_page += PAGE_SIZE;
	}
}

void map_section_64(struct multiboot_exec_params *params, uint64_t section, uint64_t addr, size_t len, int page_type, int writable)
{
	uint64_t *page_table;
	long orig_page = section;
	uint64_t page = addr;
	uint64_t end = addr + len;
	uint64_t *pdpt, *page_dir;
	uint64_t pdpe;
	uint64_t pde;
	unsigned long pdpt_addr;
	unsigned long page_dir_addr;
	unsigned long page_table_addr;
	uint64_t page_flags = DEFAULT_PAGE_FLAGS_64;
	if (writable){
		page_flags |= PAGE_WRITABLE;
	}

	while (page < end){
		unsigned long pml4e = params->arch_params->pml4t[PML4E_INDEX_64(page)];

		if (!(pml4e & PAGE_PRESENT)){
			/* if the region in which the page exists is not present, replace it
			 * with a PDPT */
			/*size_t phys_addr = (size_t)page & PML4E_MASK_64;*/
			/*int i;*/
			if (!(pdpt = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_SIZE))){
				panic("cannot allocate initial page directory: %s", multiboot_strerror(multiboot_errno));
			}
			memset(pdpt, 0, PAGE_SIZE);
			pdpt_addr = (unsigned long)pdpt;
			params->arch_params->pml4t[PML4E_INDEX_64(page)] = (uint64_t)pdpt_addr | page_flags;
			pdpe = 0;
		}else{
			pdpt_addr = pml4e & ADDR_MASK_64;
			pdpt = (uint64_t *)pdpt_addr;
			pdpe = pdpt[PDPE_INDEX_64(page)];
		}

		if (page_type == PAGE_1G){
			pdpt[PDPE_INDEX_64(page)] = (uint64_t)page | page_flags | PAGE_LARGE;
			page += 0x40000000;
			continue;
		}else if (!(pdpe & PAGE_PRESENT) || pdpe & PAGE_LARGE){
			/* if the region in which the page exists is a large page or not
			 * present, replace it with a page directory */
			/*size_t phys_addr = (size_t)page & PDPE_MASK_64;*/
			/*int i;*/
			if (!(page_dir = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_SIZE))){
				panic("cannot allocate initial page directory: %s", multiboot_strerror(multiboot_errno));
			}
			page_dir_addr = (unsigned long)page_dir;
			pdpt[PDPE_INDEX_64(page)] = (uint64_t)page_dir_addr | page_flags;

			memset(page_dir, 0, PAGE_SIZE);
			pde = 0;
		}else{
			page_dir_addr = (unsigned long)(pdpt[PDPE_INDEX_64(page)] & ADDR_MASK_64);
			page_dir = (uint64_t *)page_dir_addr;
			pde = page_dir[PDE_INDEX_64(page)];
		}


		if (page_type == PAGE_2M){
			page_dir[PDE_INDEX_64(page)] = (uint64_t)page | page_flags | PAGE_LARGE;
			page += 0x200000;
			continue;
		}else if (!(pde & PAGE_PRESENT) || pde & PAGE_LARGE){
			/* if the region in which the page exists is a large page, replace
			 * it with a page directory */
			if (!(page_table = multiboot_reallocate_mbi_tag_aligned(params, params->arch_params->page_tables_tag, PAGE_SIZE))){
				panic("cannot allocate initial page directory: %s", multiboot_strerror(multiboot_errno));
			}
			page_table_addr = (unsigned long)page_table;
			page_dir[PDE_INDEX_64(page)] = (uint64_t)page_table_addr | page_flags;
			memset(page_table, 0, PAGE_SIZE);
		}else{
			page_table_addr = (unsigned long)(page_dir[PDE_INDEX_64(page)] & ADDR_MASK_64);
			page_table = (uint64_t *)page_table_addr;
		}

		page_table[PTE_INDEX_64(page)] = orig_page | page_flags;
		page += PAGE_SIZE;
		orig_page += PAGE_SIZE;
	}
}
