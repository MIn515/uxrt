/*
 * RT/XH
 *
 * Header for compile-time configuration of the architecture-dependent part of
 * the Multiboot loader. A loader may provide its own implementation if it needs
 * to override anything.
 *
 * Copyright (c) 2011 Andrew Warkentin
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
#ifndef __MULTIBOOT_ARCHDEP_H
#define __MULTIBOOT_ARCHDEP_H

#define MULTIBOOT_ARCHITECTURE_CURRENT MULTIBOOT_ARCHITECTURE_I386
#define __BYTE_ORDER __LITTLE_ENDIAN

#define BOOT_TYPE_MULTIBOOT2 0

struct multiboot_pc_video_info_vbe {
	uint32_t vbe_control_info;
	uint32_t vbe_mode_info;
	uint32_t vbe_mode;
	uint32_t vbe_interface_seg;
	uint32_t vbe_interface_off;
	uint32_t vbe_interface_len;
};

struct multiboot_arch_params {
	struct multiboot_tag_mmap *mmap;
	int vbe_video_info_valid;
	struct multiboot_pc_video_info_vbe vbe_video_info;
	uint32_t *page_dir;
	uint64_t *pml4t;
	void *gdt;
	size_t gdt_size;
	struct multiboot_tag_xhi_page_tables *page_tables_tag;
	struct multiboot_tag_xhi_gdt *gdt_tag;
	int x86_64_supported;
	char *boot_image;
	size_t boot_image_size;
	int chained_from_type;
	struct multiboot_info *orig_mbi;
};

#define USE_MULTIBOOT_ALLOCATE_MBI
#endif /* __MULTIBOOT_ARCHDEP_H */
