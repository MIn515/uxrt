/*
 * UX/RT
 *
 * Header for the architecture-dependent part of the Multiboot loader (these
 * functions must be provided by the loader linked with this library)
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
#ifndef __MULTIBOOT_ARCH_H
#define __MULTIBOOT_ARCH_H

#define __BIG_ENDIAN 4321
#define __LITTLE_ENDIAN 1234

#include "multiboot2.h"

#include "multiboot_archdep.h"
#include "multiboot2_lib/generic.h"

/* The second magic field of the FS image header should contain this.  */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define MULTIBOOT2_XRFS_HEADER_MAGIC1           0x53465258
#elif __BYTE_ORDER == __BIG_ENDIAN
#define MULTIBOOT2_XRFS_HEADER_MAGIC1           0x58524653
#else
#error __BYTE_ORDER not properly set
#endif

int multiboot_arch_init(struct multiboot_exec_params *params);
/* Starts initializing the architecture-dependent part of the loader. Called before the kernel is loaded.
 *
 * Parameters:
 * struct multiboot_exec_params *params:        The Multiboot state/parameters structure.
 *
 * Should return 1 on success and 0 on failure.
 */

int multiboot_kernel_loaded(struct multiboot_exec_params *params);
/* Finishes initializing the architecture-dependent part of the loader. Called after the kernel is loaded.
 *
 * Parameters:
 * struct multiboot_exec_params *params:        The Multiboot state/parameters structure.
 *
 * Should return 1 on success and 0 on failure.
 */



int multiboot_get_page_size(struct multiboot_exec_params *params);
/* Returns the page size that should be used when loading the kernel. */

void *multiboot_allocate_mbi(struct multiboot_exec_params *params, size_t minsize, size_t *size);
/* Allocates the Multiboot info block.
 *
 * Parameters:
 *
 * struct multiboot_exec_params *params:        The Multiboot state/parameters structure.
 *
 * size_t minsize                     The minimum size of the Multiboot info
 *                                    block.
 * uint64_t *size                     This should be set to the size of the
 *                                    block that is allocated (may be larger
 *                                    than minsize.
 */

int multiboot_map_section(struct multiboot_exec_params *params, const struct multiboot_tag_xhi_sections *sections_tag, const struct multiboot_exec_section *section);
/* Maps a kernel or module section.
 *
 * If the section is writable and the writable_section_uip flag is false,
 * implementations should copy it rather than mapping it using paging
 * (especially since kernels may reside in ROM). Implementations should abort if
 * the start of a writable section overlaps the last page of a previous
 * read-only section.
 *
 * Parameters:
 *
 * struct multiboot_exec_params *params:        The Multiboot state/parameters
 * structure.
 *
 * struct multiboot_tag_xhi_sections *sections_tag:        The Multiboot
 * sections tag for the executable being loaded.
 *
 * struct multiboot_exec_section *section:        The Multiboot section
 * structure.
 *
 * Should return 1 on success and 0 on failure.
 */

int multiboot_check_image_addr(struct multiboot_exec_params *params);
/* Should return true if the image start address and length are valid, false otherwise
 *
 * Parameters:
 *
 * struct multiboot_exec_params *params:        The Multiboot state/parameters
 * structure.
 */

int multiboot_check_section(struct multiboot_exec_params *params, const struct multiboot_tag_xhi_sections *sections_tag, const struct multiboot_exec_section *section);
/* Should return true if the section is valid, false otherwise
 *
 * Parameters:
 *
 * struct multiboot_exec_params *params:        The Multiboot state/parameters
 * structure.
 *
 * struct multiboot_tag_xhi_sections *sections_tag:        The Multiboot
 * sections tag for the executable being loaded.
 *
 * struct multiboot_exec_section *section:        The Multiboot section
 * structure.
 *
 */

unsigned long multiboot_get_max_phys_addr(const struct multiboot_exec_params *params);
/* Gets the maximum usable physical address.
 *
 * struct multiboot_exec_params *params:        The Multiboot state/parameters
 * structure.
 *
 */

void *multiboot_decompress_image(struct multiboot_exec_params *params, struct multiboot_header_tag_fs_module *tag, size_t *len);
/* Decompresses an inner compressed XRFS image.
 *
 * struct multiboot_exec_params *params:        The Multiboot state/parameters
 * structure.
 *
 * struct multiboot_tag_fs_module tag:          The module tag of the inner
 * image. It is safe to place the decompressed image immediately after the
 * compressed image since the outer MBH won't be used again.
 *
 * size_t *len:                                 The length of the decompressed
 * image should be written to this.
 */

void multiboot_boot_kernel(struct multiboot_exec_params *params);
/* Boots the kernel.
 *
 * struct multiboot_exec_params *params:        The Multiboot state/parameters
 * structure.
 *
 * This function should never return. If the kernel cannot be booted for some
 * reason, it should halt the system.
 */


/*These functions usually do not need to be implemented in most loaders.*/

#ifdef CUSTOM_MULTIBOOT_CONVERT_MBI_ADDR

uint64_t multiboot_convert_mbi_addr(void *addr);
/* Converts a Multiboot info address used in the loader to one that will be used
 * in a Multiboot info field that the kernel will access. Most of the time, the
 * addresses are the same, so there is usually no need to override this
 * function.
 *
 * Parameters:
 * void *addr                         The address to convert.
 *
 * Should return the converted address.
 *
 */

#else
#define multiboot_convert_mbi_addr(addr) ((uint64_t)((uint32_t)(addr)))
#endif

#ifdef CUSTOM_MULTIBOOT_MAP_MODULE
uint64_t multiboot_map_module(struct multiboot_exec_params *params, const char *module, size_t module_size);
/* Maps a module that is not loaded as an executable.
 *
 * Modules should normally be identity mapped (unless they are loaded as
 * executables) because doing otherwise will usually make it more difficult for
 * the kernel to re-map modules. Therefore, there is usually no need to override
 * this function.
 *
 * Parameters:
 * struct multiboot_exec_params *params:        The Multiboot state/parameters
 * structure.
 *
 * char *module                       Pointer to the beginning of the module to
 *                                    map.
 * size_t module_size                 The size of the module.
 *
 * Should return the virtual address at which the module has been mapped, or
 * NULL on failure.
 */

#else

#define multiboot_map_module(params, module, size) ((multiboot_uint32_t)(unsigned long)(module))

#endif


#ifndef MULTIBOOT_DATA_QUALIFIER
#define MULTIBOOT_DATA_QUALIFIER
#endif
#ifndef MULTIBOOT_TEXT_QUALIFIER
#define MULTIBOOT_TEXT_QUALIFIER
#endif

#endif /* __MULTIBOOT_ARCH_H */
