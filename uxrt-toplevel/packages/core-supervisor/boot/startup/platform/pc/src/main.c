/*
 * Main function for the PC port of the loader
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

/* Standard includes */
#include <loader_stdlib/stddef.h>
#include <loader_stdlib/string.h>
#include <loader_stdlib/stdlib.h>
#include <loader_stdlib/stdio.h>

/* libpayload includes */
#include <libpayload.h>
#include <sysinfo.h>

#include <multiboot2.h>

/* RT/XH includes */
#include "loader_config.h"
#include "multiboot2_lib/multiboot.h"
#include "boot.h"
#include "util.h"
#include "panic.h"
#include "load.h"
#include "cpu/support.h"
#include "cpu/cpuid.h"
#include "cpu/cpufeature.h"

struct multiboot_arch_params arch_params;

int loaded_into_ram;

void *boot_image;
size_t boot_image_size;
char *boot_image_name;

size_t strlcpy(char *dst, const char *src, size_t dstsize)
{
	size_t srcsize;
	if ((srcsize = strlen(src)) >= dstsize){
		dst[dstsize - 1] = '\0';
		strncpy(dst, src, dstsize - 1);
		return (dstsize);
	}else{
		strcpy(dst, src);
		return (srcsize);
	}
}

int main(int argc, char **argv)
{
	unsigned long orig_mbi_address;
	unsigned long boot_image_address;

	printf(".\n");

	if (cpuid_check_features(CPUID_LEVEL_AMD_EXT_PROCESSOR_INFO, CPUID_REG_EDX, bitmaskof(X86_FEATURE_LM))){
		arch_params.x86_64_supported = 1;
	}else{
		arch_params.x86_64_supported = 0;
	}
	if (sysinfo_have_multiboot(&orig_mbi_address)){
		loaded_into_ram = 1;
		arch_params.chained_from_type = BOOT_TYPE_MULTIBOOT2;
		arch_params.orig_mbi = (struct multiboot_info *)orig_mbi_address;
	}else{
		loaded_into_ram = 0;
		panic("TODO: implement coreboot support");
	}

	if (!sysinfo_have_xrfs(&boot_image_address)){
		panic("no XRFS image passed to startup1");
	}

	struct multiboot_xrfs_header *boot_image = phys_to_virt(boot_image_address);
	loader_boot_image(&arch_params, (char *)boot_image, boot_image->total_length, argv, argc);

	panic("loader_boot_image returned - this should never happen");
	return (1);
}
