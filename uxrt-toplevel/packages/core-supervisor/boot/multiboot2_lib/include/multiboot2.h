/*  multiboot2.h - Multiboot 2 header file.  */
/*  Copyright (C) 2017-2022  Andrew Warkentin
 *  Copyright (C) 1999,2003,2007,2008,2009,2010  Free Software Foundation, Inc.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL ANY
 *  DEVELOPER OR DISTRIBUTOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *  WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 *  IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef MULTIBOOT_HEADER
#define MULTIBOOT_HEADER 1

/*FIXME: this is specific to GCC (and other compilers that support its extensions)*/
#define MULTIBOOT2_PACKED __attribute__((packed))

/* How many bytes from the start of the file we search for the header.  */
#define MULTIBOOT_SEARCH			32768
#define MULTIBOOT_HEADER_ALIGN			8

/* The magic field of the kernel header should contain this.  */
#define MULTIBOOT2_HEADER_MAGIC			0xe85250d6

/* The first magic field of the FS image header should contain this.  */
#define MULTIBOOT2_XRFS_HEADER_MAGIC0		0xe85250d7

/* MULTIBOOT2_XRFS_HEADER_MAGIC1 is defined in multiboot2_lib/arch.h instead,
 * since it is defined differently depending on byte order in order to always
 * appear as "XRFS" regardless of byte order */

/* This should be in %eax.  */
#define MULTIBOOT2_BOOTLOADER_MAGIC		0x36d76289

/* Alignment of multiboot modules.  */
#define MULTIBOOT_MOD_ALIGN			0x00001000

/* Alignment of the multiboot info structure.  */
#define MULTIBOOT_INFO_ALIGN			0x00000008

/* Flags set in the 'flags' member of the multiboot header.  */

#define MULTIBOOT_TAG_ALIGN                  8
#define MULTIBOOT_TAG_TYPE_END               0
#define MULTIBOOT_TAG_TYPE_CMDLINE           1
#define MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME  2
#define MULTIBOOT_TAG_TYPE_MODULE            3
#define MULTIBOOT_TAG_TYPE_BASIC_MEMINFO     4
#define MULTIBOOT_TAG_TYPE_BOOTDEV           5
#define MULTIBOOT_TAG_TYPE_MMAP              6
#define MULTIBOOT_TAG_TYPE_VBE               7
#define MULTIBOOT_TAG_TYPE_FRAMEBUFFER       8
#define MULTIBOOT_TAG_TYPE_ELF_SECTIONS      9
#define MULTIBOOT_TAG_TYPE_APM               10
#define MULTIBOOT_TAG_TYPE_EFI32             11
#define MULTIBOOT_TAG_TYPE_EFI64             12
#define MULTIBOOT_TAG_TYPE_SMBIOS            13
#define MULTIBOOT_TAG_TYPE_ACPI_OLD          14
#define MULTIBOOT_TAG_TYPE_ACPI_NEW          15
#define MULTIBOOT_TAG_TYPE_NETWORK           16
#define MULTIBOOT_TAG_TYPE_EFI_MMAP          17
#define MULTIBOOT_TAG_TYPE_EFI_BS            18

#define MULTIBOOT_TAG_TYPE_XHI_INFO_OFFSET 0x82
#define MULTIBOOT_TAG_TYPE_XHI_MODULE_EXEC  0x93
#define MULTIBOOT_TAG_TYPE_XHI_MODULE_IMAGE      0xb3
#define MULTIBOOT_TAG_TYPE_XHI_MODULE_SPECIAL    0xc3
#define MULTIBOOT_TAG_TYPE_XHI_PAGE_TABLES       0xf0
#define MULTIBOOT_TAG_TYPE_XHI_GDT       0xf1
#define MULTIBOOT_TAG_TYPE_XHI_MODULE_SECTIONS       0xf2
#define MULTIBOOT_TAG_TYPE_XHI_KERNEL_SECTIONS       0xf3

#define MULTIBOOT_HEADER_TAG_END  0
#define MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST  1
#define MULTIBOOT_HEADER_TAG_ADDRESS 2
#define MULTIBOOT_HEADER_TAG_ENTRY_ADDRESS  3
#define MULTIBOOT_HEADER_TAG_CONSOLE_FLAGS  4
#define MULTIBOOT_HEADER_TAG_FRAMEBUFFER  5
#define MULTIBOOT_HEADER_TAG_MODULE_ALIGN  6
#define MULTIBOOT_HEADER_TAG_EFI_BS  7

#define MULTIBOOT_HEADER_TAG_XHI_COMPATIBILITY  0x88
#define MULTIBOOT_HEADER_TAG_XHI_MAP_KERNEL_SECTIONS  0x89
#define MULTIBOOT_HEADER_TAG_XHI_ADDRESS_SIZE 0x8A

#define MULTIBOOT_HEADER_TAG_FS_ADDRESS 0xa0
#define MULTIBOOT_HEADER_TAG_FS_PAGE_SIZE 0xa1
#define MULTIBOOT_HEADER_TAG_FS_EXPAND 0xa2
#define MULTIBOOT_HEADER_TAG_FS_OS_NAME 0xa3
#define MULTIBOOT_HEADER_TAG_FS_OS_VERSION 0xa4
#define MULTIBOOT_HEADER_TAG_FS_KERNEL 0xa5
#define MULTIBOOT_HEADER_TAG_FS_MODULE 0xa6
#define MULTIBOOT_HEADER_TAG_FS_MODULE_EXEC 0xa7
#define MULTIBOOT_HEADER_TAG_FS_MODULE_SPECIAL 0xa8
#define MULTIBOOT_HEADER_TAG_FS_INFO_OFFSET 0xa9

#define MULTIBOOT_ARCHITECTURE_I386  0
#define MULTIBOOT_ARCHITECTURE_MIPS32  4
#define MULTIBOOT_HEADER_TAG_OPTIONAL 1

#define MULTIBOOT_CONSOLE_FLAGS_CONSOLE_REQUIRED 1
#define MULTIBOOT_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED 2

#define MULTIBOOT_XHI_ENV_TYPE_BAREMETAL 0x1
#define MULTIBOOT_XHI_ENV_TYPE_PVH 0x2
#define MULTIBOOT_XHI_ENV_TYPE_HVM 0x4

#ifndef __ASSEMBLY__

typedef unsigned char		multiboot_uint8_t;
typedef unsigned short		multiboot_uint16_t;
typedef unsigned int		multiboot_uint32_t;
typedef unsigned long long	multiboot_uint64_t;

struct multiboot_header
{
	/* Must be MULTIBOOT2_HEADER_MAGIC - see above.  */
	multiboot_uint32_t magic;

	/* ISA */
	multiboot_uint32_t architecture;

	/* Total header length.  */
	multiboot_uint32_t header_length;

	/* The above fields plus this one must equal 0 mod 2^32. */
	multiboot_uint32_t checksum;
};

struct multiboot_xrfs_header
{
	/* Must be MULTIBOOT2_XRFS_HEADER_MAGIC0 in native byte order - see
	 * above.  */
	multiboot_uint32_t magic0;

	/* Must be MULTIBOOT2_XRFS_HEADER_MAGIC1 in big endian - see above.  */
	multiboot_uint32_t magic1;

	/* Total header length.  */
	multiboot_uint32_t header_length;

	/* Total image length including anything outside the header (may be the
	 * same as the header length).  */
	multiboot_uint32_t total_length;

	/* The above fields plus this one must equal 0 mod 2^32. */
	multiboot_uint32_t checksum;

	multiboot_uint32_t reserved;
};

struct multiboot_header_tag
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
};

struct multiboot_header_tag_information_request
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t requests[0];
};

struct multiboot_header_tag_address
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t header_addr;
	multiboot_uint32_t load_addr;
	multiboot_uint32_t load_end_addr;
	multiboot_uint32_t bss_end_addr;
};

struct multiboot_header_tag_entry_address
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t entry_addr;
};

struct multiboot_header_tag_console_flags
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t console_flags;
};

struct multiboot_header_tag_framebuffer
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t width;
	multiboot_uint32_t height;
	multiboot_uint32_t depth;
};

struct multiboot_header_tag_module_align
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
};

struct multiboot_header_tag_xhi_address_size
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t address_size;
};

struct multiboot_header_tag_xhi_map_kernel_sections
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
};

struct multiboot_header_tag_xhi_compatibility
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t xhi_version;
	multiboot_uint32_t xhi_min_version;
	multiboot_uint32_t environments;
};

struct multiboot_header_tag_fs_string
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	char string[0];
};

struct multiboot_header_tag_fs_address
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint64_t phys_addr;
	multiboot_uint64_t virt_addr;
};

struct multiboot_header_tag_fs_page_size
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t page_size;
	multiboot_uint32_t reserved;
};

struct multiboot_header_tag_fs_info_offset
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t offset;
	multiboot_uint32_t reserved;
};

struct multiboot_header_tag_fs_module
{
	multiboot_uint16_t type;
	multiboot_uint16_t flags;
	multiboot_uint32_t size;
	multiboot_uint32_t mod_start;
	multiboot_uint32_t mod_end;
	multiboot_uint32_t padding_end;
	char cmdline[0];
};

struct multiboot_color
{
	multiboot_uint8_t red;
	multiboot_uint8_t green;
	multiboot_uint8_t blue;
};

struct multiboot_mmap_entry
{
	multiboot_uint64_t addr;
	multiboot_uint64_t len;
#define MULTIBOOT_MEMORY_AVAILABLE		1
#define MULTIBOOT_MEMORY_RESERVED		2
#define MULTIBOOT_MEMORY_ACPI_RECLAIMABLE       3
#define MULTIBOOT_MEMORY_NVS                    4
#define MULTIBOOT_MEMORY_BADRAM                 5
	multiboot_uint32_t type;
	multiboot_uint32_t zero;
} MULTIBOOT2_PACKED;
typedef struct multiboot_mmap_entry multiboot_memory_map_t;

struct multiboot_tag
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
};

struct multiboot_tag_string
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	char string[0];
};

struct multiboot_tag_module
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t mod_start;
	multiboot_uint32_t mod_end;
	char cmdline[0];
};

struct multiboot_exec_section_32
{
	multiboot_uint32_t file_start;
	multiboot_uint32_t mem_start;
	multiboot_uint32_t file_end;
	multiboot_uint32_t mem_end;
};

struct multiboot_exec_section_64
{
	multiboot_uint64_t file_start;
	multiboot_uint64_t mem_start;
	multiboot_uint64_t file_end;
	multiboot_uint64_t mem_end;
};

struct multiboot_exec_section
{
	multiboot_uint32_t flags;
	union {
		struct multiboot_exec_section_32 r32;
		struct multiboot_exec_section_64 r64;
	} regions;
} MULTIBOOT2_PACKED;

/* this can be used by kernels if they only want to deal with modules built to
 * the kernel's native word size rather than having to deal with unions */

struct multiboot_exec_section_word
{
	multiboot_uint32_t flags;
	unsigned long file_start;
	unsigned long mem_start;
	unsigned long file_end;
	unsigned long mem_end;
} MULTIBOOT2_PACKED;

struct multiboot_tag_xhi_module_exec
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t mod_start;
	multiboot_uint32_t mod_end;
	multiboot_uint32_t padding_end;
	multiboot_uint32_t sections;
	char cmdline[0];
};

struct multiboot_tag_xhi_sections
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t num_sections;
/* clear any BSS areas, but don't move any sections*/
#define MULTIBOOT_LOAD_CLEAR 0
/* move the sections so that the source layout matches the destination layout,
 * but don't move them to their destination addresses */
#define MULTIBOOT_LOAD_LAYOUT 1
/* move the sections to their destination addresses */
#define MULTIBOOT_LOAD_RELOC 2
	multiboot_uint32_t load_type;
	multiboot_uint32_t address_size;
	multiboot_uint64_t entry;
	struct multiboot_exec_section sections[0];
} MULTIBOOT2_PACKED;

struct multiboot_tag_xhi_sections_word
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t num_sections;
	multiboot_uint32_t load_type;
	multiboot_uint32_t address_size;
	multiboot_uint64_t entry;
	struct multiboot_exec_section_word sections[0];
} MULTIBOOT2_PACKED;

struct multiboot_tag_xhi_info_offset
{
	multiboot_uint32_t type;
	multiboot_uint32_t flags;
	multiboot_uint32_t offset;
	multiboot_uint32_t reserved;
};

struct multiboot_tag_basic_meminfo
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t mem_lower;
	multiboot_uint32_t mem_upper;
};

struct multiboot_tag_bootdev
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t biosdev;
	multiboot_uint32_t slice;
	multiboot_uint32_t part;
};

struct multiboot_tag_mmap
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t entry_size;
	multiboot_uint32_t entry_version;
	struct multiboot_mmap_entry entries[0];
};

struct multiboot_vbe_info_block
{
	multiboot_uint8_t external_specification[512];
};

struct multiboot_vbe_mode_info_block
{
	multiboot_uint8_t external_specification[256];
};

struct multiboot_tag_vbe
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;

	multiboot_uint16_t vbe_mode;
	multiboot_uint16_t vbe_interface_seg;
	multiboot_uint16_t vbe_interface_off;
	multiboot_uint16_t vbe_interface_len;

	struct multiboot_vbe_info_block vbe_control_info;
	struct multiboot_vbe_mode_info_block vbe_mode_info;
};

struct multiboot_tag_framebuffer_common
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;

	multiboot_uint64_t framebuffer_addr;
	multiboot_uint32_t framebuffer_pitch;
	multiboot_uint32_t framebuffer_width;
	multiboot_uint32_t framebuffer_height;
	multiboot_uint8_t framebuffer_bpp;
#define MULTIBOOT_FRAMEBUFFER_TYPE_INDEXED 0
#define MULTIBOOT_FRAMEBUFFER_TYPE_RGB     1
#define MULTIBOOT_FRAMEBUFFER_TYPE_EGA_TEXT	2
	multiboot_uint8_t framebuffer_type;
	multiboot_uint16_t reserved;
};

struct multiboot_tag_framebuffer
{
	struct multiboot_tag_framebuffer_common common;

	union
	{
		struct
		{
			multiboot_uint16_t framebuffer_palette_num_colors;
			struct multiboot_color framebuffer_palette[0];
		};
		struct
		{
			multiboot_uint8_t framebuffer_red_field_position;
			multiboot_uint8_t framebuffer_red_mask_size;
			multiboot_uint8_t framebuffer_green_field_position;
			multiboot_uint8_t framebuffer_green_mask_size;
			multiboot_uint8_t framebuffer_blue_field_position;
			multiboot_uint8_t framebuffer_blue_mask_size;
		};
	};
};

struct multiboot_tag_elf_sections
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t num;
	multiboot_uint32_t entsize;
	multiboot_uint32_t shndx;
	char sections[0];
};

struct multiboot_tag_apm
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint16_t version;
	multiboot_uint16_t cseg;
	multiboot_uint32_t offset;
	multiboot_uint16_t cseg_16;
	multiboot_uint16_t dseg;
	multiboot_uint16_t flags;
	multiboot_uint16_t cseg_len;
	multiboot_uint16_t cseg_16_len;
	multiboot_uint16_t dseg_len;
};

struct multiboot_tag_efi32
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t pointer;
};

struct multiboot_tag_efi64
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint64_t pointer;
};

struct multiboot_tag_smbios
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint8_t major;
	multiboot_uint8_t minor;
	multiboot_uint8_t reserved[6];
	multiboot_uint8_t tables[0];
};

struct multiboot_tag_old_acpi
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint8_t rsdp[0];
};

struct multiboot_tag_new_acpi
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint8_t rsdp[0];
};

struct multiboot_tag_network
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint8_t dhcpack[0];
};

struct multiboot_tag_efi_mmap
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	multiboot_uint32_t descr_size;
	multiboot_uint32_t descr_vers;
	multiboot_uint8_t efi_mmap[0];
};

struct multiboot_tag_xhi_page_tables
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	char page_tables[0];
};

struct multiboot_tag_xhi_gdt
{
	multiboot_uint32_t type;
	multiboot_uint32_t size;
	char gdt[0];
};

struct multiboot_info
{
	multiboot_uint32_t total_size;
	multiboot_uint32_t reserved;
};

#endif /* ! __ASSEMBLY__ */

#endif /* ! MULTIBOOT_HEADER */
