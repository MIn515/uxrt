/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */

/* Configuration for MultiBoot, see MultiBoot Specification:
   www.gnu.org/software/grub/manual/multiboot
   We use a flags field of 3, indicating that we want modules loaded on page
   boundaries and access to the memory map information. We do not set bit 16,
   indicating that the structure of the image should be taken from its ELF
   headers. */

#include <config.h>
#include <machine/assembler.h>

#define MULTIBOOT_HEADER_MAGIC 0x1BADB002

#ifdef CONFIG_MULTIBOOT_GRAPHICS_MODE_NONE
    #define MULTIBOOT_HEADER_FLAGS 3
    #define MULTIBOOT_GRAPHICS_TEXT 0
#else /* CONFIG_MULTIBOOT_GRAPHICS_MODE_NONE */
    #define MULTIBOOT_HEADER_FLAGS 7
    #ifdef CONFIG_MULTIBOOT_GRAPHICS_MODE_TEXT
        #define MULTIBOOT_GRAPHICS_TEXT 1
    #else /* CONFIG_MULTIBOOT_GRAPHICS_MODE_TEXT */
        #define MULTIBOOT_GRAPHICS_TEXT 0
    #endif /* CONFIG_MULTIBOOT_GRAPHICS_MODE_TEXT */
#endif /* CONFIG_MULTIBOOT_GRAPHICS_MODE_NONE */

/* These configs will be set if a graphics mode is set. if they aren't
 * then we can put whatever in the multiboot header and it will be ignored.
 * This seems to be the easiest way to make things compile */
#ifndef CONFIG_MULTIBOOT_GRAPHICS_MODE_HEIGHT
#define CONFIG_MULTIBOOT_GRAPHICS_MODE_HEIGHT 0
#endif
#ifndef CONFIG_MULTIBOOT_GRAPHICS_MODE_WIDTH
#define CONFIG_MULTIBOOT_GRAPHICS_MODE_WIDTH 0
#endif
#ifndef CONFIG_MULTIBOOT_GRAPHICS_MODE_DEPTH
#define CONFIG_MULTIBOOT_GRAPHICS_MODE_DEPTH 0
#endif

.section .mbh
#ifdef CONFIG_MULTIBOOT1_HEADER
    /* MultiBoot header */
    .align  4
    .long   MULTIBOOT_HEADER_MAGIC; /*magic*/
    .long   MULTIBOOT_HEADER_FLAGS; /*flags*/
    .long   - MULTIBOOT_HEADER_FLAGS - MULTIBOOT_HEADER_MAGIC; /*checksum*/
    .long   0 /*header_addr*/
    .long   0 /*load_addr*/
    .long   0 /*load_end_addr*/
    .long   0 /*bss_end_addr*/
    .long   0 /*entry_addr*/
    .long   MULTIBOOT_GRAPHICS_TEXT /*mode_type*/
    .long   CONFIG_MULTIBOOT_GRAPHICS_MODE_WIDTH /*width*/
    .long   CONFIG_MULTIBOOT_GRAPHICS_MODE_HEIGHT /*height*/
    .long   CONFIG_MULTIBOOT_GRAPHICS_MODE_DEPTH /*depth*/
#endif

#define MULTIBOOT2_HEADER_MAGIC 0xe85250d6
#define MULTIBOOT_ARCHITECTURE_I386  0
#define MULTIBOOT_HEADER_TAG_END 0
#define MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST 1
#define MULTIBOOT_TAG_MODULE_EXEC 0x93
#define MULTIBOOT_TAG_MODULE_IMAGE 0xb3
#define MULTIBOOT_HEADER_TAG_OPTIONAL 1

#ifdef CONFIG_MULTIBOOT2_HEADER
    .align  8
    __mbi2_start:
    /* magic multi-boot 2 header */
    .long   MULTIBOOT2_HEADER_MAGIC
    .long   MULTIBOOT_ARCHITECTURE_I386
    .long   (__mbi2_end - __mbi2_start)
    .long  -(MULTIBOOT2_HEADER_MAGIC + (__mbi2_end - __mbi2_start))
    __request_start:
    /* information request tag */
    .short MULTIBOOT_HEADER_TAG_INFORMATION_REQUEST
    /* flags */
    .word MULTIBOOT_HEADER_TAG_OPTIONAL
    /* size */
    .long __request_end - __request_start
    /* tag types */
    .long MULTIBOOT_TAG_MODULE_EXEC
    .long MULTIBOOT_TAG_MODULE_IMAGE
    __request_end:
    /* end tag - type, flags, size */
    .word   MULTIBOOT_HEADER_TAG_END
    .word   0x0
    .long   0x8
    __mbi2_end:
#endif
