/*
 * Updates the image start and end addresses in the Multiboot address tag of an
 * image
 *
 * Copyright (C) 2022		Andrew Warkentin
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>  /* Userland pieces of the ANSI C standard I/O package  */
#include <stdlib.h> /* Userland prototypes of the ANSI C std lib functions */
#include <string.h> /* Userland prototypes of the string handling funcs    */
#include <unistd.h> /* Userland prototypes of the Unix std system calls    */
#include <fcntl.h>  /* Flag value for file handling functions	      */
#include <errno.h>
#include <time.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>
#include <limits.h>
#include <stdarg.h>
#include <libgen.h>
#include <stdbool.h>

#include <netinet/in.h>	/* Consts & structs defined by the internet system */

/* good old times without autoconf... */
#if defined(__linux__) || defined(__uxrt__) || defined(__sun__) || defined(__CYGWIN__)
#include <sys/sysmacros.h>
#endif

#define DIV_ROUNDUP(a, b) (((a) + ((b) - 1)) / (b))

#define ALIGN_UP(x, a) ({ \
    typeof(x) value = x; \
    typeof(a) align = a; \
    value = DIV_ROUNDUP(value, align) * align; \
    value; \
})


#define MULTIBOOT2_HEADER_MAGIC      0xe85250d6
#define MULTIBOOT_SEARCH             32768
#define MULTIBOOT_HEADER_ALIGN       8
#define MULTIBOOT_TAG_ALIGN          8
#define MULTIBOOT_HEADER_TAG_END     0
#define MULTIBOOT_HEADER_TAG_ADDRESS 2

struct multiboot_header
{
	/* Must be MULTIBOOT2_HEADER_MAGIC - see above.  */
	uint32_t magic;

	/* ISA */
	uint32_t architecture;

	/* Total header length.  */
	uint32_t header_length;

	/* The above fields plus this one must equal 0 mod 2^32. */
	uint32_t checksum;
};

struct multiboot_header_tag
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;    
};

struct multiboot_header_tag_address
{
	uint16_t type;
	uint16_t flags;
	uint32_t size;
	uint32_t header_addr;
	uint32_t load_addr;
	uint32_t load_end_addr;
	uint32_t bss_end_addr;
};

void showhelp(const char *argv0)
{
	printf("updatembh %s\n",VERSION);
	printf("Usage: %s [options] <image> [directory]\n", argv0);
	printf("Updates the image start and end addresses in the Multiboot address tag of an image\n");
	printf("\n");
	printf("  -v		     Verbose operation\n");
	printf("  -h		     Show this help\n");
	printf("\n");
}

int main(int argc, char *argv[])
{
	int c;
	int verbose = 0;
	int f;
	char *outf = NULL;

	while ((c = getopt(argc, argv, "vh")) != EOF) {
		switch(c) {
		case 'v':
			verbose = 1;
			break;
		case 'h':
			showhelp(argv[0]);
			exit(0);
			break;
		default:
			fprintf(stderr, "%s: invalid argument %c\n", argv[0], c);
			exit(1);
		}
	}

	if (optind == argc) {
		fprintf(stderr, "%s: you must specify the image file name\n", argv[0]);
		fprintf(stderr, "Try `%s -h' for more information\n",argv[0]);
		exit(1);
	}

	outf = argv[optind];

	if (argc - optind > 1){
		fprintf(stderr, "%s: extraneous argument\n", argv[0]);
		exit(1);
	}

	f = open(outf, O_RDWR);

	if (f < 0) {
		fprintf(stderr, "%s: cannot open image ", argv[0]);
		perror(outf);
		exit(1);
	}
	
	struct stat st;
	if (fstat(f, &st) != 0){
		fprintf(stderr, "%s: cannot stat image ", argv[0]);
		perror(outf);
		exit(1);
	}

	char *image;

	if ((image = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, f, 0)) == MAP_FAILED){
		fprintf(stderr, "%s: cannot map image ", argv[0]);
		perror(outf);
		exit(1);
	}

	struct multiboot_header *mbh;
	bool header_found = false;
	for (mbh = (struct multiboot_header *) image;
			((char *) mbh <= (char *) image + MULTIBOOT_SEARCH) || (mbh = 0);
			mbh = (struct multiboot_header *) ((uint32_t *) mbh + MULTIBOOT_HEADER_ALIGN / 4)){
		if (mbh->magic == MULTIBOOT2_HEADER_MAGIC
				&& !(mbh->magic + mbh->architecture
				+ mbh->header_length + mbh->checksum)){
			header_found = true;
			break;
		}
	}

	if (!header_found){
		fprintf(stderr, "%s: image %s does not contain a Multiboot2 header\n", argv[0], outf);
		exit(1);
	}

	struct multiboot_header_tag_address *address_tag = NULL;

	for (struct multiboot_header_tag *tag = (struct multiboot_header_tag *)(mbh + 1);
	   		tag < (struct multiboot_header_tag *)((uintptr_t)mbh + mbh->header_length) && tag->type != MULTIBOOT_HEADER_TAG_END;
			tag = (struct multiboot_header_tag *)((uintptr_t)tag + ALIGN_UP(tag->size, MULTIBOOT_TAG_ALIGN))) {
		printf("type: %x\n", tag->type);
		switch (tag->type){
			case MULTIBOOT_HEADER_TAG_END:
				break;
			case MULTIBOOT_HEADER_TAG_ADDRESS:
				address_tag = (struct multiboot_header_tag_address *)tag;
				uintptr_t mbh_offset = ((char *)mbh - (char *)image);
				if (address_tag->header_addr < mbh_offset) {
					fprintf(stderr, "%s: Multiboot header address %x too low to accommodate preceding portion of image %s\n", argv[0], address_tag->header_addr, outf);
					exit(1);
				}
				
				address_tag->load_addr = address_tag->header_addr - mbh_offset;
				address_tag->load_end_addr = address_tag->load_addr + st.st_size;
				if (verbose){
					printf("%s: header address %x, load address %x, end address %x\n", outf, address_tag->header_addr, address_tag->load_addr, address_tag->load_end_addr);
				}
				break;
		}
	}

	int ret = 0;
	if (munmap(image, MULTIBOOT_SEARCH) != 0){
		fprintf(stderr, "%s: cannot unmap image ", argv[0]);
		perror(outf);
		ret = 1;
	}
	close(f);
	exit(ret);
}
