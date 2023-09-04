/*
 * Stub loader that copies the main stage of the loader (startup1) to an
 * address range outside the XRFS image
 *
 * This makes it easy to leave out the padding for startup1's bss from a
 * compressed image without having to expand the image
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

#include <multiboot2.h>
#include <multiboot2_lib/elf.h>
#include "cpu/support.h"
#include "stage0.h"

#define ELF_HDR_FIELD(field) (pu.elf32->e_ident[EI_CLASS] == ELFCLASS64 ? pu.elf64->field : pu.elf32->field)
#define ELF_PHDR_FIELD(field) (pu.elf32->e_ident[EI_CLASS] == ELFCLASS64 ? phdr.ph64->field : phdr.ph32->field)

static void *stage0_memcpy(void *dst, const void *src, unsigned long n)
{
        int i;
        void *ret = dst;

        for(i = 0; i < n % sizeof(unsigned long); i++)
                ((unsigned char *) dst)[i] = ((unsigned char *) src)[i];

        n -= i;
        src += i;
        dst += i;

        for(i = 0; i < n / sizeof(unsigned long); i++)
                ((unsigned long *) dst)[i] = ((unsigned long *) src)[i];

        return ret;
}

void print(char *str)
{
	while (*str != '\0'){
		stage0_putchar(*str);
		str++;
	}
}

void panic(char *str)
{
	print("\r\n");
	print(str);
	print("\r\n");
	hang();
}

void stage0_main()
{
        union {
                Elf32_Ehdr *elf32; 
                Elf64_Ehdr *elf64;
        }pu;
        union {
                Elf32_Phdr *ph32;
                Elf64_Phdr *ph64;
        }phdr;

	struct multiboot_info *mbi = get_multiboot_info();
	if (!mbi){
		panic("no Multiboot2 info");
	}
	unsigned long mbi_start = (unsigned long)mbi;

	print("Loading.");

	char *exec;

	exec = (char *)(((unsigned long)(&_end) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));

	int i;
	for (i = 0; i < 10; i++){
		exec += PAGE_SIZE * i;
#if STAGE0_ELF32
		if ((BOOTABLE_ELF32((*((Elf32_Ehdr *)(exec)))))){
#elif STAGE0_ELF64
		if ((BOOTABLE_ELF64((*((Elf64_Ehdr *)(exec)))))){
#endif
			break;
		}
	}
#if STAGE0_ELF32
	if (!(BOOTABLE_ELF32((*((Elf32_Ehdr *)(exec)))))){
#elif STAGE0_ELF64
	if (!(BOOTABLE_ELF64((*((Elf64_Ehdr *)(exec)))))){
#endif
		panic("no valid startup1 ELF header found");
	}

	pu.elf32 = (Elf32_Ehdr *)exec;
	entry = ELF_HDR_FIELD(e_entry);

	int segs = 0;
	for (i = 0; i < ELF_HDR_FIELD(e_phnum); i++){
                phdr.ph32 = (Elf32_Phdr *)
                        (exec + ELF_HDR_FIELD(e_phoff)
                        + (ELF_HDR_FIELD(e_phentsize) * i));
		if (ELF_PHDR_FIELD(p_type) == PT_LOAD){
			segs++;
			break;
		}
	}
	if (segs != 1){
		panic("startup1 has invalid number of loadable segments");
	}
	unsigned long offset = ELF_PHDR_FIELD(p_offset);
	unsigned long filesiz = ELF_PHDR_FIELD(p_filesz);
	unsigned long memsiz = ELF_PHDR_FIELD(p_memsz);
	unsigned long memaddr = ELF_PHDR_FIELD(p_paddr);
	if (filesiz > memsiz){
		filesiz = memsiz;
	}
	if ((memaddr >= _img_start && memaddr <= _img_end) || (memaddr + memsiz >= _img_start && memaddr + memsiz <= _img_end)){
		panic("startup1 load address overlaps boot image");
	}

	/* currently the load address of startup1 must be below the start of the
	 * boot image */
	if (memaddr >= _img_end){
		panic("startup1 load address above boot image");
	}

	if (mbi_start < _img_start){
		stage0_memcpy((char *)_img_end, (char *)mbi_start, mbi->total_size);
		mbi_moved((unsigned long)_img_end);
	}

	char *src = (char *)(exec + offset);
	char *dest = (char *)(memaddr);
	/* this assumes that stage1 will clear its own bss, which libpayload
	 * does on x86 */
	stage0_memcpy(dest, src, filesiz);
	print(".");
	start_stage1();	
}	
