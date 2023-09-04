#ifndef __CPU_LOAD_H
#define __CPU_LOAD_H

/* functions defined in support.c */

uint32_t *init_page_tables_32(struct multiboot_exec_params *params);

uint64_t *init_page_tables_64(struct multiboot_exec_params *params);

void *init_gdt_64(struct multiboot_exec_params *params);

void map_section_32(struct multiboot_exec_params *params, uint32_t section, uint32_t addr, size_t len, int writable);
void map_section_64(struct multiboot_exec_params *params, uint64_t section, uint64_t addr, size_t len, int page_type, int writable);

/* functions defined in asm_support.S */
void init_paging_32(char *page_dir);
void init_paging_64(char *pml4t);

void jump_to_kernel_unpaged_32(uint32_t entry_addr, void *multiboot_info);
void jump_to_kernel_paged_32(uint32_t entry_addr, void *multiboot_info);
void jump_to_kernel_64(uint64_t entry_addr, void *multiboot_info, void *gdt, uint16_t gdt_size);

#endif /*__CPU_LOAD_H*/
