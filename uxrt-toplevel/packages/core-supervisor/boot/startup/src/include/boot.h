#ifndef __CORE_BOOT_H
#define __CORE_BOOT_H

unsigned long find_mem_region(struct multiboot_exec_params *params, unsigned long start, unsigned long end);

void loader_boot_image(struct multiboot_arch_params *arch_params, void *image, size_t len, char *const argv[], int argc);

#endif /*__CORE_BOOT_H*/
